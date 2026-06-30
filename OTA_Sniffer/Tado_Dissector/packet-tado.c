#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <inttypes.h>

#include "packet-tado.h"

#define PROTO_TAG_TADO "Tado"

#define FRAME_TYPE_SYNC      0x25  // Beacon/poll with target + countdown
#define FRAME_TYPE_DATA      0x69  // Unicast data (encrypted payload)
#define FRAME_TYPE_DATA_ALT  0x79  // Unicast data, variant direction/class
#define FRAME_TYPE_BROADCAST 0x49  // Coordinator broadcast at end of ffff countdown
#define FRAME_TYPE_ACK       0x42  // Acknowledgement (shares seq with the data frame)

// Fixed 4-byte network/PAN identifier present in all on-air addresses
#define TADO_NETWORK_PREFIX 0x1bc50731

dissector_handle_t tado_handle = NULL;

static int proto_tado = -1;
static module_t *tado_module;

static int hf_tado_fcfield = -1;
static int hf_tado_seqgrp = -1;
static int hf_tado_sync_const = -1;
static int hf_tado_payload = -1;
static int hf_tado_checksum = -1;
static int hf_tado_crc_status = -1;

// SYNC frame specific fields
static int hf_tado_sync_sequence = -1;
static int hf_tado_sync_target = -1;
static int hf_tado_sync_const1 = -1;
static int hf_tado_sync_countdown = -1;
static int hf_tado_sync_const2 = -1;

// Tado addressing fields. An address is <device id:3> <network const 31 07 [c5 1b 00]>,
// or the 2-byte broadcast 0xffff.
static int hf_tado_addr_src = -1;
static int hf_tado_addr_dst = -1;
static int hf_tado_src_devid = -1;
static int hf_tado_dst_devid = -1;
static int hf_tado_addr_sub = -1;   // 3rd device-id byte (per-device sub/instance)
static int hf_tado_addr_net = -1;   // network constant (31 07 [c5 1b 00])

// Additional fields for non-poll frames
static int hf_tado_resp_type = -1;
static int hf_tado_resp_seq = -1;
static int hf_tado_resp_data = -1;
static int hf_tado_resp_footer = -1;
static int hf_tado_unk_header = -1;
static int hf_tado_unk_payload = -1;

static gint ett_tado = -1;
static gint ett_tado_addr_src = -1;
static gint ett_tado_addr_dst = -1;

static const value_string frame_type_vals[] = {
    { FRAME_TYPE_SYNC,      "SYNC beacon" },
    { FRAME_TYPE_DATA,      "Data" },
    { FRAME_TYPE_DATA_ALT,  "Data (alt)" },
    { FRAME_TYPE_BROADCAST, "Broadcast" },
    { FRAME_TYPE_ACK,       "Ack" },
    { 0, NULL }
};

static const value_string resp_type_vals[] = {
    { 0xec, "Standard Response" },
    { 0xee, "Acknowledgment" },
    { 0xe8, "Extended/Config" },
    { 0, NULL }
};

// Local copy of proto_checksum_vals. The exported proto_checksum_vals symbol is
// dllimport from libwireshark and can't be used in a plugin's static hf[] array
// under MSVC (C2099). The values mirror proto_checksum_enum_e.
static const value_string tado_checksum_vals[] = {
    { PROTO_CHECKSUM_E_BAD,         "Bad" },
    { PROTO_CHECKSUM_E_GOOD,        "Good" },
    { PROTO_CHECKSUM_E_UNVERIFIED,  "Unverified" },
    { PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },
    { 0, NULL }
};

// ---------------------------------------------------------------------------
// Device name UAT
//
// Device IDs are assigned during pairing and are installation-specific.
// Users populate this table via Edit -> Preferences -> Tado -> Device Names.
// The table is stored in the active Wireshark profile directory as
// "tado_device_names" and persists across sessions.
// ---------------------------------------------------------------------------

typedef struct {
    guint   device_id;  // 16-bit device ID stored as uint for UAT hex macro
    gchar  *name;
} tado_device_name_t;

static tado_device_name_t *tado_device_names     = NULL;
static guint               num_tado_device_names = 0;
static uat_t              *tado_device_names_uat = NULL;

UAT_HEX_CB_DEF(tado_device_names, device_id, tado_device_name_t)
UAT_CSTRING_CB_DEF(tado_device_names, name, tado_device_name_t)

static void *tado_names_copy_cb(void *dest, const void *orig, size_t len _U_)
{
    tado_device_name_t       *d = (tado_device_name_t *)dest;
    const tado_device_name_t *o = (const tado_device_name_t *)orig;
    d->device_id = o->device_id;
    d->name      = g_strdup(o->name);
    return dest;
}

static void tado_names_free_cb(void *r)
{
    tado_device_name_t *rec = (tado_device_name_t *)r;
    g_free(rec->name);
}

// Returns the user-assigned name for a device ID, or NULL if not found.
static const char *tado_device_name_lookup(guint16 device_id)
{
    for (guint i = 0; i < num_tado_device_names; i++) {
        if (tado_device_names[i].device_id == device_id)
            return tado_device_names[i].name;
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Address dissection
// ---------------------------------------------------------------------------

// Parse a Tado endpoint address at offset. Three observed forms:
//   broadcast : ff ff                        (2 bytes)
//   full      : <id:3> 31 07 c5 1b 00         (8 bytes)
//   short     : <id:3> 31 07                  (5 bytes)
// The device id's first 2 bytes (big-endian) are used for name lookup; the
// 3rd byte is a per-device sub/instance value. Returns bytes consumed.
static guint dissect_tado_addr(tvbuff_t *tvb, proto_tree *tree, guint offset,
    int hf_addr, int hf_devid, gint ett_addr, const char *label)
{
    gint avail = tvb_reported_length_remaining(tvb, offset);

    if (avail >= 2 && tvb_get_ntohs(tvb, offset) == 0xffff) {
        proto_item *bc = proto_tree_add_item(tree, hf_addr, tvb, offset, 2, ENC_NA);
        proto_item_set_text(bc, "%s: Broadcast (0xffff)", label);
        return 2;
    }

    if (avail < 5)
        return 0;

    guint16 dev = tvb_get_ntohs(tvb, offset);
    guint8  sub = tvb_get_uint8(tvb, offset + 2);

    // Full form carries the extra 'c5 1b 00' after '31 07'.
    gboolean full = (avail >= 8) &&
        tvb_get_uint8(tvb, offset + 3) == 0x31 &&
        tvb_get_uint8(tvb, offset + 4) == 0x07 &&
        tvb_get_uint8(tvb, offset + 5) == 0xc5 &&
        tvb_get_uint8(tvb, offset + 6) == 0x1b;
    guint len = full ? 8 : 5;

    const char *dev_name = tado_device_name_lookup(dev);
    proto_item *addr_item = proto_tree_add_item(tree, hf_addr, tvb, offset, len, ENC_NA);
    proto_item_set_text(addr_item, "%s: %s (0x%04x) sub=0x%02x", label,
        dev_name ? dev_name : "Unknown", dev, sub);

    proto_tree *addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    proto_tree_add_uint(addr_tree, hf_devid, tvb, offset, 2, dev);
    proto_tree_add_item(addr_tree, hf_tado_addr_sub, tvb, offset + 2, 1, ENC_NA);
    proto_tree_add_item(addr_tree, hf_tado_addr_net, tvb, offset + 3, len - 3, ENC_NA);
    return len;
}

// ---------------------------------------------------------------------------
// CRC
// ---------------------------------------------------------------------------

// CRC-16/CMS: poly=0x8005, init=0xFFFF, no reflection, no final XOR.
// Computed over [PHY length byte .. last payload byte]; CRC stored big-endian.
static guint16 tado_crc16_cms(const guint8 *data, guint len, guint16 crc)
{
    for (guint i = 0; i < len; i++) {
        crc ^= (guint16)data[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (guint16)((crc << 1) ^ 0x8005)
                                 : (guint16)(crc << 1);
        }
    }
    return crc;
}

// ---------------------------------------------------------------------------
// Main dissector
// ---------------------------------------------------------------------------

static int dissect_tado(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    (void)data;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tado");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_tado, tvb, 0, -1, ENC_NA);
    proto_tree *tado_tree = proto_item_add_subtree(ti, ett_tado);

    guint offset = 0;
    guint packet_length = tvb_reported_length(tvb);

    guint8 frame_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tado_tree, hf_tado_fcfield, tvb, offset, 1, ENC_NA);
    offset += 1;

    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str(pinfo->pool, frame_type, frame_type_vals, "Unknown (0x%02x)"));

    switch (frame_type) {
    case FRAME_TYPE_SYNC: {
        proto_tree_add_item(tado_tree, hf_tado_sync_sequence, tvb, offset, 1, ENC_NA);
        offset += 1;

        // Constant marker (always 0xcdab in observed captures)
        proto_tree_add_item(tado_tree, hf_tado_sync_const, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        // Target device (2 bytes, little-endian); 0xffff = broadcast
        guint16 sync_target = tvb_get_letohs(tvb, offset);
        const char *target_name = tado_device_name_lookup(sync_target);
        proto_tree_add_uint_format(tado_tree, hf_tado_sync_target, tvb, offset, 2,
            sync_target, "Target Device: %s (0x%04x)",
            (sync_target == 0xffff) ? "Broadcast"
                                    : (target_name ? target_name : "Unknown"),
            sync_target);
        offset += 2;

        // SYNC tail: const1 (0x0e82) + poll countdown + const2 (0x3f80)
        if (packet_length - offset >= 8) {
            proto_tree_add_item(tado_tree, hf_tado_sync_const1,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tado_tree, hf_tado_sync_countdown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tado_tree, hf_tado_sync_const2,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;
    }

    case FRAME_TYPE_DATA:
    case FRAME_TYPE_DATA_ALT:
    case FRAME_TYPE_BROADCAST:
    case FRAME_TYPE_ACK: {
        // Common data-frame layout:
        //   <subtype> <seq> <SRC addr> <DST addr> <payload> + CRC
        proto_tree_add_item(tado_tree, hf_tado_resp_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        // Transaction/sequence byte; a data frame and its ack share this value.
        guint8 seq = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tado_tree, hf_tado_resp_seq, tvb, offset, 1, ENC_NA);
        offset += 1;

        offset += dissect_tado_addr(tvb, tado_tree, offset,
            hf_tado_addr_src, hf_tado_src_devid, ett_tado_addr_src, "Source");
        offset += dissect_tado_addr(tvb, tado_tree, offset,
            hf_tado_addr_dst, hf_tado_dst_devid, ett_tado_addr_dst, "Destination");

        // Payload (encrypted for data/broadcast; short structured field for acks).
        if (packet_length > offset + 2) {
            proto_tree_add_item(tado_tree, hf_tado_resp_data, tvb, offset,
                packet_length - offset - 2, ENC_NA);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, " seq=0x%02x", seq);
        break;
    }

    default:
        if (packet_length > offset + 2) {
            proto_tree_add_item(tado_tree, hf_tado_unk_payload, tvb, offset,
                packet_length - offset - 2, ENC_NA);
        }
        break;
    }

    // CRC-16/CMS validation (last 2 bytes of the frame, big-endian).
    // The CRC covers the PHY length byte + frame body. TI-RPI strips the PHY
    // length byte before this dissector runs, so reconstruct it:
    //   length = byte count excluding the 2-byte CRC = packet_length - 2.
    if (packet_length >= 3 && tvb_captured_length(tvb) >= packet_length) {
        guint   crc_offset  = packet_length - 2;
        guint8  length_byte = (guint8)crc_offset;
        guint16 computed    = tado_crc16_cms(&length_byte, 1, 0xFFFF);
        const guint8 *body  = tvb_get_ptr(tvb, 0, crc_offset);
        computed = tado_crc16_cms(body, crc_offset, computed);

        proto_tree_add_checksum(tado_tree, tvb, crc_offset,
            hf_tado_checksum, hf_tado_crc_status, NULL, pinfo,
            computed, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    }

    return tvb_captured_length(tvb);
}

// ---------------------------------------------------------------------------
// Protocol registration
// ---------------------------------------------------------------------------

void proto_register_tado(void)
{
    static hf_register_info hf[] = {
        { &hf_tado_fcfield,  { "Frame Type",       "tado.fc",       FT_UINT8,  BASE_HEX,  VALS(frame_type_vals), 0x0, "Frame control field", HFILL }},
        { &hf_tado_seqgrp,   { "Sequence Group",   "tado.seqgrp",   FT_UINT8,  BASE_HEX,  NULL, 0x0, "Sequence group number", HFILL }},
        { &hf_tado_payload,  { "Payload",           "tado.payload",  FT_BYTES,  BASE_NONE, NULL, 0x0, "Frame payload", HFILL }},
        { &hf_tado_checksum, { "Checksum",          "tado.checksum", FT_UINT16, BASE_HEX,  NULL, 0x0, "Frame checksum (CRC-16/CMS)", HFILL }},
        { &hf_tado_crc_status, { "Checksum Status", "tado.crc_status", FT_UINT8, BASE_NONE, VALS(tado_checksum_vals), 0x0, "CRC validation status", HFILL }},

        { &hf_tado_sync_sequence, { "Sync Sequence",  "tado.sync.sequence",      FT_UINT8,  BASE_HEX, NULL, 0x0, "Synchronization sequence number", HFILL }},
        { &hf_tado_sync_const,    { "SYNC Constant",  "tado.sync.const",         FT_UINT16, BASE_HEX, NULL, 0x0, "Constant marker in SYNC frames (observed 0xcdab)", HFILL }},
        { &hf_tado_sync_target,   { "Target Device",  "tado.sync.target",        FT_UINT16, BASE_HEX, NULL, 0x0, "Device the beacon is polling; 0xffff = broadcast", HFILL }},
        { &hf_tado_sync_const1,   { "SYNC Const 1",   "tado.sync.const1",        FT_UINT16, BASE_HEX, NULL, 0x0, "Constant in SYNC frames (observed 0x0e82); purpose unknown", HFILL }},
        { &hf_tado_sync_countdown,{ "Poll Countdown", "tado.sync.poll_countdown", FT_UINT16, BASE_DEC, NULL, 0x0, "Decrements to 0 at the scheduled poll; clock-derived (~12-13 units/beacon)", HFILL }},
        { &hf_tado_sync_const2,   { "SYNC Const 2",   "tado.sync.const2",        FT_UINT16, BASE_HEX, NULL, 0x0, "Constant in SYNC frames (observed 0x3f80); purpose unknown", HFILL }},

        { &hf_tado_addr_src,  { "Source",             "tado.addr.src",        FT_BYTES,  BASE_NONE, NULL, 0x0, "Source address", HFILL }},
        { &hf_tado_addr_dst,  { "Destination",        "tado.addr.dst",        FT_BYTES,  BASE_NONE, NULL, 0x0, "Destination address", HFILL }},
        { &hf_tado_src_devid, { "Source Device",      "tado.addr.src.devid",  FT_UINT16, BASE_HEX,  NULL, 0x0, "Source device ID (first 2 bytes, big-endian)", HFILL }},
        { &hf_tado_dst_devid, { "Destination Device", "tado.addr.dst.devid",  FT_UINT16, BASE_HEX,  NULL, 0x0, "Destination device ID (first 2 bytes, big-endian)", HFILL }},
        { &hf_tado_addr_sub,  { "Sub-ID",             "tado.addr.sub",        FT_UINT8,  BASE_HEX,  NULL, 0x0, "Per-device sub/instance byte (3rd ID byte)", HFILL }},
        { &hf_tado_addr_net,  { "Network ID",         "tado.addr.net",        FT_BYTES,  BASE_NONE, NULL, 0x0, "Network/PAN constant (31 07 [c5 1b 00])", HFILL }},

        { &hf_tado_resp_type,   { "Subtype",          "tado.resp_type",   FT_UINT8, BASE_HEX,  VALS(resp_type_vals), 0x0, "Frame subtype", HFILL }},
        { &hf_tado_resp_seq,    { "Transaction",      "tado.seq",         FT_UINT8, BASE_HEX,  NULL, 0x0, "Transaction ID; a data frame and its ack share this value", HFILL }},
        { &hf_tado_resp_data,   { "Payload",          "tado.resp_data",   FT_BYTES, BASE_NONE, NULL, 0x0, "Frame payload (encrypted for data/broadcast)", HFILL }},
        { &hf_tado_resp_footer, { "Response Footer",  "tado.resp_footer", FT_BYTES, BASE_NONE, NULL, 0x0, "Response footer/status", HFILL }},

        { &hf_tado_unk_header,  { "Config Header",  "tado.config.header",  FT_BYTES, BASE_NONE, NULL, 0x0, "Configuration frame header pattern", HFILL }},
        { &hf_tado_unk_payload, { "Config Payload", "tado.config.payload", FT_BYTES, BASE_NONE, NULL, 0x0, "Configuration frame encrypted payload", HFILL }},
    };

    static gint *ett[] = {
        &ett_tado,
        &ett_tado_addr_src,
        &ett_tado_addr_dst
    };

    proto_tado = proto_register_protocol(
        "Tado Smart Thermostat Protocol", "Tado", "tado");
    proto_register_field_array(proto_tado, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    // Preferences
    tado_module = prefs_register_protocol(proto_tado, NULL);

    // Device name UAT
    static uat_field_t tado_device_name_fields[] = {
        UAT_FLD_HEX(tado_device_names, device_id, "Device ID",
            "16-bit device ID in hexadecimal (e.g. 0x0f42). "
            "Found in the Source/Destination device ID fields of any data frame."),
        UAT_FLD_CSTRING(tado_device_names, name, "Name",
            "Human-readable name for this device (e.g. Internet Bridge, Hallway Valve)."),
        UAT_END_FIELDS
    };

    tado_device_names_uat = uat_new("Tado Device Names",
        sizeof(tado_device_name_t),
        "tado_device_names",    // filename in Wireshark profile directory
        TRUE,                   // from_profile
        &tado_device_names,     // data_ptr
        &num_tado_device_names, // numitems_ptr
        UAT_AFFECTS_DISSECTION,
        NULL,                   // help
        tado_names_copy_cb,
        NULL,                   // update_cb
        tado_names_free_cb,
        NULL,                   // post_update_cb
        NULL,                   // reset_cb
        tado_device_name_fields);

    prefs_register_uat_preference(tado_module,
        "device_names",
        "Device Names",
        "A table mapping Tado device IDs to user-assigned names. "
        "IDs are installation-specific and can be read from any data frame capture.",
        tado_device_names_uat);
}

void proto_reg_handoff_tado(void)
{
    if (!tado_handle) {
        tado_handle = create_dissector_handle(dissect_tado, proto_tado);
    }
}
