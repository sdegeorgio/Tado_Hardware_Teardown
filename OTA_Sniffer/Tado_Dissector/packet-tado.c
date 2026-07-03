#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <inttypes.h>

#include "packet-tado.h"

#define PROTO_TAG_TADO "Tado"

// The Tado 868 MHz link is an IEEE 802.15.4e (LE CSL) MAC (identified from bridge
// firmware; see Bridge_Firmware_Analysis.md and Tado_Protocol.md §3.4). The two leading
// bytes are the standard 802.15.4-2015 Frame Control Field, so we decode them as such
// rather than as an opaque Tado type/subtype.

// 802.15.4 frame types (FCF bits 0-2)
#define IEEE802154_FTYPE_BEACON       0
#define IEEE802154_FTYPE_DATA         1
#define IEEE802154_FTYPE_ACK          2
#define IEEE802154_FTYPE_MACCMD       3
#define IEEE802154_FTYPE_MULTIPURPOSE 5   // CSL wake-up beacon (Tado "SYNC")

// 802.15.4 addressing modes (FCF bits 10-11 dest, 14-15 src)
#define IEEE802154_ADDR_NONE  0
#define IEEE802154_ADDR_SHORT 2
#define IEEE802154_ADDR_EXT   3

// Fixed 4-byte network/PAN identifier present in all on-air addresses
#define TADO_NETWORK_PREFIX 0x1bc50731

dissector_handle_t tado_handle = NULL;

// Handle for Wireshark's built-in 6LoWPAN dissector. The decrypted MAC payload of
// data/broadcast frames is a 6LoWPAN packet (IPHC -> IPv6 -> UDP -> CoAP); once the
// payload is available in the clear it is handed off here. See Bridge_Firmware_Analysis.md.
static dissector_handle_t sixlowpan_handle = NULL;

// Preference: set when the capture's data-frame payloads are already decrypted 6LoWPAN
// (e.g. externally decrypted with a recovered key). Default off, because on-air payloads
// are AES-CTR ciphertext and would only produce malformed 6LoWPAN.
static bool tado_payload_is_6lowpan = false;

static int proto_tado = -1;
static module_t *tado_module;

// Frame Control Field (general frame, 2 octets, little-endian)
static int hf_tado_fcf          = -1;
static int hf_tado_fcf_type     = -1;
static int hf_tado_fcf_security = -1;
static int hf_tado_fcf_pending  = -1;
static int hf_tado_fcf_ackreq   = -1;
static int hf_tado_fcf_pancomp  = -1;
static int hf_tado_fcf_seqsup   = -1;
static int hf_tado_fcf_ie       = -1;
static int hf_tado_fcf_dstmode  = -1;
static int hf_tado_fcf_version  = -1;
static int hf_tado_fcf_srcmode  = -1;

// Multipurpose Frame Control (SYNC beacon, 1 octet)
static int hf_tado_mpfc         = -1;
static int hf_tado_mpfc_type    = -1;
static int hf_tado_mpfc_longfc  = -1;
static int hf_tado_mpfc_dstmode = -1;
static int hf_tado_mpfc_srcmode = -1;

static int hf_tado_seq       = -1;
static int hf_tado_checksum  = -1;
static int hf_tado_crc_status = -1;

// SYNC / Multipurpose beacon body (CSL wake-up; exact IE mapping still open)
static int hf_tado_sync_sequence = -1;
static int hf_tado_sync_const    = -1;
static int hf_tado_sync_target   = -1;
static int hf_tado_sync_const1   = -1;
static int hf_tado_sync_countdown = -1;
static int hf_tado_sync_const2   = -1;

// Tado addressing fields. An address is <device id:3> <network const 31 07 [c5 1b 00]>,
// or the 2-byte broadcast 0xffff. Frame order is Destination then Source (802.15.4).
static int hf_tado_addr_src  = -1;
static int hf_tado_addr_dst  = -1;
static int hf_tado_src_devid = -1;
static int hf_tado_dst_devid = -1;
static int hf_tado_addr_sub  = -1;   // 3rd device-id byte (per-device sub/instance)
static int hf_tado_addr_net  = -1;   // network constant (31 07 [c5 1b 00])

// Auxiliary Security Header (802.15.4). Explicit on broadcast frames only.
static int hf_tado_sec_ctrl   = -1;
static int hf_tado_sec_level  = -1;
static int hf_tado_sec_keyid  = -1;
static int hf_tado_sec_fcsup  = -1;
static int hf_tado_sec_asn    = -1;
static int hf_tado_frame_counter = -1;

static int hf_tado_enc_payload = -1;   // encrypted payload (6LoWPAN when decrypted)
static int hf_tado_ack_payload = -1;   // enhanced-ack MAC payload (cleartext)

static gint ett_tado = -1;
static gint ett_tado_fcf = -1;
static gint ett_tado_sec = -1;
static gint ett_tado_addr_src = -1;
static gint ett_tado_addr_dst = -1;

static const value_string ieee802154_ftype_vals[] = {
    { IEEE802154_FTYPE_BEACON,       "Beacon" },
    { IEEE802154_FTYPE_DATA,         "Data" },
    { IEEE802154_FTYPE_ACK,          "Acknowledgment" },
    { IEEE802154_FTYPE_MACCMD,       "MAC Command" },
    { 4,                             "Reserved" },
    { IEEE802154_FTYPE_MULTIPURPOSE, "Multipurpose" },
    { 6,                             "Fragment / Frak" },
    { 7,                             "Extended" },
    { 0, NULL }
};

static const value_string ieee802154_addrmode_vals[] = {
    { 0, "Not present" },
    { 1, "Reserved" },
    { 2, "Short (16-bit)" },
    { 3, "Extended (64-bit)" },
    { 0, NULL }
};

static const value_string ieee802154_version_vals[] = {
    { 0, "IEEE 802.15.4-2003" },
    { 1, "IEEE 802.15.4-2006" },
    { 2, "IEEE 802.15.4-2015 (802.15.4e)" },
    { 3, "Reserved" },
    { 0, NULL }
};

// 802.15.4 security level (SC bits 0-2). Observed on air: 4 = ENC (encryption, no MIC).
static const value_string ieee802154_seclevel_vals[] = {
    { 0, "None" },
    { 1, "MIC-32" },
    { 2, "MIC-64" },
    { 3, "MIC-128" },
    { 4, "ENC (encryption, no MIC)" },
    { 5, "ENC-MIC-32" },
    { 6, "ENC-MIC-64" },
    { 7, "ENC-MIC-128" },
    { 0, NULL }
};

static const value_string ieee802154_keyid_vals[] = {
    { 0, "Implicit" },
    { 1, "1-octet key index" },
    { 2, "4-octet key source + index" },
    { 3, "8-octet key source + index" },
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
//   full      : <id:3> 31 07 c5 1b 00         (8 bytes, ext-64)
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

// CRC-16/CMS: poly=0x8005, init=0xFFFF, no reflection, no final XOR. This replaces the
// standard 802.15.4 FCS. Computed over [PHY length byte .. last payload byte]; stored BE.
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
// Frame handlers
// ---------------------------------------------------------------------------

// Multipurpose frame (Tado "SYNC" / CSL wake-up beacon). 1-octet MP Frame Control.
static void dissect_tado_multipurpose(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tado_tree, guint packet_length)
{
    guint offset = 0;

    proto_item *mp_item = proto_tree_add_item(tado_tree, hf_tado_mpfc, tvb, 0, 1, ENC_NA);
    proto_tree *mp_tree = proto_item_add_subtree(mp_item, ett_tado_fcf);
    proto_tree_add_item(mp_tree, hf_tado_mpfc_type,    tvb, 0, 1, ENC_NA);
    proto_tree_add_item(mp_tree, hf_tado_mpfc_longfc,  tvb, 0, 1, ENC_NA);
    proto_tree_add_item(mp_tree, hf_tado_mpfc_dstmode, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(mp_tree, hf_tado_mpfc_srcmode, tvb, 0, 1, ENC_NA);
    offset += 1;

    col_set_str(pinfo->cinfo, COL_INFO, "SYNC beacon (Multipurpose)");

    // CSL beacon body. Field boundaries are empirically stable; full CSL IE decoding
    // is still open (see Tado_Protocol.md §3.1/§3.4).
    proto_tree_add_item(tado_tree, hf_tado_sync_sequence, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tado_tree, hf_tado_sync_const, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    guint16 sync_target = tvb_get_letohs(tvb, offset);
    const char *target_name = tado_device_name_lookup(sync_target);
    proto_tree_add_uint_format(tado_tree, hf_tado_sync_target, tvb, offset, 2,
        sync_target, "Target Device: %s (0x%04x)",
        (sync_target == 0xffff) ? "Broadcast" : (target_name ? target_name : "Unknown"),
        sync_target);
    col_append_fstr(pinfo->cinfo, COL_INFO, " -> 0x%04x", sync_target);
    offset += 2;

    if (packet_length - offset >= 8) {
        proto_tree_add_item(tado_tree, hf_tado_sync_const1,    tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tado_tree, hf_tado_sync_countdown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tado_tree, hf_tado_sync_const2,    tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }
}

// General 802.15.4-2015 frame: Data / Enhanced Ack.
static void dissect_tado_general(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tado_tree, proto_tree *tree, guint packet_length, guint16 fcf)
{
    guint offset = 0;
    guint8   ftype   = fcf & 0x0007;
    gboolean secure  = (fcf >> 3) & 1;
    gboolean seqsup  = (fcf >> 8) & 1;

    proto_item *fcf_item = proto_tree_add_item(tado_tree, hf_tado_fcf, tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree *fcf_tree = proto_item_add_subtree(fcf_item, ett_tado_fcf);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_type,     tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_security, tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_pending,  tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_ackreq,   tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_pancomp,  tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_seqsup,   tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_ie,       tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_dstmode,  tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_version,  tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fcf_tree, hf_tado_fcf_srcmode,  tvb, 0, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str(pinfo->pool, ftype, ieee802154_ftype_vals, "Type %u"));

    guint8 seq = 0;
    if (!seqsup) {
        seq = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tado_tree, hf_tado_seq, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    // Addressing: Destination first, then Source (IEEE 802.15.4 order).
    guint dstlen = dissect_tado_addr(tvb, tado_tree, offset,
        hf_tado_addr_dst, hf_tado_dst_devid, ett_tado_addr_dst, "Destination");
    offset += dstlen;
    offset += dissect_tado_addr(tvb, tado_tree, offset,
        hf_tado_addr_src, hf_tado_src_devid, ett_tado_addr_src, "Source");

    // Auxiliary Security Header. Present explicitly on broadcast frames only (dest = ffff);
    // unicast frames carry implicit CSL security parameters, so the ciphertext begins
    // immediately after the source address. See Tado_Protocol.md §3.4 / §5.
    if (secure && dstlen == 2 && packet_length > offset + 2) {
        guint8 sc = tvb_get_uint8(tvb, offset);
        proto_item *sec_item = proto_tree_add_item(tado_tree, hf_tado_sec_ctrl, tvb, offset, 1, ENC_NA);
        proto_tree *sec_tree = proto_item_add_subtree(sec_item, ett_tado_sec);
        proto_tree_add_item(sec_tree, hf_tado_sec_level, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sec_tree, hf_tado_sec_keyid, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sec_tree, hf_tado_sec_fcsup, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sec_tree, hf_tado_sec_asn,   tvb, offset, 1, ENC_NA);
        offset += 1;
        // Tado uses a 2-byte (not the standard 4-byte) frame counter: SC(1) + FC(2), then
        // ciphertext. Verified: the 16-bit LE counter is strictly monotonic per session;
        // a 4-byte read is not (bytes 3-4 are ciphertext).
        if (!((sc >> 5) & 1) && packet_length > offset + 2 + 2) {  // frame counter not suppressed
            proto_tree_add_item(tado_tree, hf_tado_frame_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
    }

    // Payload
    if (packet_length > offset + 2) {
        guint payload_len = packet_length - offset - 2;
        if (ftype == IEEE802154_FTYPE_ACK) {
            // Enhanced Ack: short cleartext MAC payload, not 6LoWPAN.
            proto_tree_add_item(tado_tree, hf_tado_ack_payload, tvb, offset, payload_len, ENC_NA);
        } else {
            proto_tree_add_item(tado_tree, hf_tado_enc_payload, tvb, offset, payload_len, ENC_NA);
            if (tado_payload_is_6lowpan && sixlowpan_handle) {
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, payload_len);
                call_dissector(sixlowpan_handle, next_tvb, pinfo, tree);
            }
        }
    }

    if (!seqsup)
        col_append_fstr(pinfo->cinfo, COL_INFO, " seq=0x%02x", seq);
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

    guint  packet_length = tvb_reported_length(tvb);
    guint8 first = tvb_get_uint8(tvb, 0);
    guint8 ftype = first & 0x07;

    if (ftype == IEEE802154_FTYPE_MULTIPURPOSE) {
        dissect_tado_multipurpose(tvb, pinfo, tado_tree, packet_length);
    } else {
        guint16 fcf = tvb_get_letohs(tvb, 0);
        dissect_tado_general(tvb, pinfo, tado_tree, tree, packet_length, fcf);
    }

    // CRC-16/CMS validation (last 2 bytes of the frame, big-endian). Covers the PHY
    // length byte + frame body. TI-RPI strips the PHY length byte before this dissector
    // runs, so reconstruct it: length = byte count excluding the 2-byte CRC.
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
        // General Frame Control Field (802.15.4-2015)
        { &hf_tado_fcf,          { "Frame Control Field", "tado.fcf",          FT_UINT16,  BASE_HEX,  NULL, 0x0, "IEEE 802.15.4 FCF", HFILL }},
        { &hf_tado_fcf_type,     { "Frame Type",          "tado.fcf.type",     FT_UINT16,  BASE_DEC,  VALS(ieee802154_ftype_vals),   0x0007, NULL, HFILL }},
        { &hf_tado_fcf_security, { "Security Enabled",    "tado.fcf.security", FT_BOOLEAN, 16,        NULL, 0x0008, NULL, HFILL }},
        { &hf_tado_fcf_pending,  { "Frame Pending",       "tado.fcf.pending",  FT_BOOLEAN, 16,        NULL, 0x0010, NULL, HFILL }},
        { &hf_tado_fcf_ackreq,   { "Ack Request",         "tado.fcf.ack_req",  FT_BOOLEAN, 16,        NULL, 0x0020, NULL, HFILL }},
        { &hf_tado_fcf_pancomp,  { "PAN ID Compression",  "tado.fcf.pan_comp", FT_BOOLEAN, 16,        NULL, 0x0040, NULL, HFILL }},
        { &hf_tado_fcf_seqsup,   { "Seq Num Suppression", "tado.fcf.seq_sup",  FT_BOOLEAN, 16,        NULL, 0x0100, NULL, HFILL }},
        { &hf_tado_fcf_ie,       { "IE Present",          "tado.fcf.ie",       FT_BOOLEAN, 16,        NULL, 0x0200, NULL, HFILL }},
        { &hf_tado_fcf_dstmode,  { "Dest Addressing Mode","tado.fcf.dst_mode", FT_UINT16,  BASE_DEC,  VALS(ieee802154_addrmode_vals),0x0C00, NULL, HFILL }},
        { &hf_tado_fcf_version,  { "Frame Version",       "tado.fcf.version",  FT_UINT16,  BASE_DEC,  VALS(ieee802154_version_vals), 0x3000, NULL, HFILL }},
        { &hf_tado_fcf_srcmode,  { "Src Addressing Mode", "tado.fcf.src_mode", FT_UINT16,  BASE_DEC,  VALS(ieee802154_addrmode_vals),0xC000, NULL, HFILL }},

        // Multipurpose Frame Control (SYNC beacon)
        { &hf_tado_mpfc,         { "MP Frame Control",    "tado.mpfc",         FT_UINT8,   BASE_HEX,  NULL, 0x0, "Multipurpose frame control (802.15.4e)", HFILL }},
        { &hf_tado_mpfc_type,    { "Frame Type",          "tado.mpfc.type",    FT_UINT8,   BASE_DEC,  VALS(ieee802154_ftype_vals),   0x07, NULL, HFILL }},
        { &hf_tado_mpfc_longfc,  { "Long Frame Control",  "tado.mpfc.long_fc", FT_BOOLEAN, 8,         NULL, 0x08, NULL, HFILL }},
        { &hf_tado_mpfc_dstmode, { "Dest Addressing Mode","tado.mpfc.dst_mode",FT_UINT8,   BASE_DEC,  VALS(ieee802154_addrmode_vals),0x30, NULL, HFILL }},
        { &hf_tado_mpfc_srcmode, { "Src Addressing Mode", "tado.mpfc.src_mode",FT_UINT8,   BASE_DEC,  VALS(ieee802154_addrmode_vals),0xC0, NULL, HFILL }},

        { &hf_tado_seq,          { "Sequence Number",     "tado.seq",          FT_UINT8,   BASE_HEX,  NULL, 0x0, "Transaction ID; a data frame and its ack share this value", HFILL }},
        { &hf_tado_checksum,     { "Checksum",            "tado.checksum",     FT_UINT16,  BASE_HEX,  NULL, 0x0, "Frame checksum (CRC-16/CMS, replaces the 802.15.4 FCS)", HFILL }},
        { &hf_tado_crc_status,   { "Checksum Status",     "tado.crc_status",   FT_UINT8,   BASE_NONE, VALS(tado_checksum_vals), 0x0, NULL, HFILL }},

        { &hf_tado_sync_sequence,{ "Sync Sequence",       "tado.sync.sequence",      FT_UINT8,  BASE_HEX, NULL, 0x0, "Constant within a polling session; changes between sessions", HFILL }},
        { &hf_tado_sync_const,   { "SYNC Constant",       "tado.sync.const",         FT_UINT16, BASE_HEX, NULL, 0x0, "Constant in SYNC frames (observed 0xcdab); CSL/MP addressing field", HFILL }},
        { &hf_tado_sync_target,  { "Target Device",       "tado.sync.target",        FT_UINT16, BASE_HEX, NULL, 0x0, "Device the beacon is polling; 0xffff = broadcast", HFILL }},
        { &hf_tado_sync_const1,  { "SYNC Const 1",        "tado.sync.const1",        FT_UINT16, BASE_HEX, NULL, 0x0, "Constant in SYNC frames (observed 0x0e82)", HFILL }},
        { &hf_tado_sync_countdown,{ "Poll Countdown",     "tado.sync.poll_countdown",FT_UINT16, BASE_DEC, NULL, 0x0, "CSL rendezvous time; decrements to 0 at the scheduled poll", HFILL }},
        { &hf_tado_sync_const2,  { "SYNC Const 2",        "tado.sync.const2",        FT_UINT16, BASE_HEX, NULL, 0x0, "Constant in SYNC frames (observed 0x3f80)", HFILL }},

        { &hf_tado_addr_src,  { "Source",             "tado.addr.src",        FT_BYTES,  BASE_NONE, NULL, 0x0, "Source address", HFILL }},
        { &hf_tado_addr_dst,  { "Destination",        "tado.addr.dst",        FT_BYTES,  BASE_NONE, NULL, 0x0, "Destination address", HFILL }},
        { &hf_tado_src_devid, { "Source Device",      "tado.addr.src.devid",  FT_UINT16, BASE_HEX,  NULL, 0x0, "Source device ID (first 2 bytes, big-endian)", HFILL }},
        { &hf_tado_dst_devid, { "Destination Device", "tado.addr.dst.devid",  FT_UINT16, BASE_HEX,  NULL, 0x0, "Destination device ID (first 2 bytes, big-endian)", HFILL }},
        { &hf_tado_addr_sub,  { "Sub-ID",             "tado.addr.sub",        FT_UINT8,  BASE_HEX,  NULL, 0x0, "Per-device sub/instance byte (3rd ID byte)", HFILL }},
        { &hf_tado_addr_net,  { "Network ID",         "tado.addr.net",        FT_BYTES,  BASE_NONE, NULL, 0x0, "Network/PAN constant (31 07 [c5 1b 00])", HFILL }},

        { &hf_tado_sec_ctrl,  { "Security Control",   "tado.sec.ctrl",        FT_UINT8,  BASE_HEX,  NULL, 0x0, "802.15.4 Auxiliary Security Header, Security Control field", HFILL }},
        { &hf_tado_sec_level, { "Security Level",     "tado.sec.level",       FT_UINT8,  BASE_DEC,  VALS(ieee802154_seclevel_vals), 0x07, NULL, HFILL }},
        { &hf_tado_sec_keyid, { "Key Identifier Mode","tado.sec.key_id_mode", FT_UINT8,  BASE_DEC,  VALS(ieee802154_keyid_vals),    0x18, NULL, HFILL }},
        { &hf_tado_sec_fcsup, { "Frame Counter Suppression", "tado.sec.fc_sup", FT_BOOLEAN, 8,      NULL, 0x20, NULL, HFILL }},
        { &hf_tado_sec_asn,   { "ASN in Nonce",       "tado.sec.asn",         FT_BOOLEAN, 8,         NULL, 0x40, NULL, HFILL }},
        { &hf_tado_frame_counter, { "Frame Counter",  "tado.sec.frame_counter", FT_UINT16, BASE_DEC, NULL, 0x0, "Frame counter (2-byte LE; Tado uses a short counter, not the 802.15.4 4-byte). Feeds the AES-CTR nonce", HFILL }},

        { &hf_tado_enc_payload, { "Encrypted Payload", "tado.enc_payload", FT_BYTES, BASE_NONE, NULL, 0x0, "AES-encrypted 6LoWPAN payload (IPv6/UDP/CoAP when decrypted)", HFILL }},
        { &hf_tado_ack_payload, { "Ack Payload",       "tado.ack_payload", FT_BYTES, BASE_NONE, NULL, 0x0, "Enhanced-ack MAC payload (cleartext)", HFILL }},
    };

    static gint *ett[] = {
        &ett_tado,
        &ett_tado_fcf,
        &ett_tado_sec,
        &ett_tado_addr_src,
        &ett_tado_addr_dst
    };

    proto_tado = proto_register_protocol(
        "Tado Smart Heating Protocol", "Tado", "tado");
    proto_register_field_array(proto_tado, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    // Preferences
    tado_module = prefs_register_protocol(proto_tado, NULL);

    prefs_register_bool_preference(tado_module,
        "payload_is_6lowpan",
        "Data-frame payload is decrypted 6LoWPAN",
        "Hand the data/broadcast frame payload to the 6LoWPAN dissector "
        "(IPv6/UDP/CoAP). Enable only for captures whose AES payloads have "
        "already been decrypted; on-air payloads are ciphertext.",
        &tado_payload_is_6lowpan);

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
    // Built-in 6LoWPAN dissector for decrypted data-frame payloads.
    sixlowpan_handle = find_dissector("6lowpan");
}
