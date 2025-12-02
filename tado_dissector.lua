-- Tado RF Protocol Dissector for Wireshark
-- Based on reverse engineering of the Tado smart heating system
-- Protocol: GFSK modulation at 868.323726 MHz, 50 kbps
-- Sync word: 0xD391

-- Declare the protocol
local tado_proto = Proto("tado", "Tado RF Protocol")

-- Define protocol fields
local fields = tado_proto.fields

-- Packet structure fields
fields.preamble = ProtoField.bytes("tado.preamble", "Preamble", base.SPACE)
fields.sync_word = ProtoField.uint16("tado.sync_word", "Sync Word", base.HEX)
fields.payload_length = ProtoField.uint8("tado.payload_length", "Payload Length", base.DEC)
fields.payload = ProtoField.bytes("tado.payload", "Payload", base.SPACE)
fields.rssi = ProtoField.int8("tado.rssi", "RSSI", base.DEC)
fields.lqi = ProtoField.uint8("tado.lqi", "LQI/CRC", base.HEX)

-- Payload subfields (to be determined from captures)
fields.device_addr = ProtoField.bytes("tado.device_addr", "Device Address", base.SPACE)
fields.msg_type = ProtoField.uint8("tado.msg_type", "Message Type", base.HEX)
fields.sequence = ProtoField.uint8("tado.sequence", "Sequence Number", base.DEC)
fields.data = ProtoField.bytes("tado.data", "Data", base.SPACE)
fields.crc = ProtoField.uint16("tado.crc", "CRC", base.HEX)

-- Dissector function
function tado_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    -- Set protocol name in packet list
    pinfo.cols.protocol = tado_proto.name

    -- Create protocol tree
    local subtree = tree:add(tado_proto, buffer(), "Tado RF Protocol Data")

    local offset = 0

    -- Preamble (4 bytes) - typically 0xAA or 0x55 pattern
    if length >= 4 then
        subtree:add(fields.preamble, buffer(offset, 4))
        offset = offset + 4
    end

    -- Sync Word (2 bytes) - 0xD391
    if length >= offset + 2 then
        local sync = buffer(offset, 2):uint()
        subtree:add(fields.sync_word, buffer(offset, 2))
        if sync ~= 0xD391 then
            subtree:add_expert_info(PI_CHECKSUM, PI_WARN, "Unexpected sync word")
        end
        offset = offset + 2
    end

    -- Variable length packet format
    -- First byte after sync is typically the length
    if length >= offset + 1 then
        local payload_len = buffer(offset, 1):uint()
        subtree:add(fields.payload_length, buffer(offset, 1))
        offset = offset + 1

        -- Payload data
        if length >= offset + payload_len then
            local payload_tree = subtree:add(fields.payload, buffer(offset, payload_len))

            -- Parse payload subfields (structure to be determined)
            -- This is a placeholder structure - update based on actual captures
            local payload_offset = offset

            -- Possible payload structure (to be confirmed):
            -- - Device address (variable length, typically 4-8 bytes)
            -- - Message type (1 byte)
            -- - Sequence number (1 byte)
            -- - Data (variable length)
            -- - CRC (2 bytes)

            -- Example parsing (adjust based on actual data):
            if payload_len >= 4 then
                payload_tree:add(fields.device_addr, buffer(payload_offset, 4))
                payload_offset = payload_offset + 4
            end

            if payload_len >= 5 then
                payload_tree:add(fields.msg_type, buffer(payload_offset, 1))
                payload_offset = payload_offset + 1
            end

            if payload_len >= 6 then
                payload_tree:add(fields.sequence, buffer(payload_offset, 1))
                payload_offset = payload_offset + 1
            end

            -- Remaining payload data
            local remaining = payload_len - (payload_offset - offset)
            if remaining > 2 then
                payload_tree:add(fields.data, buffer(payload_offset, remaining - 2))
                payload_offset = payload_offset + (remaining - 2)

                -- CRC (last 2 bytes of payload)
                payload_tree:add(fields.crc, buffer(payload_offset, 2))
            end

            offset = offset + payload_len
        end
    end

    -- Status bytes (2 bytes) - RSSI and LQI/CRC from CC110L
    if length >= offset + 2 then
        -- RSSI value (signed byte)
        local rssi_raw = buffer(offset, 1):int()
        local rssi_dbm = (rssi_raw / 2) - 74  -- CC110L RSSI calculation
        local rssi_item = subtree:add(fields.rssi, buffer(offset, 1))
        rssi_item:append_text(string.format(" (%d dBm)", rssi_dbm))
        offset = offset + 1

        -- LQI and CRC OK status
        local lqi = buffer(offset, 1):uint()
        local crc_ok = bit.band(lqi, 0x80) ~= 0
        local lqi_value = bit.band(lqi, 0x7F)
        local lqi_item = subtree:add(fields.lqi, buffer(offset, 1))
        lqi_item:append_text(string.format(" (LQI: %d, CRC: %s)", lqi_value, crc_ok and "OK" or "FAIL"))

        if not crc_ok then
            subtree:add_expert_info(PI_CHECKSUM, PI_ERROR, "CRC check failed")
        end
    end

    -- Update info column with summary
    pinfo.cols.info = "Tado RF Packet"
end

-- Register the dissector
-- This dissector can be called from:
-- 1. A custom DLT (Data Link Type) if capturing directly from RF
-- 2. As a subdissector from another protocol (e.g., if encapsulated)
-- 3. Via "Decode As" menu in Wireshark

-- For now, register on a custom DLT or user table
-- Users can assign it via: Analyze -> Decode As -> Select protocol
local wtap_encap_table = DissectorTable.get("wtap_encap")
local user_encap_table = DissectorTable.get("user_encap")

-- Register for USER DLT 147-162 (can be changed as needed)
if user_encap_table then
    user_encap_table:add(wtap.USER0, tado_proto)
end

-- Also create a custom dissector table for Tado
DissectorTable.new("tado.msgtype", "Tado Message Type", ftypes.UINT8, base.HEX)

print("Tado RF Protocol dissector loaded")
print("To use:")
print("  1. Capture RF packets using TI Packet Sniffer or similar")
print("  2. In Wireshark: Analyze -> Decode As -> select 'Tado RF Protocol'")
print("  3. Or save captures with DLT_USER0 encapsulation")
