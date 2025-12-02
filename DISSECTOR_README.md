# Tado Wireshark Dissector

This directory contains a Wireshark dissector for the Tado RF protocol.

## Current Status

✅ **Completed:**
- Dissector skeleton with known protocol parameters
- RSSI and LQI/CRC decoding (from CC110L status bytes)
- Sync word detection (0xD391)
- Basic packet structure parsing

⚠️ **In Progress:**
- Payload structure analysis (requires actual packet captures)
- Message type identification
- Device addressing scheme
- Command/response parsing

## Protocol Information (from Hardware Analysis)

### RF Parameters
- **Frequency:** 868.323726 MHz (Channel 26)
- **Modulation:** GFSK (Gaussian Frequency Shift Keying)
- **Data Rate:** 49,987.79 bps (~50 kbps)
- **Deviation:** 25.39 kHz
- **Sync Word:** 0xD391
- **CRC:** Enabled

### Packet Structure (Preliminary)
```
+----------+----------+--------+---------+------+-----+
| Preamble | Sync     | Length | Payload | RSSI | LQI |
| 4 bytes  | 2 bytes  | 1 byte | N bytes | 1 B  | 1 B |
+----------+----------+--------+---------+------+-----+
```

- **Preamble:** 4 bytes (0xAA or 0x55 pattern for clock recovery)
- **Sync Word:** 0xD3 0x91 (30/32 bits required for detection)
- **Length:** Variable packet length (0-255 bytes)
- **Payload:** 16 bytes typical (from wiki analysis)
- **RSSI:** Received Signal Strength Indicator (signed byte, formula: (value/2) - 74 dBm)
- **LQI:** Link Quality Indicator (7 bits) + CRC OK flag (1 bit, MSB)

### Payload Structure (TO BE DETERMINED)

The exact payload structure needs to be determined from actual packet captures. Likely contains:
- Device address/ID
- Message type (command, response, status, etc.)
- Sequence number
- Data payload
- CRC-16

## Installation

### 1. Install Wireshark

If not already installed:
```bash
sudo apt-get install wireshark  # Debian/Ubuntu
```

### 2. Install the Dissector

Copy the dissector to your Wireshark plugins directory:

```bash
# Find your plugins directory
wireshark -v | grep "Personal Lua Plugins"

# Copy the dissector
mkdir -p ~/.local/lib/wireshark/plugins
cp tado_dissector.lua ~/.local/lib/wireshark/plugins/
```

### 3. Verify Installation

Launch Wireshark and check that the dissector loaded:
- Go to **Help → About Wireshark → Plugins**
- Look for `tado_dissector.lua` in the list
- Check the Wireshark console for "Tado RF Protocol dissector loaded" message

## Usage

### Method 1: Decode As (Recommended for Testing)

1. Open a packet capture file containing Tado RF data
2. Select a packet
3. Go to **Analyze → Decode As...**
4. Click **+** to add a new entry
5. Set "Current" to **Tado RF Protocol**
6. Click **OK**

### Method 2: Direct Capture from TI Packet Sniffer

When using TI Packet Sniffer (as mentioned in your wiki):

1. Configure TI Packet Sniffer to output to Wireshark
2. Set the RF parameters to match Tado settings:
   - Frequency: 868.323726 MHz
   - Data rate: 50000 bps
   - Deviation: 25.39 kHz
   - Sync word: 0xD391
3. Start capture
4. Packets should be automatically decoded with this dissector

## Next Steps

To complete the dissector, we need to:

### 1. Export SPI Data from Saleae

From Saleae Logic 2:
1. Open `Logic Captures/CC110L SPI at power on with security.sal`
2. Right-click on the **SPI CC110L** analyzer
3. Select **Export to text/csv file**
4. Save as `spi_capture.csv`

This will allow us to:
- Extract actual TX/RX packet data from the FIFO operations
- Identify packet patterns
- Determine payload structure

### 2. Capture OTA (Over-The-Air) Packets

Using TI Packet Sniffer 2 (recommended in your wiki):
1. Configure with the RF parameters above
2. Capture packets during normal Tado operation:
   - Device pairing
   - Temperature updates
   - Command/control messages
   - Status broadcasts
3. Save captures in pcap format

### 3. Analyze Packet Patterns

With captured data, analyze:
- Message types and their opcodes
- Device addressing scheme
- Sequence numbering
- Command/response pairs
- Encryption (if any)

## CC110L SPI Commands to Look For

When analyzing SPI captures, look for these key operations:

### TX FIFO Write (Transmit Packet)
- **Command:** 0x3F (burst write to TX FIFO)
- **Format:** `0x3F [length] [data bytes...]`
- This contains the actual packet being transmitted

### RX FIFO Read (Receive Packet)
- **Command:** 0xBF (burst read from RX FIFO)
- **Format:** `0xBF [read length bytes]`
- This contains received packet data

### Status Bytes
After each FIFO operation, CC110L returns status bytes containing RSSI and LQI

## Parsing Tools

Use the provided Python scripts:

```bash
# Once you export CSV from Saleae:
python3 parse_spi_csv.py spi_capture.csv

# This will extract:
# - TX packets (from FIFO writes)
# - RX packets (from FIFO reads)
# - Packet statistics
```

## References

- [Your Tado Wiki](https://github.com/sdegeorgio/Tado_Hardware_Teardown/wiki)
- [CC110L Datasheet](https://www.ti.com/product/CC110L)
- [Wireshark Lua Dissectors](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)

## Contributing

Once we have packet captures, please share:
1. Example packet hex dumps
2. Context (what operation triggered the packet)
3. Any observed patterns

This will help refine the dissector and complete the protocol analysis.
