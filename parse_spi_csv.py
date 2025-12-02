#!/usr/bin/env python3
"""
Parse Saleae SPI CSV export to extract Tado RF packets

Usage:
    python3 parse_spi_csv.py spi_capture.csv

This script looks for:
- TX FIFO writes (0x3F) - packets being transmitted
- RX FIFO reads (0xBF) - packets being received
- Register configurations
"""

import csv
import sys
from typing import List, Tuple
from dataclasses import dataclass


@dataclass
class SPITransaction:
    """Represents a single SPI transaction"""
    time: float
    mosi: int
    miso: int


@dataclass
class Packet:
    """Represents a Tado RF packet"""
    time: float
    direction: str  # 'TX' or 'RX'
    data: bytes
    rssi: int = None
    lqi: int = None


# CC110L Register names for reference
CC110L_REGISTERS = {
    0x00: "IOCFG2", 0x01: "IOCFG1", 0x02: "IOCFG0",
    0x03: "FIFOTHR", 0x04: "SYNC1", 0x05: "SYNC0",
    0x06: "PKTLEN", 0x07: "PKTCTRL1", 0x08: "PKTCTRL0",
    0x09: "ADDR", 0x0A: "CHANNR", 0x0B: "FSCTRL1",
    0x0C: "FSCTRL0", 0x0D: "FREQ2", 0x0E: "FREQ1", 0x0F: "FREQ0",
    0x10: "MDMCFG4", 0x11: "MDMCFG3", 0x12: "MDMCFG2", 0x13: "MDMCFG1",
    0x14: "MDMCFG0", 0x15: "DEVIATN", 0x16: "MCSM2", 0x17: "MCSM1",
    0x18: "MCSM0", 0x19: "FOCCFG", 0x1A: "BSCFG", 0x1B: "AGCCTRL2",
    0x1C: "AGCCTRL1", 0x1D: "AGCCTRL0", 0x1E: "WOREVT1", 0x1F: "WOREVT0",
    0x20: "WORCTRL", 0x21: "FREND1", 0x22: "FREND0", 0x23: "FSCAL3",
    0x24: "FSCAL2", 0x25: "FSCAL1", 0x26: "FSCAL0", 0x27: "RCCTRL1",
    0x28: "RCCTRL0", 0x29: "FSTEST", 0x2A: "PTEST", 0x2B: "AGCTEST",
    0x2C: "TEST2", 0x2D: "TEST1", 0x2E: "TEST0",
    0x30: "PARTNUM", 0x31: "VERSION", 0x32: "FREQEST", 0x33: "LQI",
    0x34: "RSSI", 0x35: "MARCSTATE", 0x36: "WORTIME1", 0x37: "WORTIME0",
    0x38: "PKTSTATUS", 0x39: "VCO_VC_DAC", 0x3A: "TXBYTES", 0x3B: "RXBYTES",
}

# Command strobes
CC110L_STROBES = {
    0x30: "SRES", 0x31: "SFSTXON", 0x32: "SXOFF", 0x33: "SCAL",
    0x34: "SRX", 0x35: "STX", 0x36: "SIDLE", 0x38: "SWOR",
    0x39: "SPWD", 0x3A: "SFRX", 0x3B: "SFTX", 0x3C: "SWORRST",
    0x3D: "SNOP"
}


def parse_csv(filename: str) -> List[SPITransaction]:
    """Parse Saleae SPI CSV export"""
    transactions = []

    with open(filename, 'r') as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Saleae CSV format typically has columns:
            # Time [s], Packet ID, MOSI, MISO
            # or similar - adjust based on actual export format

            try:
                # Try different column name variations
                time_str = row.get('Time [s]') or row.get('Time') or row.get('time')
                mosi_str = row.get('MOSI') or row.get('mosi')
                miso_str = row.get('MISO') or row.get('miso')

                if not all([time_str, mosi_str, miso_str]):
                    continue

                time = float(time_str)

                # Parse hex values (format: 0x12 or just 12)
                mosi = int(mosi_str.replace('0x', ''), 16) if mosi_str else 0
                miso = int(miso_str.replace('0x', ''), 16) if miso_str else 0

                transactions.append(SPITransaction(time, mosi, miso))

            except (ValueError, KeyError) as e:
                # Skip malformed rows
                continue

    return transactions


def extract_packets(transactions: List[SPITransaction]) -> List[Packet]:
    """Extract RF packets from SPI transactions"""
    packets = []
    i = 0

    while i < len(transactions):
        trans = transactions[i]
        cmd = trans.mosi

        # Check if this is a TX FIFO write (burst write to 0x3F)
        if cmd == 0x7F or cmd == 0x3F:  # 0x7F = burst write to TX FIFO
            packet_time = trans.time
            packet_data = []

            # Next byte is typically the length (in variable length mode)
            if i + 1 < len(transactions):
                i += 1
                length = transactions[i].mosi
                packet_data.append(length)

                # Read packet bytes
                for _ in range(min(length, 64)):  # Max packet size safety limit
                    if i + 1 < len(transactions):
                        i += 1
                        packet_data.append(transactions[i].mosi)

                packets.append(Packet(
                    time=packet_time,
                    direction='TX',
                    data=bytes(packet_data)
                ))
                print(f"[{packet_time:10.6f}s] TX Packet: {len(packet_data)} bytes")

        # Check if this is an RX FIFO read (burst read from 0x3F with R/W bit set)
        elif cmd == 0xFF or cmd == 0xBF:  # 0xBF = burst read from RX FIFO
            packet_time = trans.time
            packet_data = []

            # First read byte is usually the length
            if i + 1 < len(transactions):
                i += 1
                length = transactions[i].miso  # Data comes back on MISO
                packet_data.append(length)

                # Read packet bytes from MISO
                for _ in range(min(length, 64)):
                    if i + 1 < len(transactions):
                        i += 1
                        packet_data.append(transactions[i].miso)

                # Last 2 bytes are RSSI and LQI (appended by CC110L)
                rssi = None
                lqi = None
                if len(packet_data) >= 2:
                    # RSSI is second-to-last byte (signed)
                    rssi_raw = packet_data[-2]
                    if rssi_raw > 127:
                        rssi_raw = rssi_raw - 256
                    rssi = (rssi_raw / 2) - 74  # Convert to dBm

                    # LQI is last byte
                    lqi_raw = packet_data[-1]
                    lqi = lqi_raw & 0x7F
                    crc_ok = (lqi_raw & 0x80) != 0

                packets.append(Packet(
                    time=packet_time,
                    direction='RX',
                    data=bytes(packet_data),
                    rssi=rssi,
                    lqi=lqi
                ))
                print(f"[{packet_time:10.6f}s] RX Packet: {len(packet_data)} bytes, " +
                      f"RSSI: {rssi:.1f} dBm, LQI: {lqi}, CRC: {'OK' if crc_ok else 'FAIL'}")

        # Decode register operations for context
        elif (cmd & 0x3F) in CC110L_REGISTERS:
            reg_addr = cmd & 0x3F
            is_read = (cmd & 0x80) != 0
            is_burst = (cmd & 0x40) != 0
            reg_name = CC110L_REGISTERS[reg_addr]

            if i + 1 < len(transactions):
                i += 1
                value = transactions[i].miso if is_read else transactions[i].mosi
                # Uncomment to show register operations:
                # print(f"[{trans.time:10.6f}s] {'READ' if is_read else 'WRITE'} " +
                #       f"{reg_name} = 0x{value:02X}")

        # Decode command strobes
        elif cmd in CC110L_STROBES:
            strobe_name = CC110L_STROBES[cmd]
            # Uncomment to show strobes:
            # print(f"[{trans.time:10.6f}s] STROBE {strobe_name}")

        i += 1

    return packets


def analyze_packets(packets: List[Packet]):
    """Analyze packet patterns"""
    print("\n" + "="*70)
    print("PACKET ANALYSIS")
    print("="*70)

    tx_packets = [p for p in packets if p.direction == 'TX']
    rx_packets = [p for p in packets if p.direction == 'RX']

    print(f"\nTotal packets: {len(packets)}")
    print(f"  TX packets: {len(tx_packets)}")
    print(f"  RX packets: {len(rx_packets)}")

    if packets:
        print(f"\nPacket sizes:")
        sizes = {}
        for p in packets:
            size = len(p.data)
            sizes[size] = sizes.get(size, 0) + 1

        for size in sorted(sizes.keys()):
            print(f"  {size} bytes: {sizes[size]} packets")

        print(f"\n" + "="*70)
        print("SAMPLE PACKETS")
        print("="*70)

        # Show first few packets of each direction
        print("\nFirst TX packets:")
        for i, p in enumerate(tx_packets[:5]):
            hex_data = ' '.join(f'{b:02X}' for b in p.data)
            print(f"  TX #{i+1}: {hex_data}")

        print("\nFirst RX packets:")
        for i, p in enumerate(rx_packets[:5]):
            hex_data = ' '.join(f'{b:02X}' for b in p.data)
            rssi_str = f", RSSI: {p.rssi:.1f} dBm" if p.rssi else ""
            lqi_str = f", LQI: {p.lqi}" if p.lqi else ""
            print(f"  RX #{i+1}: {hex_data}{rssi_str}{lqi_str}")

    print("\n" + "="*70)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 parse_spi_csv.py <spi_capture.csv>")
        print("\nTo export from Saleae Logic 2:")
        print("  1. Open the .sal file")
        print("  2. Right-click on 'SPI CC110L' analyzer")
        print("  3. Select 'Export to text/csv file'")
        print("  4. Run this script on the exported file")
        sys.exit(1)

    filename = sys.argv[1]

    print(f"Parsing {filename}...")
    transactions = parse_csv(filename)

    if not transactions:
        print("ERROR: No SPI transactions found in CSV")
        print("\nPlease check:")
        print("  - CSV format matches expected columns (Time, MOSI, MISO)")
        print("  - File was exported from SPI analyzer (not raw digital channels)")
        sys.exit(1)

    print(f"Found {len(transactions)} SPI transactions")

    print("\nExtracting packets...")
    packets = extract_packets(transactions)

    if not packets:
        print("\nWARNING: No RF packets found in SPI data")
        print("This might mean:")
        print("  - No TX/RX FIFO operations in this capture")
        print("  - Capture only contains register configuration")
        print("  - Need a capture during actual RF communication")
    else:
        analyze_packets(packets)

        # Save packets to file
        output_file = filename.replace('.csv', '_packets.txt')
        with open(output_file, 'w') as f:
            f.write("Tado RF Packets Extracted from SPI Capture\n")
            f.write("="*70 + "\n\n")

            for i, p in enumerate(packets):
                f.write(f"Packet #{i+1} [{p.direction}] @ {p.time:.6f}s\n")
                hex_data = ' '.join(f'{b:02X}' for b in p.data)
                f.write(f"  Hex: {hex_data}\n")
                if p.rssi:
                    f.write(f"  RSSI: {p.rssi:.1f} dBm\n")
                if p.lqi:
                    f.write(f"  LQI: {p.lqi}\n")
                f.write("\n")

        print(f"\nPackets saved to: {output_file}")


if __name__ == '__main__':
    main()
