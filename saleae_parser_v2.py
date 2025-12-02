#!/usr/bin/env python3
"""
Saleae Logic 2 Binary Parser - Attempt 2
Based on reverse engineering the binary format
"""

import struct
from pathlib import Path
from typing import List, Tuple
import json


class DigitalChannel:
    """Represents a digital channel with transitions"""

    def __init__(self, channel_num: int):
        self.channel_num = channel_num
        self.transitions = []  # List of (timestamp, state) tuples

    def add_transition(self, timestamp: int, state: int):
        self.transitions.append((timestamp, state))

    def get_state_at(self, timestamp: int) -> int:
        """Get signal state at a specific timestamp"""
        state = 0  # Default to low
        for ts, st in self.transitions:
            if ts > timestamp:
                break
            state = st
        return state


def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Read variable-length integer (similar to protobuf varint)
    Returns (value, bytes_consumed)
    """
    value = 0
    shift = 0
    bytes_consumed = 0

    while offset + bytes_consumed < len(data):
        byte = data[offset + bytes_consumed]
        bytes_consumed += 1

        # Add lower 7 bits to value
        value |= (byte & 0x7F) << shift

        # If high bit is not set, we're done
        if (byte & 0x80) == 0:
            break

        shift += 7

    return value, bytes_consumed


def parse_digital_channel_simple(filepath: Path) -> DigitalChannel:
    """
    Parse a digital channel file using simplified approach
    """
    channel_num = int(filepath.stem.split('-')[1])
    channel = DigitalChannel(channel_num)

    with open(filepath, 'rb') as f:
        data = f.read()

    # Skip header
    if not data.startswith(b'<SALEAE>'):
        print(f"Invalid header in {filepath.name}")
        return channel

    offset = 8  # After "<SALEAE>"

    # Read version, length, type
    version = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    length_field = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    type_field = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    # Skip additional header data
    # This varies but typically there's metadata before the transition data
    # Look for the pattern where transitions start
    # Transitions are encoded as: delta_time (varint), state_change

    # Skip to data section (heuristic: skip first ~32 bytes of metadata)
    offset += 20

    timestamp = 0
    current_state = 0
    transition_count = 0

    print(f"Parsing channel {channel_num}...")

    while offset < len(data):
        try:
            # Read time delta as varint
            delta, consumed = read_varint(data, offset)
            if consumed == 0:
                break

            offset += consumed
            timestamp += delta

            # State toggles with each transition
            current_state = 1 - current_state

            channel.add_transition(timestamp, current_state)
            transition_count += 1

            # Safety limit for testing
            if transition_count > 100000:
                break

        except Exception as e:
            # If we hit an error, we might have run out of data
            break

    print(f"  Found {transition_count} transitions")
    return channel


def decode_spi_bytes(mosi: DigitalChannel, miso: DigitalChannel,
                     sclk: DigitalChannel, cs: DigitalChannel) -> List[Tuple[int, int, int]]:
    """
    Decode SPI bytes from digital channels
    Returns list of (timestamp, mosi_byte, miso_byte)
    """
    transactions = []

    # Find CS active (low) periods
    cs_low_periods = []
    cs_state = 1
    cs_start = None

    for ts, state in cs.transitions:
        if state == 0 and cs_state == 1:
            cs_start = ts
            cs_state = 0
        elif state == 1 and cs_state == 0:
            if cs_start:
                cs_low_periods.append((cs_start, ts))
            cs_state = 1

    print(f"\nFound {len(cs_low_periods)} CS active periods")

    # For each CS period, find clock edges and sample data
    for period_num, (cs_start, cs_end) in enumerate(cs_low_periods[:20]):  # Limit for testing
        # Find rising clock edges in this period
        clock_edges = [ts for ts, state in sclk.transitions
                      if cs_start <= ts <= cs_end and state == 1]

        if len(clock_edges) < 8:
            continue  # Not enough for a full byte

        print(f"\n  CS Period {period_num}: {len(clock_edges)} clock edges")

        # Decode bytes
        mosi_byte = 0
        miso_byte = 0
        bit_count = 0
        bytes_decoded = []

        for edge_ts in clock_edges:
            # Sample MOSI and MISO at clock edge
            mosi_bit = mosi.get_state_at(edge_ts)
            miso_bit = miso.get_state_at(edge_ts)

            # Shift in bit (MSB first)
            mosi_byte = (mosi_byte << 1) | mosi_bit
            miso_byte = (miso_byte << 1) | miso_bit
            bit_count += 1

            if bit_count == 8:
                # Complete byte
                bytes_decoded.append((edge_ts, mosi_byte, miso_byte))
                mosi_byte = 0
                miso_byte = 0
                bit_count = 0

        # Print decoded bytes for this transaction
        if bytes_decoded:
            print(f"    Decoded {len(bytes_decoded)} bytes:")
            for ts, mosi_b, miso_b in bytes_decoded[:10]:  # Show first 10
                print(f"      MOSI: 0x{mosi_b:02X}, MISO: 0x{miso_b:02X}")

        transactions.extend(bytes_decoded)

    return transactions


def analyze_cc110_commands(transactions: List[Tuple[int, int, int]]):
    """
    Analyze CC110L SPI commands
    """
    print("\n" + "="*60)
    print("CC110L Command Analysis")
    print("="*60)

    # CC110L command byte format:
    # Bit 7: R/W (0=write, 1=read)
    # Bit 6: Burst (0=single, 1=burst)
    # Bits 5-0: Address

    for i, (ts, mosi, miso) in enumerate(transactions[:100]):  # Analyze first 100
        is_read = (mosi & 0x80) != 0
        is_burst = (mosi & 0x40) != 0
        address = mosi & 0x3F

        cmd_type = "READ " if is_read else "WRITE"
        burst_str = " BURST" if is_burst else ""

        # Decode register addresses
        reg_names = {
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
            0x3C: "RCCTRL1_STATUS", 0x3D: "RCCTRL0_STATUS",
            0x3E: "PA_TABLE", 0x3F: "TX_FIFO", 0xBF: "RX_FIFO"
        }

        # Command strobes
        strobe_names = {
            0x30: "SRES", 0x31: "SFSTXON", 0x32: "SXOFF", 0x33: "SCAL",
            0x34: "SRX", 0x35: "STX", 0x36: "SIDLE", 0x38: "SWOR",
            0x39: "SPWD", 0x3A: "SFRX", 0x3B: "SFTX", 0x3C: "SWORRST",
            0x3D: "SNOP"
        }

        if address in reg_names:
            reg_name = reg_names[address]
        elif mosi in strobe_names:
            reg_name = strobe_names[mosi]
            cmd_type = "STROBE"
            burst_str = ""
        else:
            reg_name = f"0x{address:02X}"

        print(f"{i:4d}. {cmd_type}{burst_str:6s} {reg_name:15s} MOSI=0x{mosi:02X} MISO=0x{miso:02X}")


def main():
    """Main parser"""
    extracted_dir = Path("/home/user/Tado_Hardware_Teardown/Logic Captures/extracted")

    print("Parsing Saleae capture...\n")

    # Parse channels
    miso = parse_digital_channel_simple(extracted_dir / "digital-2.bin")
    mosi = parse_digital_channel_simple(extracted_dir / "digital-3.bin")
    sclk = parse_digital_channel_simple(extracted_dir / "digital-4.bin")
    cs = parse_digital_channel_simple(extracted_dir / "digital-5.bin")

    if not all([miso.transitions, mosi.transitions, sclk.transitions, cs.transitions]):
        print("\nERROR: Could not parse channels properly")
        print("\nRECOMMENDED: Export SPI data from Saleae Logic 2:")
        print("  1. Open the .sal file in Saleae Logic 2")
        print("  2. Right-click the 'SPI CC110L' analyzer")
        print("  3. Select 'Export to text/csv file'")
        return

    # Decode SPI
    print("\n" + "="*60)
    print("Decoding SPI Transactions")
    print("="*60)

    transactions = decode_spi_bytes(mosi, miso, sclk, cs)

    print(f"\nTotal SPI bytes decoded: {len(transactions)}")

    if transactions:
        analyze_cc110_commands(transactions)


if __name__ == '__main__':
    main()
