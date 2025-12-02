#!/usr/bin/env python3
"""
Saleae Logic 2 Binary Format Parser
Parses .sal files to extract SPI communication data
"""

import struct
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Optional

@dataclass
class Transition:
    """Represents a digital signal transition"""
    timestamp: int  # In sample counts
    state: int      # 0 or 1

    def time_seconds(self, sample_rate: int) -> float:
        """Convert timestamp to seconds"""
        return self.timestamp / sample_rate


class SaleaeParser:
    """Parser for Saleae Logic 2 binary files"""

    def __init__(self, extracted_dir: str):
        self.extracted_dir = Path(extracted_dir)
        self.meta = self._load_meta()
        self.sample_rate = self.meta['data']['captureSettings']['connectedDevice']['settings']['sampleRate']['digital']

    def _load_meta(self) -> dict:
        """Load metadata JSON"""
        meta_path = self.extracted_dir / 'meta.json'
        with open(meta_path, 'r') as f:
            return json.load(f)

    def parse_digital_channel(self, channel_num: int) -> List[Transition]:
        """Parse a digital channel binary file"""
        file_path = self.extracted_dir / f'digital-{channel_num}.bin'

        if not file_path.exists():
            print(f"Warning: {file_path} not found")
            return []

        transitions = []

        with open(file_path, 'rb') as f:
            # Read header
            header = f.read(8)
            if header != b'<SALEAE>':
                print(f"Warning: Invalid header in {file_path}")
                return []

            # Read version (4 bytes)
            version = struct.unpack('<I', f.read(4))[0]
            print(f"Channel {channel_num}: Version {version}")

            # Read data length (4 bytes)
            data_len = struct.unpack('<I', f.read(4))[0]

            # Read data type (4 bytes)
            data_type = struct.unpack('<I', f.read(4))[0]

            # Skip to data section (varies by version)
            # The rest of the file contains transition data
            # Format appears to be: timestamp (variable length encoded) + state

            position = 0
            last_timestamp = 0
            current_state = 0

            while True:
                # Try to read transition data
                chunk = f.read(1024)
                if not chunk:
                    break

                # This is simplified - actual format is complex with variable-length encoding
                # For now, let's try a different approach

        print(f"Channel {channel_num}: Found {len(transitions)} transitions")
        return transitions

    def decode_variable_length_int(self, data: bytes, offset: int) -> Tuple[int, int]:
        """
        Decode variable-length integer used in Saleae format
        Returns (value, bytes_consumed)
        """
        value = 0
        shift = 0
        bytes_read = 0

        while offset + bytes_read < len(data):
            byte = data[offset + bytes_read]
            bytes_read += 1

            value |= (byte & 0x7F) << shift

            if (byte & 0x80) == 0:
                break

            shift += 7

        return value, bytes_read


class SPIDecoder:
    """Decode SPI communication from digital signals"""

    def __init__(self, mosi_transitions: List[Transition],
                 miso_transitions: List[Transition],
                 sclk_transitions: List[Transition],
                 cs_transitions: List[Transition],
                 sample_rate: int):
        self.mosi = mosi_transitions
        self.miso = miso_transitions
        self.sclk = sclk_transitions
        self.cs = cs_transitions
        self.sample_rate = sample_rate

    def get_state_at_time(self, transitions: List[Transition], timestamp: int) -> int:
        """Get signal state at a given timestamp"""
        state = 0
        for trans in transitions:
            if trans.timestamp > timestamp:
                break
            state = trans.state
        return state

    def decode(self) -> List[Tuple[float, int, int]]:
        """
        Decode SPI transactions
        Returns list of (timestamp, mosi_byte, miso_byte)
        """
        transactions = []

        # Find CS low periods (active)
        cs_active_periods = []
        cs_state = 1  # Assume CS starts high
        cs_start = None

        for trans in self.cs:
            if trans.state == 0 and cs_state == 1:
                # CS goes low (active)
                cs_start = trans.timestamp
                cs_state = 0
            elif trans.state == 1 and cs_state == 0:
                # CS goes high (inactive)
                if cs_start is not None:
                    cs_active_periods.append((cs_start, trans.timestamp))
                cs_state = 1

        print(f"Found {len(cs_active_periods)} SPI transactions")

        # For each CS active period, decode bytes on clock edges
        for cs_start, cs_end in cs_active_periods[:10]:  # Limit to first 10 for testing
            # Find rising edges of clock in this period
            clock_edges = [t for t in self.sclk if cs_start <= t.timestamp <= cs_end and t.state == 1]

            if len(clock_edges) == 0:
                continue

            # Decode bytes (8 bits per byte)
            mosi_byte = 0
            miso_byte = 0
            bit_count = 0

            for edge in clock_edges:
                # Sample data at clock edge
                mosi_bit = self.get_state_at_time(self.mosi, edge.timestamp)
                miso_bit = self.get_state_at_time(self.miso, edge.timestamp)

                # MSB first
                mosi_byte = (mosi_byte << 1) | mosi_bit
                miso_byte = (miso_byte << 1) | miso_bit
                bit_count += 1

                if bit_count == 8:
                    # Complete byte
                    timestamp_sec = edge.time_seconds(self.sample_rate)
                    transactions.append((timestamp_sec, mosi_byte, miso_byte))
                    mosi_byte = 0
                    miso_byte = 0
                    bit_count = 0

        return transactions


def main():
    """Main parser function"""
    extracted_dir = "/home/user/Tado_Hardware_Teardown/Logic Captures/extracted"

    print("Loading Saleae capture data...")
    parser = SaleaeParser(extracted_dir)

    print(f"Sample rate: {parser.sample_rate:,} Hz")
    print(f"Capture duration: {parser.meta['data']['captureProgress']['maxCollectedTime']:.2f} seconds")

    # Parse digital channels
    print("\nParsing digital channels...")

    # Channel mapping from meta.json:
    # Channel 2: MISO
    # Channel 3: MOSI
    # Channel 4: SCLK
    # Channel 5: CSn CC110L

    miso = parser.parse_digital_channel(2)
    mosi = parser.parse_digital_channel(3)
    sclk = parser.parse_digital_channel(4)
    cs = parser.parse_digital_channel(5)

    if not all([miso, mosi, sclk, cs]):
        print("\nERROR: Could not parse all required channels")
        print("The Saleae binary format is complex. Recommended approach:")
        print("1. Open the .sal file in Saleae Logic 2")
        print("2. Right-click on the 'SPI CC110L' analyzer")
        print("3. Select 'Export to text/csv file'")
        print("4. Save the CSV export")
        return

    # Decode SPI
    print("\nDecoding SPI transactions...")
    decoder = SPIDecoder(mosi, miso, sclk, cs, parser.sample_rate)
    transactions = decoder.decode()

    print(f"\nFound {len(transactions)} SPI bytes")
    print("\nFirst 50 transactions:")
    print("Time (s)    MOSI    MISO")
    print("-" * 30)
    for timestamp, mosi_byte, miso_byte in transactions[:50]:
        print(f"{timestamp:10.6f}  0x{mosi_byte:02X}    0x{miso_byte:02X}")


if __name__ == '__main__':
    main()
