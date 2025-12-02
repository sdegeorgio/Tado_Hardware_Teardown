#!/usr/bin/env python3
"""
Examine Saleae binary format structure
"""

import struct
from pathlib import Path

def examine_file(filepath):
    """Examine structure of a Saleae binary file"""
    print(f"\n{'='*60}")
    print(f"Examining: {filepath.name}")
    print(f"Size: {filepath.stat().st_size:,} bytes")
    print(f"{'='*60}")

    with open(filepath, 'rb') as f:
        # Read and display header
        header = f.read(8)
        print(f"Header: {header}")

        if header != b'<SALEAE>':
            print("ERROR: Invalid header!")
            return

        # Read version
        version = struct.unpack('<I', f.read(4))[0]
        print(f"Version: {version}")

        # Read length
        length = struct.unpack('<I', f.read(4))[0]
        print(f"Length field: {length}")

        # Read type
        data_type = struct.unpack('<I', f.read(4))[0]
        print(f"Type field: {data_type}")

        # Read next fields
        print("\nNext 64 bytes (hex):")
        next_data = f.read(64)
        for i in range(0, len(next_data), 16):
            hex_str = ' '.join(f'{b:02X}' for b in next_data[i:i+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in next_data[i:i+16])
            print(f"  {i+20:04X}: {hex_str:48s} {ascii_str}")

        # Try to find patterns
        f.seek(0)
        data = f.read()

        print(f"\nFile analysis:")
        print(f"Total size: {len(data):,} bytes")

        # Look for repeated byte values
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        print(f"Unique bytes: {len(byte_counts)}")
        print(f"Most common bytes:")
        for byte, count in sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  0x{byte:02X}: {count:,} times ({100*count/len(data):.1f}%)")


def main():
    extracted_dir = Path("/home/user/Tado_Hardware_Teardown/Logic Captures/extracted")

    # Examine each channel
    for channel in [1, 2, 3, 4, 5, 6, 7]:
        filepath = extracted_dir / f"digital-{channel}.bin"
        if filepath.exists():
            examine_file(filepath)


if __name__ == '__main__':
    main()
