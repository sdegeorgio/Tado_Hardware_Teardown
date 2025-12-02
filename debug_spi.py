#!/usr/bin/env python3
"""
Debug SPI decoding - check if parsing is working
"""

from saleae_parser_v2 import parse_digital_channel_simple
from pathlib import Path


def main():
    extracted_dir = Path("/home/user/Tado_Hardware_Teardown/Logic Captures/extracted")

    print("Loading channels...")
    miso = parse_digital_channel_simple(extracted_dir / "digital-2.bin")
    mosi = parse_digital_channel_simple(extracted_dir / "digital-3.bin")
    sclk = parse_digital_channel_simple(extracted_dir / "digital-4.bin")
    cs = parse_digital_channel_simple(extracted_dir / "digital-5.bin")

    print(f"\nChannel transition counts:")
    print(f"  MISO: {len(miso.transitions)}")
    print(f"  MOSI: {len(mosi.transitions)}")
    print(f"  SCLK: {len(sclk.transitions)}")
    print(f"  CS:   {len(cs.transitions)}")

    print(f"\nFirst 20 CS transitions:")
    for i, (ts, state) in enumerate(cs.transitions[:20]):
        print(f"  {i}: ts={ts}, state={state}")

    # Find first CS low period
    cs_low_start = None
    cs_low_end = None

    for i, (ts, state) in enumerate(cs.transitions):
        if state == 0 and cs_low_start is None:
            cs_low_start = ts
            print(f"\nFirst CS goes LOW at timestamp {ts}")
        elif state == 1 and cs_low_start is not None and cs_low_end is None:
            cs_low_end = ts
            print(f"First CS goes HIGH at timestamp {ts}")
            print(f"Duration: {cs_low_end - cs_low_start} samples")
            break

    if cs_low_start and cs_low_end:
        # Count clock edges in this period
        clock_edges_in_period = [ts for ts, state in sclk.transitions
                                 if cs_low_start <= ts <= cs_low_end and state == 1]

        print(f"\nClock edges during first CS period: {len(clock_edges_in_period)}")

        if clock_edges_in_period:
            print(f"First 20 clock edges:")
            for i, edge_ts in enumerate(clock_edges_in_period[:20]):
                mosi_bit = mosi.get_state_at(edge_ts)
                miso_bit = miso.get_state_at(edge_ts)
                print(f"  {i}: ts={edge_ts}, MOSI={mosi_bit}, MISO={miso_bit}")


if __name__ == '__main__':
    main()
