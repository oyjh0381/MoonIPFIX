#!/usr/bin/env python3
from pathlib import Path
TEMPLATE = bytes.fromhex("000a001c00000001000000000000002a0002000c0100000100080004")
DATA = bytes.fromhex("000a001800000002000000000000002a01000008c0000201")
target = Path(__file__).resolve().parents[1] / ".scratch" / "example.ipfix"
target.parent.mkdir(exist_ok=True)
target.write_bytes(TEMPLATE + DATA)
print(target)
