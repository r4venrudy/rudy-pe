"""Generate a tiny synthetic PE32+ file for parser demonstrations only."""

import pathlib
import struct
import sys


def put16(data, offset, value):
    struct.pack_into("<H", data, offset, value)


def put32(data, offset, value):
    struct.pack_into("<I", data, offset, value)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python create_minimal_pe.py <output-file>")
    data = bytearray(0x400)
    put16(data, 0, 0x5A4D)
    put32(data, 0x3C, 0x80)
    put32(data, 0x80, 0x00004550)
    put16(data, 0x84, 0x8664)
    put16(data, 0x86, 1)
    put16(data, 0x94, 0xF0)
    optional = 0x98
    put16(data, optional, 0x20B)
    put32(data, optional + 16, 0x1000)
    put32(data, optional + 56, 0x2000)
    put32(data, optional + 60, 0x200)
    put16(data, optional + 68, 3)
    put32(data, optional + 108, 16)
    section = 0x188
    data[section:section + 5] = b".text"
    put32(data, section + 8, 0x100)
    put32(data, section + 12, 0x1000)
    put32(data, section + 16, 0x200)
    put32(data, section + 20, 0x200)
    put32(data, section + 36, 0x60000020)
    pathlib.Path(sys.argv[1]).write_bytes(data)
    print(f"wrote {len(data)} bytes of synthetic PE32+ test data to {sys.argv[1]}")


if __name__ == "__main__":
    main()
