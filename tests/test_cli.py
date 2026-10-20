import json
import pathlib
import struct
import subprocess
import sys
import tempfile


def put16(data, offset, value):
    struct.pack_into("<H", data, offset, value)


def put32(data, offset, value):
    struct.pack_into("<I", data, offset, value)


def fixture():
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
    return data


def run(binary, *args):
    return subprocess.run([binary, *args], capture_output=True, text=True, check=False)


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "sample.exe"
        path.write_bytes(fixture())

        json_result = run(binary, "--format", "json", str(path))
        assert json_result.returncode == 0, json_result.stderr
        report = json.loads(json_result.stdout)
        assert report["machine"] == "AMD64"
        assert report["bitness"] == 64
        assert report["sections"][0]["name"] == ".text"

        sarif_result = run(binary, "--format", "sarif", str(path))
        assert sarif_result.returncode == 0, sarif_result.stderr
        sarif = json.loads(sarif_result.stdout)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert isinstance(sarif["runs"][0]["results"], list)

        text_result = run(binary, str(path))
        assert text_result.returncode == 0, text_result.stderr
        assert "AMD64 64-bit image" in text_result.stdout

        path.write_bytes(b"MZ")
        malformed = run(binary, "--format", "json", str(path))
        assert malformed.returncode == 2
        assert "malformed PE" in malformed.stderr

        bad_option = run(binary, "--format", "yaml", str(path))
        assert bad_option.returncode == 1

    print("CLI text, JSON, SARIF, malformed-input, and argument tests passed.")


if __name__ == "__main__":
    main()
