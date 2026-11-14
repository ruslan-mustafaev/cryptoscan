# cryptoscan

[![CI](https://github.com/ruslan-mustafaev/cryptoscan/actions/workflows/ci.yml/badge.svg)](https://github.com/ruslan-mustafaev/cryptoscan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)
![Ghidra](https://img.shields.io/badge/Ghidra-script-D2232A)
![License](https://img.shields.io/badge/license-MIT-green)

**Find cryptographic constants in binaries, firmware and memory dumps — from the command line or directly inside Ghidra.**

When you reverse a stripped binary, the fastest way to spot crypto code is to find the
constant tables it depends on: the AES S-box, SHA-256 round constants, CRC tables, etc.
`cryptoscan` finds them, tells you the **file offset, virtual address and section** (ELF/PE),
and the bundled Ghidra script **labels, comments and bookmarks** every hit.

- Zero dependencies, pure Python 3.8+
- Every table is **generated from its mathematical definition** (and unit-tested against the
  published reference values) — no opaque blobs
- Little- and big-endian variants of word tables
- ELF (32/64-bit, LE/BE) and PE/PE32+ offset → virtual address mapping
- JSON output for pipelines, recursive directory scan for firmware dumps

## Detected constants

| Algorithm | Signature | Confidence |
|---|---|---|
| AES | S-box, inverse S-box, Te0 T-table | high |
| SHA-256 | K round constants, initial hash values | high |
| SHA-512 | K round constants (64-bit) | high |
| MD5 | T (sine) table | high |
| MD5 / SHA-1 | initial state `67452301 efcdab89 …` | medium |
| CRC-32 / CRC-32C | lookup tables (zlib, Castagnoli) | high |
| ChaCha20 / Salsa20 | `expand 32-byte k`, `expand 16-byte k` | high |
| Blowfish | P-array (pi digits) | high |
| Base64 | standard alphabet | medium |

## Install

```bash
pip install git+https://github.com/ruslan-mustafaev/cryptoscan.git
```

## Usage

```bash
cryptoscan /usr/lib/x86_64-linux-gnu/libcrypto.so.3
```

```text
/usr/lib/x86_64-linux-gnu/libcrypto.so.3
  0x000b6ec0  0x000b6ec0  .text         AES S-box  [high]
  0x000b7b00  0x000b7b00  .text         AES inverse S-box  [high]
  0x000bc910  0x000bc910  .text         SHA-256 K constants (LE)  [high]
  0x0011fac0  0x0011fac0  .text         ChaCha20/Salsa20 sigma  [high]
  0x0033edd0  0x0033edd0  .text         SHA-512 K constants (LE)  [high]
  0x004099a0  0x004099a0  .rodata       Blowfish P-array (LE)  [high]
```

Columns: file offset · virtual address · section · constant (endianness) · confidence.

```bash
cryptoscan -r -q firmware_dump/            # scan a directory, hide files without hits
cryptoscan --min-confidence high sample.exe
cryptoscan --json sample.bin | jq '.[] | select(.algorithm == "AES")'
```

Exit code is `0` on success and `2` if a path could not be read.

### As a library

```python
from cryptoscan import scan_file

for m in scan_file("sample.bin"):
    print(hex(m.offset), m.vaddr, m.section, m.name)
```

## Ghidra script

`ghidra/CryptoScan.py` is self-contained and works with **Jython (Ghidra 9.x–11.x)** and
**PyGhidra (Ghidra 11.3+)**.

1. Open *Window → Script Manager → Manage Script Directories* and add the `ghidra/` folder
   (or copy `CryptoScan.py` into `~/ghidra_scripts`).
2. Run **CryptoScan** (category *Crypto*, or *Search → CryptoScan*).
3. Every match gets a label such as `CRYPTO_AES_S_BOX_00402040`, an end-of-line comment and a
   bookmark — open *Window → Bookmarks* and filter by `CryptoScan`.

From there, *References → Show References to* on the label leads you straight to the
encryption / hashing routine.

## Limitations

- Constants that are compiled into instructions as immediates (common for IVs such as
  `0x67452301`) are not contiguous in the file and will not be found by a byte scan.
- Packed, encrypted or compressed sections must be unpacked first.
- Mach-O offsets are reported, but not mapped to virtual addresses.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite compiles a small C program with `gcc` and checks that the reported virtual
addresses match `nm`, and verifies that the Ghidra script generates byte-for-byte the same
patterns as the Python package.

## License

[MIT](LICENSE) © Ruslan Mustafaev
