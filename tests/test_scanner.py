import json
import shutil
import subprocess

import pytest

from cryptoscan import cli, scan_bytes, scan_file
from cryptoscan import signatures as s


def _names(matches):
    return {(m.name, m.endian) for m in matches}


def test_finds_constants_in_raw_blob():
    blob = (b"\x00" * 100 + bytes(s.aes_sbox()) + b"junk"
            + b"".join(k.to_bytes(4, "big") for k in s.sha256_k())
            + b"expand 32-byte k")
    matches = scan_bytes(blob)
    names = _names(matches)
    assert ("AES S-box", "n/a") in names
    assert ("SHA-256 K constants", "be") in names
    assert ("ChaCha20/Salsa20 sigma", "n/a") in names
    sbox = next(m for m in matches if m.name == "AES S-box")
    assert sbox.offset == 100 and sbox.vaddr is None


def test_min_confidence_filters_medium():
    blob = s.BASE64_ALPHABET + bytes(s.aes_sbox())
    assert ("Base64 alphabet", "n/a") in _names(scan_bytes(blob))
    high = _names(scan_bytes(blob, min_confidence="high"))
    assert ("Base64 alphabet", "n/a") not in high
    assert ("AES S-box", "n/a") in high


def test_empty_and_clean_inputs(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert scan_file(str(empty)) == []
    assert scan_bytes(b"\x00" * 4096) == []


C_SOURCE = """
#include <stdint.h>
#include <stdio.h>
const uint8_t sbox[256] = { %s };
const uint32_t k256[64] = { %s };
int main(void) { printf("%%d %%u\\n", sbox[1], (unsigned)k256[1]); return 0; }
"""


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not installed")
def test_elf_virtual_addresses(tmp_path):
    src = tmp_path / "sample.c"
    src.write_text(C_SOURCE % (
        ", ".join(str(b) for b in s.aes_sbox()),
        ", ".join(f"0x{k:08x}u" for k in s.sha256_k()),
    ))
    binary = tmp_path / "sample"
    subprocess.run(["gcc", "-O0", "-no-pie", str(src), "-o", str(binary)], check=True)

    matches = scan_file(str(binary))
    sbox = next(m for m in matches if m.name == "AES S-box")
    assert sbox.section == ".rodata"
    assert sbox.vaddr is not None and sbox.vaddr > sbox.offset

    nm = subprocess.run(["nm", str(binary)], capture_output=True, text=True, check=True)
    symbols = {line.split()[-1]: int(line.split()[0], 16)
               for line in nm.stdout.splitlines() if len(line.split()) == 3}
    assert sbox.vaddr == symbols["sbox"]
    k = next(m for m in matches if m.name == "SHA-256 K constants")
    assert k.vaddr == symbols["k256"]


def test_cli_json(tmp_path, capsys):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"xx" + bytes(s.aes_inv_sbox()))
    assert cli.main([str(target), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["name"] == "AES inverse S-box"
    assert data[0]["offset"] == 2


def test_cli_text_and_errors(tmp_path, capsys):
    target = tmp_path / "blob.bin"
    target.write_bytes(bytes(s.aes_sbox()))
    assert cli.main([str(target)]) == 0
    assert "AES S-box" in capsys.readouterr().out
    assert cli.main([str(tmp_path / "missing.bin")]) == 2


def test_cli_recursive(tmp_path, capsys):
    sub = tmp_path / "fw"
    sub.mkdir()
    (sub / "a.bin").write_bytes(b"expand 16-byte k")
    (sub / "b.bin").write_bytes(b"nothing here")
    assert cli.main(["-r", "-q", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "a.bin" in out and "b.bin" not in out
