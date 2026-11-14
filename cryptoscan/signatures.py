"""Signatures of well-known cryptographic constants.

Every table is generated from its mathematical definition instead of being
pasted as a blob, so the values can be audited and unit-tested.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class Signature:
    """A byte pattern that identifies a cryptographic primitive."""

    name: str          # Human readable name, e.g. "AES S-box"
    algorithm: str     # Algorithm family, e.g. "AES"
    pattern: bytes     # Exact bytes to search for
    endian: str        # "le", "be" or "n/a" for byte tables / strings
    confidence: str    # "high" or "medium"

    @property
    def label(self) -> str:
        """Identifier usable as a disassembler label."""
        clean = "".join(c if c.isalnum() else "_" for c in self.name.upper())
        while "__" in clean:
            clean = clean.replace("__", "_")
        return "CRYPTO_" + clean.strip("_")


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def _rotl8(x: int, shift: int) -> int:
    return ((x << shift) | (x >> (8 - shift))) & 0xFF


def aes_sbox() -> List[int]:
    """AES forward S-box (multiplicative inverse in GF(2^8) + affine map)."""
    sbox = [0] * 256
    p = q = 1
    while True:
        # Multiply p by 3 in GF(2^8)
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        # Divide q by 3 (q becomes the multiplicative inverse of p)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


def aes_inv_sbox() -> List[int]:
    sbox = aes_sbox()
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv


def _xtime(x: int) -> int:
    return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def aes_te0() -> List[int]:
    """First T-table used by table-based AES implementations (OpenSSL style)."""
    table = []
    for s in aes_sbox():
        s2 = _xtime(s)
        s3 = s2 ^ s
        table.append((s2 << 24) | (s << 16) | (s << 8) | s3)
    return table


def _primes(count: int) -> List[int]:
    found: List[int] = []
    candidate = 2
    while len(found) < count:
        if all(candidate % p for p in found if p * p <= candidate):
            found.append(candidate)
        candidate += 1
    return found


def _icbrt(n: int) -> int:
    """Integer cube root (floor)."""
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


def sha256_k() -> List[int]:
    """SHA-256 round constants: fractional parts of cube roots of first 64 primes."""
    return [_icbrt(p << 96) & 0xFFFFFFFF for p in _primes(64)]


def sha256_h() -> List[int]:
    """SHA-256 initial hash: fractional parts of square roots of first 8 primes."""
    return [math.isqrt(p << 64) & 0xFFFFFFFF for p in _primes(8)]


def sha512_k() -> List[int]:
    """SHA-512 round constants (64-bit)."""
    return [_icbrt(p << 192) & 0xFFFFFFFFFFFFFFFF for p in _primes(80)]


def md5_t() -> List[int]:
    """MD5 sine table: floor(abs(sin(i + 1)) * 2^32)."""
    return [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]


def crc32_table(poly: int) -> List[int]:
    """Reflected CRC-32 lookup table for the given (reversed) polynomial."""
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        table.append(c)
    return table


MD5_SHA1_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

# Hex digits of pi; Blowfish P-array initial values.
BLOWFISH_P = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
]

BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# ---------------------------------------------------------------------------
# Signature construction
# ---------------------------------------------------------------------------

def _encode_words(words: List[int], size: int, endian: str) -> bytes:
    order = "little" if endian == "le" else "big"
    return b"".join(w.to_bytes(size, order) for w in words)


def _word_signatures(name: str, algorithm: str, words: List[int], size: int,
                     confidence: str = "high") -> List[Signature]:
    sigs = []
    for endian in ("le", "be"):
        sigs.append(Signature(name, algorithm, _encode_words(words, size, endian),
                              endian, confidence))
    return sigs


def build_signatures() -> List[Signature]:
    sigs: List[Signature] = [
        Signature("AES S-box", "AES", bytes(aes_sbox()), "n/a", "high"),
        Signature("AES inverse S-box", "AES", bytes(aes_inv_sbox()), "n/a", "high"),
        Signature("ChaCha20/Salsa20 sigma", "ChaCha20", b"expand 32-byte k", "n/a", "high"),
        Signature("ChaCha20/Salsa20 tau", "ChaCha20", b"expand 16-byte k", "n/a", "high"),
        Signature("Base64 alphabet", "Base64", BASE64_ALPHABET, "n/a", "medium"),
    ]
    sigs += _word_signatures("AES Te0 table", "AES", aes_te0()[:8], 4)
    sigs += _word_signatures("SHA-256 K constants", "SHA-256", sha256_k()[:8], 4)
    sigs += _word_signatures("SHA-256 initial hash", "SHA-256", sha256_h(), 4)
    sigs += _word_signatures("SHA-512 K constants", "SHA-512", sha512_k()[:4], 8)
    sigs += _word_signatures("MD5 T table", "MD5", md5_t()[:8], 4)
    sigs += _word_signatures("MD5/SHA-1 initial state", "MD5/SHA-1", MD5_SHA1_IV, 4,
                             confidence="medium")
    sigs += _word_signatures("CRC-32 table", "CRC-32", crc32_table(0xEDB88320)[:16], 4)
    sigs += _word_signatures("CRC-32C table", "CRC-32C", crc32_table(0x82F63B78)[:16], 4)
    sigs += _word_signatures("Blowfish P-array", "Blowfish", BLOWFISH_P, 4)
    return sigs


SIGNATURES: Tuple[Signature, ...] = tuple(build_signatures())
