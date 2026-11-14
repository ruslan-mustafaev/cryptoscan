# Find well-known cryptographic constants (AES, SHA-2, MD5, CRC-32, ChaCha20,
# Blowfish, Base64) in the current program, then label, comment and bookmark them.
# Works with Jython (Ghidra 9.x - 11.x) and PyGhidra (Ghidra 11.3+).
#@author Ruslan Mustafaev
#@category Crypto
#@keybinding
#@menupath Search.CryptoScan
#@toolbar

# NOTE: this file is self-contained on purpose (Ghidra copies scripts around),
# so the signature generators below mirror cryptoscan/signatures.py.
# tests/test_ghidra_script.py checks that both produce identical patterns.

import math


def _rotl8(x, shift):
    return ((x << shift) | (x >> (8 - shift))) & 0xFF


def aes_sbox():
    sbox = [0] * 256
    p = 1
    q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
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


def aes_inv_sbox():
    sbox = aes_sbox()
    inv = [0] * 256
    for i in range(256):
        inv[sbox[i]] = i
    return inv


def _xtime(x):
    return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def aes_te0():
    table = []
    for s in aes_sbox():
        s2 = _xtime(s)
        table.append((s2 << 24) | (s << 16) | (s << 8) | (s2 ^ s))
    return table


def _primes(count):
    found = []
    candidate = 2
    while len(found) < count:
        if all(candidate % p for p in found if p * p <= candidate):
            found.append(candidate)
        candidate += 1
    return found


def _iroot(n, k):
    """Integer k-th root (floor) using Newton's method on Python big ints."""
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // (x ** (k - 1))) // k
        if y >= x:
            break
        x = y
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    return x


def sha256_k():
    return [_iroot(p << 96, 3) & 0xFFFFFFFF for p in _primes(64)]


def sha256_h():
    return [_iroot(p << 64, 2) & 0xFFFFFFFF for p in _primes(8)]


def sha512_k():
    return [_iroot(p << 192, 3) & 0xFFFFFFFFFFFFFFFF for p in _primes(80)]


def md5_t():
    return [int(abs(math.sin(i + 1)) * 4294967296.0) & 0xFFFFFFFF for i in range(64)]


def crc32_table(poly):
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = ((c >> 1) ^ poly) if c & 1 else (c >> 1)
        table.append(c)
    return table


MD5_SHA1_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
BLOWFISH_P = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
              0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89]
BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _ascii(text):
    return [ord(c) for c in text]


def _words(words, size, endian):
    out = []
    for w in words:
        chunk = [(w >> (8 * i)) & 0xFF for i in range(size)]
        if endian == "be":
            chunk.reverse()
        out.extend(chunk)
    return out


def build_signatures():
    """Return a list of (name, label, endian, confidence, [byte ints])."""
    sigs = [
        ("AES S-box", "n/a", "high", aes_sbox()),
        ("AES inverse S-box", "n/a", "high", aes_inv_sbox()),
        ("ChaCha20/Salsa20 sigma", "n/a", "high", _ascii("expand 32-byte k")),
        ("ChaCha20/Salsa20 tau", "n/a", "high", _ascii("expand 16-byte k")),
        ("Base64 alphabet", "n/a", "medium", _ascii(BASE64_ALPHABET)),
    ]
    word_tables = [
        ("AES Te0 table", aes_te0()[:8], 4, "high"),
        ("SHA-256 K constants", sha256_k()[:8], 4, "high"),
        ("SHA-256 initial hash", sha256_h(), 4, "high"),
        ("SHA-512 K constants", sha512_k()[:4], 8, "high"),
        ("MD5 T table", md5_t()[:8], 4, "high"),
        ("MD5/SHA-1 initial state", MD5_SHA1_IV, 4, "medium"),
        ("CRC-32 table", crc32_table(0xEDB88320)[:16], 4, "high"),
        ("CRC-32C table", crc32_table(0x82F63B78)[:16], 4, "high"),
        ("Blowfish P-array", BLOWFISH_P, 4, "high"),
    ]
    for name, words, size, confidence in word_tables:
        for endian in ("le", "be"):
            sigs.append((name, endian, confidence, _words(words, size, endian)))

    result = []
    for name, endian, confidence, data in sigs:
        label = "".join(c if c.isalnum() else "_" for c in name.upper())
        while "__" in label:
            label = label.replace("__", "_")
        result.append((name, "CRYPTO_" + label.strip("_"), endian, confidence, data))
    return result


# ---------------------------------------------------------------------------
# Ghidra part (only runs inside Ghidra, where `currentProgram` is defined)
# ---------------------------------------------------------------------------

def _to_java_bytes(values):
    try:
        import jarray  # Jython
        return jarray.array([v - 256 if v > 127 else v for v in values], "b")
    except ImportError:  # PyGhidra / JPype converts bytes to byte[]
        return bytes(bytearray(values))


def _check_cancelled():
    # Ghidra 11 renamed checkCanceled() to checkCancelled().
    if hasattr(monitor, "checkCancelled"):  # noqa: F821
        monitor.checkCancelled()  # noqa: F821
    else:
        monitor.checkCanceled()  # noqa: F821


def run_in_ghidra():
    memory = currentProgram.getMemory()  # noqa: F821
    total = 0
    signatures = build_signatures()
    monitor.initialize(len(signatures))  # noqa: F821
    for name, label, endian, confidence, data in signatures:
        _check_cancelled()
        monitor.setMessage("CryptoScan: " + name)  # noqa: F821
        pattern = _to_java_bytes(data)
        for block in memory.getBlocks():
            if not block.isInitialized():
                continue
            start = block.getStart()
            end = block.getEnd()
            while start is not None:
                found = memory.findBytes(start, end, pattern, None, True, monitor)  # noqa: F821
                if found is None:
                    break
                suffix = "" if endian == "n/a" else "_" + endian.upper()
                text = "%s%s [%s] (%d bytes)" % (
                    name, "" if endian == "n/a" else " (%s)" % endian.upper(),
                    confidence, len(data))
                try:
                    createLabel(found, "%s%s_%s" % (label, suffix, found.toString().replace(":", "_")), True)  # noqa: F821
                except Exception as exc:  # label may already exist
                    println("label failed at %s: %s" % (found, exc))  # noqa: F821
                setEOLComment(found, text)  # noqa: F821
                createBookmark(found, "CryptoScan", text)  # noqa: F821
                println("%s  %s" % (found, text))  # noqa: F821
                total += 1
                if found.compareTo(end) >= 0:
                    break
                start = found.add(1)
        monitor.incrementProgress(1)  # noqa: F821
    println("CryptoScan: %d match(es). See Window > Bookmarks, category 'CryptoScan'." % total)  # noqa: F821


if "currentProgram" in globals():
    run_in_ghidra()
