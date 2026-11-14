"""Check generated tables against published reference values."""

from cryptoscan import signatures as s


def test_aes_sbox_reference_values():
    sbox = s.aes_sbox()
    assert sbox[:8] == [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]
    assert sbox[0xFF] == 0x16
    assert sorted(sbox) == list(range(256))


def test_aes_inverse_sbox():
    inv = s.aes_inv_sbox()
    assert inv[:4] == [0x52, 0x09, 0x6A, 0xD5]
    sbox = s.aes_sbox()
    assert all(inv[sbox[i]] == i for i in range(256))


def test_aes_te0():
    assert s.aes_te0()[:2] == [0xC66363A5, 0xF87C7C84]


def test_sha256_constants():
    k = s.sha256_k()
    assert k[0] == 0x428A2F98 and k[1] == 0x71374491 and k[63] == 0xC67178F2
    assert s.sha256_h() == [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]


def test_sha512_constants():
    k = s.sha512_k()
    assert k[0] == 0x428A2F98D728AE22
    assert k[79] == 0x6C44198C4A475817


def test_md5_t():
    t = s.md5_t()
    assert t[:4] == [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE]
    assert t[63] == 0xEB86D391


def test_crc_tables():
    assert s.crc32_table(0xEDB88320)[1] == 0x77073096
    assert s.crc32_table(0xEDB88320)[255] == 0x2D02EF8D
    assert s.crc32_table(0x82F63B78)[1] == 0xF26B8303


def test_signature_patterns_are_unique():
    patterns = [sig.pattern for sig in s.SIGNATURES]
    assert len(patterns) == len(set(patterns))
    assert all(len(p) >= 16 for p in patterns)


def test_labels_are_identifiers():
    for sig in s.SIGNATURES:
        assert sig.label.replace("_", "").isalnum(), sig.label
