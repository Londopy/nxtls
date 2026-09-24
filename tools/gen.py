#!/usr/bin/env python3
"""Generate nxtls's constant tables and test vectors.

Test tooling only, never shipped with nxtls. Every constant in
src/tables.nx is derived here from its definition (roots of primes for
SHA-2, the curve equation for Ed25519), and every vector under
tests/vectors/ comes from Python's hashlib and hmac and from the
`cryptography` package, which serve as the reference implementations
the Nexium code has to agree with. Published values from the standards
(FIPS 180-4, FIPS 186-5, RFC 4231, RFC 5869, RFC 6455, RFC 7748, RFC 8017,
RFC 8032, RFC 8439, RFC 8448) are asserted along the way, so a mistake here cannot quietly become
a "correct" answer. RFC 8439's vectors are in tools/rfc8439.py, extracted
from the RFC's text rather than typed in.

    python tools/gen.py           rewrite src/tables.nx and tests/vectors/
    python tools/gen.py --check   exit 1 when the files on disk differ
"""

import base64
import hashlib
import hmac as pyhmac
import os
import random
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.asymmetric import padding as pypad, rsa as pyrsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from rfc8439 import RFC8439, RFC8439_COUNTERS  # noqa: E402
RNG = random.Random(20260922)


def rand_bytes(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


def hx(b):
    return b.hex() if b else "-"


# ------------------------------------------------------------------ SHA-2


def primes(n):
    out = []
    c = 2
    while len(out) < n:
        if all(c % q for q in out if q * q <= c):
            out.append(c)
        c += 1
    return out


def icbrt(n):
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


def isqrt(n):
    import math

    return math.isqrt(n)


P80 = primes(80)
M32 = (1 << 32) - 1
M64 = (1 << 64) - 1
K256 = [icbrt(q << 96) & M32 for q in P80[:64]]
K512 = [icbrt(q << 192) & M64 for q in P80]
IV256 = [isqrt(q << 64) & M32 for q in P80[:8]]
IV384 = [isqrt(q << 128) & M64 for q in P80[8:16]]
IV512 = [isqrt(q << 128) & M64 for q in P80[:8]]

# FIPS 180-4 sections 4.2.2, 4.2.3, 5.3.3 to 5.3.5
assert K256[0] == 0x428A2F98 and K256[63] == 0xC67178F2
assert K512[0] == 0x428A2F98D728AE22 and K512[79] == 0x6C44198C4A475817
assert IV256 == [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
assert IV384[0] == 0xCBBB9D5DC1059ED8 and IV384[7] == 0x47B5481DBEFA4FA4
assert IV512[0] == 0x6A09E667F3BCC908 and IV512[7] == 0x5BE0CD19137E2179


# ------------------------------------------------------------------ Ed25519

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
assert D == 37095705934669439343138083508754565189542113879843219016388785533085940283555
assert SQRT_M1 * SQRT_M1 % P == P - 1


def recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


BY = 4 * pow(5, P - 2, P) % P
BX = recover_x(BY, 0)
assert BX == 15112221349535400772501151409588531511454012693041857206046113283949847762202


def enc_point(x, y):
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


assert enc_point(BX, BY) == bytes.fromhex("58" + "66" * 31)


def pt_add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P
    return (x3, y3)


def pt_mul(s, pt):
    q = (0, 1)
    while s > 0:
        if s & 1:
            q = pt_add(q, pt)
        pt = pt_add(pt, pt)
        s >>= 1
    return q


def limbs(v):
    return [(v >> (51 * i)) & ((1 << 51) - 1) for i in range(5)]


# ------------------------------------------------------------------ tables.nx


def nx_array(name, typ, values, width, per_line):
    digits = width // 4
    rows = []
    for i in range(0, len(values), per_line):
        chunk = values[i : i + per_line]
        rows.append("    " + ", ".join("0x%0*x" % (digits, v) for v in chunk) + ",")
    return "pub const %s: [%d]%s = [\n%s\n]\n" % (name, len(values), typ, "\n".join(rows))


def nx_bytes(name, b):
    return nx_array(name, "u8", list(b), 8, 16)


def nx_fe(name, v):
    return "pub const %s: [5]u64 = [%s]\n" % (name, ", ".join("0x%x" % l for l in limbs(v)))


def nist_curve(curve, p, n):
    """A NIST curve's p, n, b and base point, from the reference: G is 1 G,
    n is confirmed as the order by (n - 1) G = -G and n refused as a key,
    and b follows from y^2 = x^3 - 3x + b at G."""
    g = ec.derive_private_key(1, curve).public_key().public_numbers()
    m = ec.derive_private_key(n - 1, curve).public_key().public_numbers()
    assert m.x == g.x and m.y == (p - g.y) % p, "the order"
    try:
        ec.derive_private_key(n, curve)
        raise AssertionError("n accepted as a key")
    except ValueError:
        pass
    b = (g.y * g.y - g.x ** 3 + 3 * g.x) % p
    return {"p": p, "n": n, "b": b, "gx": g.x, "gy": g.y}


# FIPS 186-5 (D.1.2.3, D.1.2.4): the primes by their published forms, the
# orders as published (confirmed above)
P256 = nist_curve(ec.SECP256R1(), 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1,
                  0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)
P384 = nist_curve(ec.SECP384R1(), 2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1,
                  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973)
assert P256["b"] == 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
assert P256["gx"] == 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296


def nx_curve(prefix, c, size):
    out = ""
    for key in ["p", "n", "b", "gx", "gy"]:
        out += nx_bytes("%s_%s" % (prefix, key.upper()), c[key].to_bytes(size, "big"))
    return out


def tables_nx():
    parts = [
        "// tables.nx: constants for sha2.nx, ed25519.nx and ecdsa.nx.\n"
        "//\n"
        "// GENERATED by tools/gen.py; do not edit. Each value is derived there\n"
        "// from its definition: SHA-2's round constants are the fractional\n"
        "// parts of the cube roots of the first 80 primes and its initial\n"
        "// values the square roots of the first 16 (FIPS 180-4); the Ed25519\n"
        "// constants come from the curve equation (RFC 8032), with field\n"
        "// elements as five 51-bit limbs, least significant first; the NIST\n"
        "// curves' come from Python's cryptography package, checked against\n"
        "// their published forms (FIPS 186-5).\n",
        nx_array("K256", "u32", K256, 32, 4),
        nx_array("K512", "u64", K512, 64, 2),
        nx_array("IV256", "u32", IV256, 32, 4),
        nx_array("IV384", "u64", IV384, 64, 2),
        nx_array("IV512", "u64", IV512, 64, 2),
        "/// d = -121665/121666 mod p\n" + nx_fe("ED_D", D),
        "/// 2d, used by point addition\n" + nx_fe("ED_D2", 2 * D % P),
        "/// a square root of -1 mod p, 2^((p-1)/4)\n" + nx_fe("ED_SQRT_M1", SQRT_M1),
        "/// the base point B: y = 4/5, x even; t = xy\n"
        + nx_fe("ED_BX", BX)
        + nx_fe("ED_BY", BY)
        + nx_fe("ED_BT", BX * BY % P),
        "/// the group order L = 2^252 + 27742317777372353535851937790883648493, little-endian\n"
        + nx_bytes("ED_L", L.to_bytes(32, "little")),
        "/// p - 2, the exponent of an inversion, little-endian\n"
        + nx_bytes("ED_P_MINUS_2", (P - 2).to_bytes(32, "little")),
        "/// (p + 3) / 8, the exponent of a square root candidate, little-endian\n"
        + nx_bytes("ED_P_PLUS_3_DIV_8", ((P + 3) // 8).to_bytes(32, "little")),
        "/// NIST P-256 (FIPS 186-5): p, the order n, b and the base point, big-endian\n"
        + nx_curve("P256", P256, 32),
        "/// NIST P-384 (FIPS 186-5): p, the order n, b and the base point, big-endian\n"
        + nx_curve("P384", P384, 48),
    ]
    return "\n".join(parts)


# ------------------------------------------------------------------ vectors

NIST_MESSAGES = [
    b"",
    b"abc",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
    b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
]
ALGS = [("sha256", hashlib.sha256), ("sha384", hashlib.sha384), ("sha512", hashlib.sha512)]


def pattern(n):
    # the same generator is in the Nexium tests: byte i of message n
    return bytes(((i * 31) + n) & 0xFF for i in range(n))


def sha2_vectors():
    assert hashlib.sha256(b"abc").hexdigest() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    lines = ["# alg message digest; message is hex, - for empty, pattern:N, or million-a"]
    for name, fn in ALGS:
        for m in NIST_MESSAGES:
            lines.append("%s %s %s" % (name, hx(m), fn(m).hexdigest()))
        for n in list(range(0, 141)) + [191, 192, 239, 240, 255, 256, 257, 1000, 4099]:
            lines.append("%s pattern:%d %s" % (name, n, fn(pattern(n)).hexdigest()))
        lines.append("%s million-a %s" % (name, fn(b"a" * 1000000).hexdigest()))
    return "\n".join(lines) + "\n"


def sha1_vectors():
    # FIPS 180-4's published examples, and RFC 6455's handshake example
    assert hashlib.sha1(b"abc").hexdigest() == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hashlib.sha1(NIST_MESSAGES[2]).hexdigest() == "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    assert hashlib.sha1(b"a" * 1000000).hexdigest() == "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    key = b"dGhlIHNhbXBsZSBub25jZQ=="
    accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
    assert accept == b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    lines = ["# message digest; message is hex, - for empty, pattern:N, or million-a"]
    for m in NIST_MESSAGES:
        lines.append("%s %s" % (hx(m), hashlib.sha1(m).hexdigest()))
    for n in list(range(0, 141)) + [191, 192, 255, 256, 257, 1000, 4099]:
        lines.append("pattern:%d %s" % (n, hashlib.sha1(pattern(n)).hexdigest()))
    lines.append("million-a %s" % hashlib.sha1(b"a" * 1000000).hexdigest())
    return "\n".join(lines) + "\n"


RFC4231 = [
    (b"\x0b" * 20, b"Hi There"),
    (b"Jefe", b"what do ya want for nothing?"),
    (b"\xaa" * 20, b"\xdd" * 50),
    (bytes(range(1, 26)), b"\xcd" * 50),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First"),
    (b"\xaa" * 131, b"This is a test using a larger than block-size key and a larger "
                    b"than block-size data. The key needs to be hashed before being "
                    b"used by the HMAC algorithm."),
]


def hmac_vectors():
    assert pyhmac.new(RFC4231[0][0], RFC4231[0][1], hashlib.sha256).hexdigest() == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    lines = ["# alg key message mac (hex, - for empty)"]
    for name, fn in ALGS:
        for key, msg in RFC4231:
            lines.append("%s %s %s %s" % (name, hx(key), hx(msg), pyhmac.new(key, msg, fn).hexdigest()))
        for kl in [0, 1, 32, 47, 48, 63, 64, 65, 127, 128, 129, 200]:
            key = rand_bytes(kl)
            msg = rand_bytes(RNG.randrange(0, 300))
            lines.append("%s %s %s %s" % (name, hx(key), hx(msg), pyhmac.new(key, msg, fn).hexdigest()))
    return "\n".join(lines) + "\n"


def py_hkdf(fn, salt, ikm, info, length):
    size = fn().digest_size
    prk = pyhmac.new(salt if salt else b"\x00" * size, ikm, fn).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = pyhmac.new(prk, t + info + bytes([i]), fn).digest()
        okm += t
        i += 1
    return prk, okm[:length]


def expand_label(fn, secret, label, context, length):
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    size = fn().digest_size
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = pyhmac.new(secret, t + info + bytes([i]), fn).digest()
        okm += t
        i += 1
    assert size > 0
    return okm[:length]


def hkdf_vectors():
    rfc5869 = [
        (bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
         bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42),
        (bytes(range(0x00, 0x50)), bytes(range(0x60, 0xB0)), bytes(range(0xB0, 0x100)), 82),
        (bytes.fromhex("0b" * 22), b"", b"", 42),
    ]
    ikm, salt, info, length = rfc5869[0]
    prk, okm = py_hkdf(hashlib.sha256, salt, ikm, info, length)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")
    lines = ["# alg ikm salt info length prk okm"]
    algs = {"sha256": (hashlib.sha256, hashes.SHA256()), "sha384": (hashlib.sha384, hashes.SHA384()),
            "sha512": (hashlib.sha512, hashes.SHA512())}
    cases = [("sha256",) + c for c in rfc5869]
    for name in algs:
        for _ in range(6):
            cases.append((name, rand_bytes(RNG.randrange(1, 90)), rand_bytes(RNG.choice([0, 13, 64, 128])),
                          rand_bytes(RNG.randrange(0, 40)), RNG.randrange(1, 300)))
    for name, ikm, salt, info, length in cases:
        fn, alg = algs[name]
        prk, okm = py_hkdf(fn, salt, ikm, info, length)
        ref = HKDF(algorithm=alg, length=length, salt=salt or None, info=info).derive(ikm)
        assert ref == okm, "HKDF disagrees with cryptography"
        lines.append("%s %s %s %s %d %s %s" % (name, hx(ikm), hx(salt), hx(info), length, prk.hex(), okm.hex()))
    return "\n".join(lines) + "\n"


def hkdf_label_vectors():
    # RFC 8448 section 3, "Simple 1-RTT Handshake": the early secret and the
    # "derived" secret that follows it
    early, _ = py_hkdf(hashlib.sha256, b"", b"\x00" * 32, b"", 32)
    assert early.hex() == "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
    derived = expand_label(hashlib.sha256, early, b"derived", hashlib.sha256(b"").digest(), 32)
    assert derived.hex() == "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
    lines = ["# alg secret label context length output; the label is hex (labels hold",
             "# spaces) and without its tls13 prefix"]
    lines.append("sha256 %s %s %s 32 %s" % (early.hex(), b"derived".hex(), hashlib.sha256(b"").hexdigest(),
                                            derived.hex()))
    labels = [b"key", b"iv", b"finished", b"c hs traffic", b"s ap traffic", b"derived", b"traffic upd"]
    for name, fn in ALGS:
        for label in labels:
            secret = rand_bytes(fn().digest_size)
            context = RNG.choice([b"", rand_bytes(fn().digest_size)])
            length = RNG.choice([12, 16, 32, fn().digest_size])
            out = expand_label(fn, secret, label, context, length)
            lines.append("%s %s %s %s %d %s" % (name, secret.hex(), label.hex(), hx(context), length, out.hex()))
    return "\n".join(lines) + "\n"


def raw_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ref_verify(pk, msg, sig):
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def ed25519_vectors():
    lines = ["# expect public-key message signature what",
             "# nxtls is stricter than RFC 8032 where marked strict: like libsodium it",
             "# rejects small-order public keys and R values and every non-canonical",
             "# encoding, which some verifiers (OpenSSL among them) accept"]
    checked = []

    def add(expect, pk, msg, sig, what, strict=False):
        what = what.replace(" ", "_") + ("_strict" if strict else "")
        lines.append("%s %s %s %s %s" % (expect, hx(pk), hx(msg), hx(sig), what))
        if not strict:
            checked.append((expect, pk, msg, sig, what))

    # RFC 8032 section 7.1, TEST 1, 2 and 3: keys from their secret seeds
    rfc = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", b"",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
         "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", bytes.fromhex("72"),
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", bytes.fromhex("af82"),
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]
    for i, (seed, msg, sig) in enumerate(rfc):
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        assert key.sign(msg).hex() == sig, "RFC 8032 test %d" % (i + 1)
        add("valid", raw_pub(key), msg, bytes.fromhex(sig), "rfc8032 test %d" % (i + 1))

    for i in range(40):
        key = Ed25519PrivateKey.from_private_bytes(rand_bytes(32))
        pk = raw_pub(key)
        msg = rand_bytes(RNG.choice([0, 1, 31, 32, 64, 100, 511, 1500]))
        sig = key.sign(msg)
        add("valid", pk, msg, sig, "random %d" % i)
        if i % 4 == 0:
            bad = bytearray(msg or b"\x00")
            bad[RNG.randrange(len(bad))] ^= 1 << RNG.randrange(8)
            add("invalid", pk, bytes(bad), sig, "message bit flipped %d" % i)
        if i % 4 == 1:
            bad = bytearray(sig)
            bad[RNG.randrange(32)] ^= 1 << RNG.randrange(8)
            add("invalid", pk, msg, bytes(bad), "R bit flipped %d" % i)
        if i % 4 == 2:
            bad = bytearray(sig)
            bad[32 + RNG.randrange(31)] ^= 1 << RNG.randrange(8)
            add("invalid", pk, msg, bytes(bad), "S bit flipped %d" % i)
        if i % 4 == 3:
            other = raw_pub(Ed25519PrivateKey.from_private_bytes(rand_bytes(32)))
            add("invalid", other, msg, sig, "someone else's key %d" % i)
        if i < 6:
            # S + L names the same point; RFC 8032 requires rejecting S >= L
            s = int.from_bytes(sig[32:], "little") + L
            assert s < 2 ** 256
            add("invalid", pk, msg, sig[:32] + s.to_bytes(32, "little"), "S plus L %d" % i)

    # the identity as a public key signs anything with R = B, S = 1
    msg = b"small order"
    r_b = enc_point(BX, BY)
    one = (1).to_bytes(32, "little")
    add("invalid", (1).to_bytes(32, "little"), msg, r_b + one, "identity public key", strict=True)
    add("invalid", (P + 1).to_bytes(32, "little"), msg, r_b + one, "noncanonical identity key", strict=True)
    add("invalid", ((1 << 255) | 1).to_bytes(32, "little"), msg, r_b + one, "x zero with sign bit", strict=True)
    # (sqrt(-1), 0) is a point of order 4
    four = recover_x(0, 0)
    assert four is not None and pt_mul(4, (four, 0)) == (0, 1)
    add("invalid", enc_point(four, 0), msg, r_b + one, "order four public key", strict=True)
    # a y with no x on the curve
    y = 2
    while recover_x(y, 0) is not None:
        y += 1
    key = Ed25519PrivateKey.from_private_bytes(rand_bytes(32))
    sig = key.sign(msg)
    add("invalid", y.to_bytes(32, "little"), msg, sig, "public key off the curve")
    # y = p is out of range even though p mod p = 0 names a point
    add("invalid", raw_pub(key), msg, sig[:32] + L.to_bytes(32, "little"), "S equal to L")
    add("invalid", raw_pub(key), msg, (1).to_bytes(32, "little") + sig[32:], "identity R")
    add("invalid", raw_pub(key)[:31], msg, sig, "short public key")
    add("invalid", raw_pub(key), msg, sig[:63], "short signature")

    # the reference agrees with every expectation that is not marked strict
    for expect, pk, msg, sig, what in checked:
        got = ref_verify(pk, msg, sig)
        assert got == (expect == "valid"), "reference disagrees on " + what
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ X25519


def x25519(k, u):
    """X25519(k, u) by the reference, or None when it is all zeros (the
    reference refuses those)."""
    try:
        return X25519PrivateKey.from_private_bytes(k).exchange(X25519PublicKey.from_public_bytes(u))
    except ValueError:
        return None


def x25519_vectors():
    lines = ["# scalar u-coordinate result (RFC 7748 5.2 and 6.1, then random scalars",
             "# against points, points on the twist, and u with bit 255 set)"]
    rfc = [
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        # 6.1: Alice's and Bob's public keys, then their shared secret
        ("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         "0900000000000000000000000000000000000000000000000000000000000000",
         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
        ("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
         "0900000000000000000000000000000000000000000000000000000000000000",
         "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
        ("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
         "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
    ]
    for k, u, out in rfc:
        got = x25519(bytes.fromhex(k), bytes.fromhex(u))
        assert got is not None and got.hex() == out, "RFC 7748 " + out
        lines.append("%s %s %s" % (k, u, out))
    n = 0
    while n < 120:
        k = rand_bytes(32)
        kind = n % 4
        if kind < 2:
            # a real public key
            u = X25519PrivateKey.from_private_bytes(rand_bytes(32)).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        elif kind == 2:
            # any 32 bytes, most of them on the twist
            u = rand_bytes(32)
        else:
            # bit 255 set: ignored, as RFC 7748 says
            u = bytearray(rand_bytes(32))
            u[31] |= 0x80
            u = bytes(u)
        got = x25519(k, u)
        if got is None:
            continue
        lines.append("%s %s %s" % (k.hex(), u.hex(), got.hex()))
        n += 1
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ ChaCha20 and Poly1305


def rfc8439(section, vector, label):
    for s, v, name, h in RFC8439:
        if (s, v, name) == (section, vector, label):
            return bytes.fromhex(h)
    raise KeyError((section, vector, label))


def chacha20(key, counter, nonce, data):
    """The reference's ChaCha20: its 16-byte nonce is the 32-bit counter,
    little-endian, then the 12-byte nonce."""
    enc = Cipher(algorithms.ChaCha20(key, counter.to_bytes(4, "little") + nonce), mode=None).encryptor()
    return enc.update(data)


def chacha20_vectors():
    lines = ["# key counter nonce plaintext ciphertext (RFC 8439 A.1, A.2 and A.4,",
             "# then random lengths and counters)"]

    def add(key, counter, nonce, pt, ct):
        assert chacha20(key, counter, nonce, pt) == ct
        lines.append("%s %d %s %s %s" % (hx(key), counter, hx(nonce), hx(pt), hx(ct)))

    for v in "12345":
        ks = rfc8439("A.1", v, "Keystream")
        add(rfc8439("A.1", v, "Key"), RFC8439_COUNTERS["A.1#" + v], rfc8439("A.1", v, "Nonce"), bytes(len(ks)), ks)
    for v in "123":
        add(rfc8439("A.2", v, "Key"), RFC8439_COUNTERS["A.2#" + v], rfc8439("A.2", v, "Nonce"),
            rfc8439("A.2", v, "Plaintext"), rfc8439("A.2", v, "Ciphertext"))
    # A.4: the Poly1305 key is the first 32 bytes of block 0
    for v in "123":
        otk = rfc8439("A.4", v, "Poly1305 one-time key")
        add(rfc8439("A.4", v, "The ChaCha20 Key"), 0, rfc8439("A.4", v, "The nonce"), bytes(32), otk)
    for i in range(30):
        n = RNG.choice([0, 1, 63, 64, 65, 127, 128, 129, 300, 1000])
        counter = RNG.choice([0, 1, 7, 12345, 2 ** 32 - 20])
        key, nonce, pt = rand_bytes(32), rand_bytes(12), rand_bytes(n)
        add(key, counter, nonce, pt, chacha20(key, counter, nonce, pt))
    return "\n".join(lines) + "\n"


def poly1305_vectors():
    lines = ["# key message tag (RFC 8439 A.3, whose vectors 5 to 11 try the carries",
             "# and the final reduction, then random)"]

    def add(key, msg, tag):
        assert Poly1305.generate_tag(key, msg) == tag
        lines.append("%s %s %s" % (hx(key), hx(msg), hx(tag)))

    for v in "1234":
        add(rfc8439("A.3", v, "One-time Poly1305 Key"), rfc8439("A.3", v, "Text to MAC"), rfc8439("A.3", v, "Tag"))
    for v in ["5", "6", "7", "8", "9", "10", "11"]:
        add(rfc8439("A.3", v, "R") + rfc8439("A.3", v, "S"), rfc8439("A.3", v, "data"), rfc8439("A.3", v, "tag"))
    for i in range(40):
        n = RNG.choice([0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 255, 1000])
        key, msg = rand_bytes(32), rand_bytes(n)
        add(key, msg, Poly1305.generate_tag(key, msg))
    # r and s all ones: the widest intermediate values
    ones = bytes([0xff] * 32)
    for n in [16, 64, 1000]:
        msg = bytes([0xff] * n)
        add(ones, msg, Poly1305.generate_tag(ones, msg))
    return "\n".join(lines) + "\n"


def aead_vectors():
    lines = ["# key nonce aad plaintext sealed (the ciphertext, then the 16-byte tag;",
             "# RFC 8439 2.8.2 and A.5, then random)"]

    def add(key, nonce, aad, pt, sealed):
        assert ChaCha20Poly1305(key).encrypt(nonce, pt, aad) == sealed
        lines.append("%s %s %s %s %s" % (hx(key), hx(nonce), hx(aad), hx(pt), hx(sealed)))

    # 2.8.2 prints the tag apart; the ciphertext must match
    key = rfc8439("2.8.2", "", "Key")
    # the nonce: the 32-bit common part, then the 64-bit IV
    nonce = rfc8439("2.8.2", "", "32-bit fixed-common part") + rfc8439("2.8.2", "", "IV")
    assert chacha20(key, 0, nonce, bytes(32)) == rfc8439("2.8.2", "", "Poly1305 Key")
    aad = rfc8439("2.8.2", "", "AAD")
    pt = rfc8439("2.8.2", "", "Plaintext")
    sealed = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    assert sealed[:-16] == rfc8439("2.8.2", "", "Ciphertext")
    add(key, nonce, aad, pt, sealed)
    # A.5: a message received, with its tag
    key = rfc8439("A.5", "", "The ChaCha20 Key")
    nonce = rfc8439("A.5", "", "The nonce")
    aad = rfc8439("A.5", "", "The AAD")
    ct = rfc8439("A.5", "", "Ciphertext")
    tag = rfc8439("A.5", "", "Received Tag")
    assert tag == rfc8439("A.5", "", "Calculated Tag")
    pt = ChaCha20Poly1305(key).decrypt(nonce, ct + tag, aad)
    assert pt == rfc8439("A.5", "", "Plaintext")
    add(key, nonce, aad, pt, ct + tag)
    for i in range(40):
        key, nonce = rand_bytes(32), rand_bytes(12)
        aad = rand_bytes(RNG.choice([0, 1, 12, 16, 17, 64]))
        pt = rand_bytes(RNG.choice([0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 1000]))
        add(key, nonce, aad, pt, ChaCha20Poly1305(key).encrypt(nonce, pt, aad))
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ ECDSA

EC_CURVES = [("p256", ec.SECP256R1(), P256, 32), ("p384", ec.SECP384R1(), P384, 48)]
EC_HASHES = [("sha256", hashes.SHA256(), 32), ("sha384", hashes.SHA384(), 48)]


def ec_sign(curve, c, size, d, digest, k):
    """ECDSA as FIPS 186-5 has it, with k given (the vectors must not change
    from run to run): r = (k G).x mod n, s = k^-1 (e + r d) mod n."""
    n = c["n"]
    e = int.from_bytes(digest[:size], "big") % n
    r = ec.derive_private_key(k, curve).public_key().public_numbers().x % n
    s = pow(k, -1, n) * (e + r * d) % n
    assert r != 0 and s != 0
    return r, s


def der_int(v, pad=False):
    """A DER INTEGER; with `pad`, one zero byte more than DER allows."""
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    if pad:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def der_sig(r, s, pad_r=False, trailing=b""):
    body = der_int(r, pad_r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body + trailing


def ref_ecdsa(curve, pub, digest, sig, hash_alg):
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(curve, pub)
        key.verify(sig, digest, ec.ECDSA(asym_utils.Prehashed(hash_alg)))
        return True
    except Exception:
        return False


def ecdsa_vectors():
    lines = ["# expect curve public-key hash signature what (hash: the message's digest;",
             "# signature: DER; public key: uncompressed; nxtls is stricter than the",
             "# reference where marked strict)"]
    checked = []

    def add(expect, name, pub, digest, sig, what, strict=False):
        what = what.replace(" ", "_") + ("_strict" if strict else "")
        lines.append("%s %s %s %s %s %s" % (expect, name, hx(pub), hx(digest), hx(sig), what))

    for name, curve, c, size in EC_CURVES:
        n, p = c["n"], c["p"]
        for hname, halg, hlen in EC_HASHES:
            for i in range(8):
                d = int.from_bytes(rand_bytes(size + 8), "big") % (n - 1) + 1
                k = int.from_bytes(rand_bytes(size + 8), "big") % (n - 1) + 1
                key = ec.derive_private_key(d, curve)
                pub = key.public_key().public_bytes(serialization.Encoding.X962,
                                                    serialization.PublicFormat.UncompressedPoint)
                digest = rand_bytes(hlen)
                r, s = ec_sign(curve, c, size, d, digest, k)
                sig = der_sig(r, s)
                what = "%s %s %d" % (name, hname, i)
                assert ref_ecdsa(curve, pub, digest, sig, halg), what
                add("valid", name, pub, digest, sig, what)
                checked.append((curve, pub, digest, sig, halg, True, what))
                if i == 0:
                    # s and n - s both verify: ECDSA is malleable, not broken
                    add("valid", name, pub, digest, der_sig(r, n - s), what + " n minus s")
                    checked.append((curve, pub, digest, der_sig(r, n - s), halg, True, what))
                    bad = bytearray(digest)
                    bad[RNG.randrange(len(bad))] ^= 1 << RNG.randrange(8)
                    add("invalid", name, pub, bytes(bad), sig, what + " hash bit flipped")
                    add("invalid", name, pub, digest, der_sig(r ^ 1, s), what + " r changed")
                    add("invalid", name, pub, digest, der_sig(r, s ^ 1), what + " s changed")
                    add("invalid", name, pub, digest, der_sig(0, s), what + " r zero")
                    add("invalid", name, pub, digest, der_sig(r, 0), what + " s zero")
                    add("invalid", name, pub, digest, der_sig(r, n), what + " s equal to n")
                    add("invalid", name, pub, digest, der_sig(n + r, s), what + " r plus n")
                    other = ec.derive_private_key(int.from_bytes(rand_bytes(size + 8), "big") % (n - 1) + 1, curve)
                    opub = other.public_key().public_bytes(serialization.Encoding.X962,
                                                           serialization.PublicFormat.UncompressedPoint)
                    add("invalid", name, opub, digest, sig, what + " someone else's key")
                    off = bytearray(pub)
                    off[-1] ^= 1
                    add("invalid", name, bytes(off), digest, sig, what + " key off the curve")
                    x = int.from_bytes(pub[1:1 + size], "big")
                    y = int.from_bytes(pub[1 + size:], "big")
                    big = b"\x04" + (x + p).to_bytes(size + 1, "big")[1:] + pub[1 + size:] if x + p < 2 ** (8 * size) else None
                    if big is not None:
                        add("invalid", name, big, digest, sig, what + " x plus p")
                    compressed = bytes([2 + (y & 1)]) + pub[1:1 + size]
                    add("invalid", name, compressed, digest, sig, what + " compressed key", strict=True)
                    add("invalid", name, pub, digest, der_sig(r, s, pad_r=True), what + " needless zero in r", strict=True)
                    add("invalid", name, pub, digest, der_sig(r, s, trailing=b"\x00"), what + " trailing byte", strict=True)
    # the reference agrees with every expectation that is not marked strict
    for line in lines:
        if line.startswith("#") or line.endswith("_strict"):
            continue
        f = line.split(" ")
        curve = ec.SECP384R1() if f[1] == "p384" else ec.SECP256R1()
        digest = bytes.fromhex(f[3])
        halg = hashes.SHA384() if len(digest) == 48 else hashes.SHA256()
        got = ref_ecdsa(curve, bytes.fromhex(f[2]), digest, bytes.fromhex(f[4]), halg)
        assert got == (f[0] == "valid"), "the reference disagrees on " + f[5]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ RSA

SMALL_PRIMES = primes(1000)[1:]
RSA_HASHES = [("sha256", hashlib.sha256, hashes.SHA256()),
              ("sha384", hashlib.sha384, hashes.SHA384()),
              ("sha512", hashlib.sha512, hashes.SHA512())]
# RFC 8017 9.2, note 1: the DER DigestInfo before the hash
DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def probable_prime(n):
    """Miller-Rabin, 40 rounds with bases from the seeded RNG."""
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(40):
        x = pow(RNG.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rand_prime(bits, e):
    """A prime of `bits` bits with its top two set (so two of them multiply
    to the full size), and p - 1 prime to e."""
    while True:
        c = RNG.getrandbits(bits) | (3 << (bits - 2)) | 1
        if any(c % q == 0 for q in SMALL_PRIMES):
            continue
        if (c - 1) % e == 0 or not probable_prime(c):
            continue
        return c


def rsa_key(bits, e=65537):
    """A key of exactly `bits` bits from the seeded RNG (the reference makes
    its own keys at random, so the vectors would change from run to run),
    built through the reference, which checks it."""
    a = (bits + 1) // 2
    p = rand_prime(a, e)
    q = rand_prime(bits - a, e)
    n = p * q
    assert n.bit_length() == bits
    d = pow(e, -1, (p - 1) * (q - 1))
    key = pyrsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p),
                                  pyrsa.RSAPublicNumbers(e, n)).private_key()
    return {"key": key, "n": n, "e": e, "d": d, "k": (bits + 7) // 8}


def rsa_raw(key, em):
    """The private operation on an encoded message (which must be below n)."""
    m = int.from_bytes(em, "big")
    assert m < key["n"]
    return pow(m, key["d"], key["n"]).to_bytes(key["k"], "big")


def pkcs1_encode(k, name, digest, info=None):
    t = (DIGEST_INFO[name] if info is None else info) + digest
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def mgf1(fn, seed, length):
    out = b""
    c = 0
    while len(out) < length:
        out += fn(seed + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:length]


def pss_encode(fn, digest, salt, em_bits, trailer=0xBC, top=False):
    """EMSA-PSS-ENCODE (RFC 8017 9.1.1) with the salt given; `top` leaves
    the bits past emBits set, which a verifier must refuse."""
    em_len = (em_bits + 7) // 8
    h = fn(b"\x00" * 8 + digest + salt).digest()
    db = b"\x00" * (em_len - len(salt) - len(h) - 2) + b"\x01" + salt
    masked = bytearray(a ^ b for a, b in zip(db, mgf1(fn, h, len(db))))
    spare = 8 * em_len - em_bits
    if top:
        masked[0] |= (0xFF << (8 - spare)) & 0xFF
    else:
        masked[0] &= 0xFF >> spare
    return bytes(masked) + h + bytes([trailer])


def pss_sign(key, fn, digest, salt_len=None, trailer=0xBC, top=False, lead=0):
    """A PSS signature from the seeded RNG's salts: tried until the encoding
    (with `lead` as the byte in front when EM is a byte short of n) lies
    below n."""
    em_bits = key["n"].bit_length() - 1
    k = key["k"]
    while True:
        salt = rand_bytes(fn().digest_size if salt_len is None else salt_len)
        em = pss_encode(fn, digest, salt, em_bits, trailer, top)
        if len(em) < k:
            em = bytes([lead]) + em
        if int.from_bytes(em, "big") < key["n"]:
            return rsa_raw(key, em)


def ref_rsa(n, e, scheme, halg, digest, sig):
    try:
        public = pyrsa.RSAPublicNumbers(e, n).public_key()
        if scheme == "pss":
            pad = pypad.PSS(mgf=pypad.MGF1(halg), salt_length=halg.digest_size)
        else:
            pad = pypad.PKCS1v15()
        public.verify(sig, digest, pad, asym_utils.Prehashed(halg))
        return True
    except Exception:
        return False


def int_hex(v):
    return v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big").hex()


def rsa_vectors():
    lines = ["# expect scheme hash n e digest signature what (hash: the message's digest;",
             "# n and e big-endian; nxtls is stricter than the reference where marked strict)"]

    def add(expect, scheme, name, key, digest, sig, what, strict=False, e=None):
        what = what.replace(" ", "_") + ("_strict" if strict else "")
        lines.append("%s %s %s %s %s %s %s %s" % (
            expect, scheme, name, int_hex(key["n"]), int_hex(key["e"] if e is None else e),
            hx(digest), hx(sig), what))

    keys = [("2048", rsa_key(2048)), ("2049", rsa_key(2049)), ("3072", rsa_key(3072)),
            ("4096", rsa_key(4096))]
    other = rsa_key(2048)
    for label, key in keys:
        k = key["k"]
        for name, fn, halg in RSA_HASHES:
            digest = rand_bytes(fn().digest_size)
            what = "%s %s" % (label, name)
            sig = key["key"].sign(digest, pypad.PKCS1v15(), asym_utils.Prehashed(halg))
            # the reference's signature is the encoding this file expects
            assert sig == rsa_raw(key, pkcs1_encode(k, name, digest)), what
            add("valid", "pkcs1", name, key, digest, sig, what)
            pss = pss_sign(key, fn, digest)
            add("valid", "pss", name, key, digest, pss, what)
            full = label in ("2048", "2049") and name == "sha256"
            some = label in ("3072", "4096") and name == "sha384"
            if not (full or some):
                continue
            bad = bytearray(digest)
            bad[RNG.randrange(len(bad))] ^= 1 << RNG.randrange(8)
            flipped = bytearray(sig)
            flipped[RNG.randrange(len(sig))] ^= 1 << RNG.randrange(8)
            pflipped = bytearray(pss)
            pflipped[RNG.randrange(len(pss))] ^= 1 << RNG.randrange(8)
            add("invalid", "pkcs1", name, key, bytes(bad), sig, what + " hash bit flipped")
            add("invalid", "pkcs1", name, key, digest, bytes(flipped), what + " signature bit flipped")
            add("invalid", "pss", name, key, bytes(bad), pss, what + " hash bit flipped")
            add("invalid", "pss", name, key, digest, bytes(pflipped), what + " signature bit flipped")
            if not full:
                continue
            n_bytes = key["n"].to_bytes(k, "big")
            add("invalid", "pkcs1", name, key, digest, n_bytes, what + " signature equal to n")
            add("invalid", "pss", name, key, digest, n_bytes, what + " signature equal to n")
            add("invalid", "pkcs1", name, key, digest, b"\x00" + sig,
                what + " signature a byte long", strict=True)
            add("invalid", "pss", name, other, digest, pss, what + " someone else's key")
            add("invalid", "pkcs1", name, other, digest, sig, what + " someone else's key")
            add("invalid", "pss", name, key, digest, sig, what + " PKCS1 signature as PSS")
            add("invalid", "pkcs1", name, key, digest, pss, what + " PSS signature as PKCS1")
            add("invalid", "pkcs1", "sha384", key, digest, sig, what + " named SHA-384")
            # DigestInfo without the NULL parameters, which RFC 8017 requires
            no_null = bytes.fromhex("302f300b0609608648016503040201") + b"\x04\x20"
            add("invalid", "pkcs1", name, key, digest, rsa_raw(key, pkcs1_encode(k, name, digest, no_null)),
                what + " DigestInfo without NULL", strict=True)
            # a byte of garbage after the hash, one FF fewer
            em = pkcs1_encode(k, name, digest)
            add("invalid", "pkcs1", name, key, digest, rsa_raw(key, em[:2] + em[3:] + b"\x00"),
                what + " garbage after the hash")
            add("invalid", "pkcs1", name, key, digest, rsa_raw(key, b"\x00\x02" + em[2:]),
                what + " block type 2")
            add("invalid", "pss", name, key, digest, pss_sign(key, fn, digest, salt_len=20),
                what + " salt of 20 bytes")
            add("invalid", "pss", name, key, digest, pss_sign(key, fn, digest, salt_len=0),
                what + " no salt")
            add("invalid", "pss", name, key, digest, pss_sign(key, fn, digest, trailer=0xCC),
                what + " trailer not BC")
            if label == "2048":
                add("invalid", "pss", name, key, digest, pss_sign(key, fn, digest, top=True),
                    what + " bits past emBits set")
            else:
                # 2049 bits: EM is a byte shorter than n, and the byte in
                # front of it must be zero
                add("invalid", "pss", name, key, digest, pss_sign(key, fn, digest, lead=1),
                    what + " byte in front of EM")
    # e = 3: signatures still verify, and Bleichenbacher's forgery (garbage
    # after the hash, a cube root) does not
    e3 = rsa_key(2048, 3)
    digest = rand_bytes(32)
    add("valid", "pkcs1", "sha256", e3, digest,
        e3["key"].sign(digest, pypad.PKCS1v15(), asym_utils.Prehashed(hashes.SHA256())), "e3")
    add("valid", "pss", "sha256", e3, digest, pss_sign(e3, hashlib.sha256, digest), "e3")
    prefix = b"\x00\x01\xff\x00" + DIGEST_INFO["sha256"] + digest
    shift = 8 * (e3["k"] - len(prefix))
    forged = icbrt(int.from_bytes(prefix, "big") << shift) + 1
    assert (forged ** 3) >> shift == int.from_bytes(prefix, "big") and forged ** 3 < e3["n"]
    add("invalid", "pkcs1", "sha256", e3, digest, forged.to_bytes(e3["k"], "big"),
        "e3 Bleichenbacher forgery")
    # below 2048 bits nxtls refuses the key; e = 1 would make every encoding
    # its own signature
    small = rsa_key(1024)
    digest = rand_bytes(32)
    add("invalid", "pkcs1", "sha256", small, digest,
        small["key"].sign(digest, pypad.PKCS1v15(), asym_utils.Prehashed(hashes.SHA256())),
        "1024 bits", strict=True)
    add("invalid", "pss", "sha256", small, digest, pss_sign(small, hashlib.sha256, digest),
        "1024 bits", strict=True)
    key = keys[0][1]
    add("invalid", "pkcs1", "sha256", key, digest, pkcs1_encode(key["k"], "sha256", digest),
        "e1", strict=True, e=1)
    # the reference agrees with every expectation that is not marked strict
    halgs = {name: halg for name, _, halg in RSA_HASHES}
    for line in lines:
        if line.startswith("#") or line.endswith("_strict"):
            continue
        f = line.split(" ")
        got = ref_rsa(int(f[3], 16), int(f[4], 16), f[1], halgs[f[2]], bytes.fromhex(f[5]),
                      bytes.fromhex(f[6]))
        assert got == (f[0] == "valid"), "the reference disagrees on " + f[7]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ main

OUTPUTS = {
    "src/tables.nx": tables_nx,
    "tests/vectors/sha2.txt": sha2_vectors,
    "tests/vectors/sha1.txt": sha1_vectors,
    "tests/vectors/hmac.txt": hmac_vectors,
    "tests/vectors/hkdf.txt": hkdf_vectors,
    "tests/vectors/hkdf_label.txt": hkdf_label_vectors,
    "tests/vectors/ed25519.txt": ed25519_vectors,
    "tests/vectors/x25519.txt": x25519_vectors,
    "tests/vectors/chacha20.txt": chacha20_vectors,
    "tests/vectors/poly1305.txt": poly1305_vectors,
    "tests/vectors/chacha20poly1305.txt": aead_vectors,
    "tests/vectors/ecdsa.txt": ecdsa_vectors,
    "tests/vectors/rsa.txt": rsa_vectors,
}


def main():
    check = "--check" in sys.argv
    stale = []
    for rel, make in OUTPUTS.items():
        text = make()
        path = os.path.join(ROOT, rel)
        old = open(path, encoding="utf-8").read() if os.path.exists(path) else None
        if old == text:
            continue
        if check:
            stale.append(rel)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("wrote", rel)
    if stale:
        print("out of date:", ", ".join(stale))
        sys.exit(1)


if __name__ == "__main__":
    main()
