#!/usr/bin/env python3
"""Generate nxtls's constant tables and test vectors.

Test tooling only, never shipped with nxtls. Every constant in
src/tables.nx is derived here from its definition (roots of primes for
SHA-2, the curve equation for Ed25519), and every vector under
tests/vectors/ comes from Python's hashlib and hmac and from the
`cryptography` package, which serve as the reference implementations
the Nexium code has to agree with. Published values from the standards
(FIPS 180-4, FIPS 186-5, RFC 4231, RFC 5869, RFC 6455, RFC 7748, RFC 8017,
RFC 8032, RFC 8439, RFC 8448) are asserted along the way, and the chains in
the X.509 vectors are judged by the reference's own path validation, so a mistake here cannot quietly become
a "correct" answer. RFC 8439's vectors are in tools/rfc8439.py, extracted
from the RFC's text rather than typed in.

    python tools/gen.py           rewrite src/tables.nx and tests/vectors/
    python tools/gen.py --check   exit 1 when the files on disk differ
"""

import base64
import datetime
import hashlib
import hmac as pyhmac
import ipaddress
import os
import random
import sys
import warnings

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
from cryptography import x509 as pyx509
from cryptography.x509 import verification as xv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from rfc8439 import RFC8439, RFC8439_COUNTERS  # noqa: E402
from rfc8448 import RFC8448  # noqa: E402
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


# ------------------------------------------------------------------ X.509

UTC = datetime.timezone.utc


def der_tlv(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(lb)]) + lb
    return bytes([tag]) + head + body


def der_seq(*items):
    return der_tlv(0x30, b"".join(items))


def der_set(*items):
    return der_tlv(0x31, b"".join(items))


def der_oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for v in parts[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        body += bytes(reversed(chunk))
    return der_tlv(0x06, body)


def der_uint(v):
    return der_tlv(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big"))


def der_bits(b, unused=0):
    return der_tlv(0x03, bytes([unused]) + b)


def der_time(dt):
    if 1950 <= dt.year < 2050:
        return der_tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())
    return der_tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode())


def der_name(cn, org="nxtls tests"):
    return der_seq(der_set(der_seq(der_oid("2.5.4.6"), der_tlv(0x13, b"US"))),
                   der_set(der_seq(der_oid("2.5.4.10"), der_tlv(0x0C, org.encode()))),
                   der_set(der_seq(der_oid("2.5.4.3"), der_tlv(0x0C, cn.encode()))))


def der_ext(dotted, value, critical=False):
    flag = [der_tlv(0x01, b"\xff")] if critical else []
    return der_seq(der_oid(dotted), *flag, der_tlv(0x04, value))


KU_SIGN, KU_ENCIPHER, KU_CERT_SIGN, KU_CRL_SIGN = 0, 2, 5, 6
SERVER_AUTH, CLIENT_AUTH = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"


def ku_bits(*bits):
    """KeyUsage as DER has it: bit 0 the first byte's top bit, no trailing
    zero bits."""
    top = max(bits)
    b = bytearray(top // 8 + 1)
    for i in bits:
        b[i // 8] |= 0x80 >> (i % 8)
    return der_bits(bytes(b), 8 * len(b) - (top + 1))


def test_key(kind, bits=2048):
    if kind == "rsa":
        k = rsa_key(bits)
        k["kind"] = "rsa"
        k["point"] = der_seq(der_uint(k["n"]), der_uint(k["e"]))
        k["spki"] = der_seq(der_seq(der_oid("1.2.840.113549.1.1.1"), der_tlv(0x05, b"")), der_bits(k["point"]))
        return k
    _, curve, c, size = EC_CURVES[0] if kind == "p256" else EC_CURVES[1]
    d = int.from_bytes(rand_bytes(size + 8), "big") % (c["n"] - 1) + 1
    point = ec.derive_private_key(d, curve).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    curve_oid = "1.2.840.10045.3.1.7" if kind == "p256" else "1.3.132.0.34"
    return {"kind": kind, "d": d, "curve": curve, "c": c, "size": size, "point": point,
            "spki": der_seq(der_seq(der_oid("1.2.840.10045.2.1"), der_oid(curve_oid)), der_bits(point))}


SIG_ALGS = {
    "rsa-sha256": ("1.2.840.113549.1.1.11", "sha256"),
    "rsa-sha384": ("1.2.840.113549.1.1.12", "sha384"),
    "rsa-sha512": ("1.2.840.113549.1.1.13", "sha512"),
    "rsa-sha1": ("1.2.840.113549.1.1.5", "sha1"),
    "ecdsa-sha256": ("1.2.840.10045.4.3.2", "sha256"),
    "ecdsa-sha384": ("1.2.840.10045.4.3.3", "sha384"),
    "ecdsa-sha512": ("1.2.840.10045.4.3.4", "sha512"),
}


def alg_der(alg):
    dotted, _ = SIG_ALGS[alg]
    if alg.startswith("rsa"):
        return der_seq(der_oid(dotted), der_tlv(0x05, b""))
    return der_seq(der_oid(dotted))


def sign_with(key, alg, message):
    """Signatures that do not change from run to run: PKCS #1 v1.5 is
    deterministic, and ECDSA's k comes from the seeded RNG."""
    hname = SIG_ALGS[alg][1]
    digest = hashlib.new(hname, message).digest()
    if key["kind"] == "rsa":
        if hname == "sha1":
            return rsa_raw(key, pkcs1_encode(key["k"], None, digest, bytes.fromhex("3021300906052b0e03021a05000414")))
        return rsa_raw(key, pkcs1_encode(key["k"], hname, digest))
    k = int.from_bytes(rand_bytes(key["size"] + 8), "big") % (key["c"]["n"] - 1) + 1
    r, sv = ec_sign(key["curve"], key["c"], key["size"], key["d"], digest, k)
    return der_sig(r, sv)


def ski_of(key):
    return hashlib.sha1(key["point"]).digest()


def profile(kind, key, issuer_key, names=(), pathlen=0, **over):
    """The extensions of a root, a CA or a server's certificate as the web
    has them; `over` replaces one by its name here, None leaves it out, and
    new names are added at the end."""
    e = {}
    if kind == "root":
        e["basic"] = der_ext("2.5.29.19", der_seq(der_tlv(0x01, b"\xff")), True)
        e["ku"] = der_ext("2.5.29.15", ku_bits(KU_CERT_SIGN, KU_CRL_SIGN), True)
        e["ski"] = der_ext("2.5.29.14", der_tlv(0x04, ski_of(key)))
    elif kind == "ca":
        body = der_tlv(0x01, b"\xff") + (b"" if pathlen is None else der_uint(pathlen))
        e["basic"] = der_ext("2.5.29.19", der_tlv(0x30, body), True)
        e["ku"] = der_ext("2.5.29.15", ku_bits(KU_SIGN, KU_CERT_SIGN, KU_CRL_SIGN), True)
        e["eku"] = der_ext("2.5.29.37", der_seq(der_oid(SERVER_AUTH), der_oid(CLIENT_AUTH)))
        e["ski"] = der_ext("2.5.29.14", der_tlv(0x04, ski_of(key)))
        e["aki"] = der_ext("2.5.29.35", der_seq(der_tlv(0x80, ski_of(issuer_key))))
    else:
        e["ku"] = der_ext("2.5.29.15", ku_bits(KU_SIGN), True)
        e["eku"] = der_ext("2.5.29.37", der_seq(der_oid(SERVER_AUTH)))
        e["basic"] = der_ext("2.5.29.19", der_seq(), True)
        e["ski"] = der_ext("2.5.29.14", der_tlv(0x04, ski_of(key)))
        e["aki"] = der_ext("2.5.29.35", der_seq(der_tlv(0x80, ski_of(issuer_key))))
        e["san"] = der_ext("2.5.29.17", der_seq(*[der_tlv(0x82, n.encode()) for n in names]))
    for name, value in over.items():
        if value is None:
            e.pop(name, None)
        else:
            e[name] = value
    return list(e.values())


def make_cert(subject, key, issuer, issuer_key, exts, nb, na, alg=None, version=3, inner_alg=None,
              times=None, tamper=False, serial=None, sig_unused=0):
    alg = alg or {"rsa": "rsa-sha256", "p256": "ecdsa-sha256", "p384": "ecdsa-sha384"}[issuer_key["kind"]]
    if serial is None:
        serial = int.from_bytes(rand_bytes(16), "big") >> 1
    items = [der_tlv(0xA0, der_uint(version - 1))] if version > 1 else []
    validity = der_seq(*times) if times else der_seq(der_time(nb), der_time(na))
    items += [der_uint(serial), alg_der(inner_alg or alg), der_name(issuer), validity, der_name(subject), key["spki"]]
    if exts:
        items.append(der_tlv(0xA3, der_seq(*exts)))
    tbs = der_seq(*items)
    sig = sign_with(issuer_key, alg, tbs)
    if tamper:
        sig = sig[:-1] + bytes([sig[-1] ^ 1])
    return der_seq(tbs, alg_der(alg), der_bits(sig, sig_unused))


def ms_of(dt):
    return int(dt.timestamp()) * 1000


def load_cert(der):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return pyx509.load_der_x509_certificate(der)


def ref_well_formed(der):
    """Whether the reference reads the certificate whole, extensions and key
    included (it reads extensions only when asked)."""
    try:
        c = load_cert(der)
        c.extensions
        c.public_key()
        c.not_valid_before_utc
        c.not_valid_after_utc
        c.subject
        c.issuer
        return True
    except Exception:
        return False


def ref_info(der):
    c = load_cert(der)
    key = c.public_key()
    if isinstance(key, pyrsa.RSAPublicKey):
        kind = "rsa"
    elif isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name in ("secp256r1", "secp384r1"):
        kind = "p256" if key.curve.name == "secp256r1" else "p384"
    else:
        kind = "other"
    names = {d: n for n, (d, _) in SIG_ALGS.items() if n != "rsa-sha1"}
    alg = names.get(c.signature_algorithm_oid.dotted_string, "other")
    ca, path_len, usage, server, dns = "-", -1, -1, "-", []
    for e in c.extensions:
        v = e.value
        if isinstance(v, pyx509.BasicConstraints):
            ca = "1" if v.ca else "0"
            path_len = -1 if v.path_length is None else v.path_length
        elif isinstance(v, pyx509.KeyUsage):
            flags = [v.digital_signature, v.content_commitment, v.key_encipherment, v.data_encipherment,
                     v.key_agreement, v.key_cert_sign, v.crl_sign]
            if v.key_agreement:
                flags += [v.encipher_only, v.decipher_only]
            usage = sum(1 << i for i, f in enumerate(flags) if f)
        elif isinstance(v, pyx509.ExtendedKeyUsage):
            ok = any(o.dotted_string in (SERVER_AUTH, "2.5.29.37.0") for o in v)
            server = "1" if ok else "0"
        elif isinstance(v, pyx509.SubjectAlternativeName):
            dns = v.get_values_for_type(pyx509.DNSName)
    version = 3 if c.version == pyx509.Version.v3 else 1
    return "%d %d %d %s %s %s %d %d %s %s" % (
        version, ms_of(c.not_valid_before_utc), ms_of(c.not_valid_after_utc), kind, alg, ca, path_len, usage,
        server, ",".join(dns) if dns else "-")


def ref_chain(certs, roots, chain, host, now):
    """The reference's verdict: its path validation for a server (the CA/B
    Forum's profile), with what it cannot read left out as nxtls leaves it."""
    try:
        store = xv.Store([load_cert(certs[r]) for r in roots])
        leaf = load_cert(certs[chain[0]])
    except Exception:
        return False
    extra = []
    for n in chain[1:]:
        try:
            extra.append(load_cert(certs[n]))
        except Exception:
            pass
    try:
        try:
            subject = xv.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            subject = xv.DNSName(host)
        verifier = xv.PolicyBuilder().store(store).time(now).build_server_verifier(subject)
        verifier.verify(leaf, extra)
        return True
    except Exception:
        return False


def x509_vectors():
    certs = {}
    cert_lines, info_lines, bad_lines, chain_lines = [], [], [], []

    def cert(name, der):
        certs[name] = der
        cert_lines.append("cert %s %s" % (name, der.hex()))

    def info(name):
        info_lines.append("info %s %s" % (name, ref_info(certs[name])))

    def malformed(what, der, strict=False):
        what = what.replace(" ", "_") + ("_strict" if strict else "")
        bad_lines.append("malformed %s %s" % (what, der.hex()))

    def case(expect, host, now, roots, chain, what, mark=""):
        what = what.replace(" ", "_") + ("_" + mark if mark else "")
        chain_lines.append("chain %s %s %d %s %s %s" % (
            expect, host, ms_of(now), ",".join(roots) or "-", ",".join(chain) or "-", what))

    y = lambda year, month=1, day=1: datetime.datetime(year, month, day, tzinfo=UTC)  # noqa: E731
    now = y(2026, 6)
    root_t, ca_t, leaf_t = (y(2020), y(2040)), (y(2025), y(2030)), (y(2026, 3), y(2026, 9))

    k_root, k_root_rsa, k_new = test_key("p384"), test_key("rsa"), test_key("p256")
    k_int, k_int_rsa, k_int2 = test_key("p256"), test_key("rsa"), test_key("p256")
    k_leaf, k_leaf384, k_leaf_rsa = test_key("p256"), test_key("p384"), test_key("rsa")
    k_other, k_small = test_key("p256"), test_key("rsa", 1024)
    names = ["example.com", "*.example.com"]

    def root_cert(cn, key, t=root_t, **over):
        return make_cert(cn, key, cn, key, profile("root", key, key, **over), *t)

    def ca_cert(cn, key, issuer, issuer_key, t=ca_t, pathlen=0, **kw):
        over = {k: v for k, v in kw.items() if k not in ("alg", "version", "serial")}
        rest = {k: v for k, v in kw.items() if k in ("alg", "version", "serial")}
        return make_cert(cn, key, issuer, issuer_key, profile("ca", key, issuer_key, pathlen=pathlen, **over), *t, **rest)

    make_args = ("alg", "version", "tamper", "inner_alg", "times", "sig_unused", "serial")

    def leaf_cert(key, issuer, issuer_key, sans=names, t=leaf_t, cn="example.com", **kw):
        over = {k: v for k, v in kw.items() if k not in make_args}
        rest = {k: v for k, v in kw.items() if k in make_args}
        return make_cert(cn, key, issuer, issuer_key, profile("leaf", key, issuer_key, sans, **over), *t, **rest)

    cert("root", root_cert("Test Root EC", k_root))
    cert("root-rsa", root_cert("Test Root RSA", k_root_rsa))
    cert("root-old", root_cert("Test Root EC", k_root, t=(y(2010), y(2026))))
    cert("int", ca_cert("Test CA EC", k_int, "Test Root EC", k_root))
    cert("int-rsa", ca_cert("Test CA RSA", k_int_rsa, "Test Root RSA", k_root_rsa))
    cert("leaf", leaf_cert(k_leaf, "Test CA EC", k_int))
    for n in ["root", "root-rsa", "int", "int-rsa", "leaf"]:
        info(n)
    basic = ["leaf", "int"]
    case("valid", "www.example.com", now, ["root"], basic, "EC chain")
    case("valid", "example.com", now, ["root"], basic, "the bare name")
    case("invalid", "a.b.example.com", now, ["root"], basic, "a wildcard over two labels")
    case("invalid", "example.org", now, ["root"], basic, "another host")
    case("invalid", "www.example.com", now, [], basic, "no roots")
    case("invalid", "www.example.com", now, ["root"], ["leaf"], "the CA certificate not sent")
    case("invalid", "www.example.com", now, ["root-rsa"], basic, "another root")
    case("valid", "www.example.com", now, ["root"], ["leaf", "root-rsa", "int"], "out of order among others")
    case("valid", "www.example.com", now, ["root"], ["leaf", "int", "root"], "the root sent too")
    case("valid", "www.example.com", now, ["int"], ["leaf"], "a CA certificate as the trust anchor")
    case("invalid", "www.example.com", y(2026, 2), ["root"], basic, "before the server's certificate")
    case("invalid", "www.example.com", y(2026, 10), ["root"], basic, "after the server's certificate")
    case("invalid", "www.example.com", now, ["root-old"], basic, "an expired root")
    case("valid", "www.example.com", now, ["root-old", "root"], basic, "an expired root and its successor")

    cert("int-old", ca_cert("Test CA EC", k_int, "Test Root EC", k_root, t=(y(2024), y(2026))))
    case("invalid", "www.example.com", now, ["root"], ["leaf", "int-old"], "an expired CA")
    cert("int-later", ca_cert("Test CA EC", k_int, "Test Root EC", k_root, t=(y(2026, 7), y(2030))))
    case("invalid", "www.example.com", now, ["root"], ["leaf", "int-later"], "a CA not valid yet")

    # algorithms
    cert("leaf-under-rsa", leaf_cert(k_leaf, "Test CA RSA", k_int_rsa))
    case("valid", "example.com", now, ["root-rsa"], ["leaf-under-rsa", "int-rsa"], "RSA root and CA")
    cert("leaf-rsa", leaf_cert(k_leaf_rsa, "Test CA EC", k_int))
    info("leaf-rsa")
    case("valid", "example.com", now, ["root"], ["leaf-rsa", "int"], "an RSA server key")
    cert("leaf-p384", leaf_cert(k_leaf384, "Test CA EC", k_int, alg="ecdsa-sha384"))
    info("leaf-p384")
    case("valid", "example.com", now, ["root"], ["leaf-p384", "int"], "a P-384 key, SHA-384 by a P-256 CA")
    cert("leaf-sha512", leaf_cert(k_leaf, "Test CA EC", k_int, alg="ecdsa-sha512"))
    case("valid", "example.com", now, ["root"], ["leaf-sha512", "int"], "ECDSA with SHA-512")
    for alg in ["rsa-sha384", "rsa-sha512"]:
        cert("leaf-" + alg, leaf_cert(k_leaf, "Test CA RSA", k_int_rsa, alg=alg))
        info("leaf-" + alg)
        case("valid", "example.com", now, ["root-rsa"], ["leaf-" + alg, "int-rsa"], alg)
    cert("leaf-rsa-sha1", leaf_cert(k_leaf, "Test CA RSA", k_int_rsa, alg="rsa-sha1"))
    case("invalid", "example.com", now, ["root-rsa"], ["leaf-rsa-sha1", "int-rsa"], "SHA-1")
    cert("int-small", ca_cert("Test CA Small", k_small, "Test Root RSA", k_root_rsa))
    cert("leaf-small", leaf_cert(k_leaf, "Test CA Small", k_small))
    case("invalid", "example.com", now, ["root-rsa"], ["leaf-small", "int-small"], "a CA with a 1024-bit key")

    # what makes a CA a CA
    bad_cas = [
        ("int-nobasic", {"basic": None}, "a CA without basicConstraints"),
        ("int-notca", {"basic": der_ext("2.5.29.19", der_seq(), True)}, "a CA with cA false"),
        ("int-ku", {"ku": der_ext("2.5.29.15", ku_bits(KU_SIGN), True)}, "a CA without keyCertSign"),
        ("int-client", {"eku": der_ext("2.5.29.37", der_seq(der_oid(CLIENT_AUTH)))}, "a CA for clients only"),
        ("int-critical", {"odd": der_ext("1.3.6.1.4.1.55555.1", der_tlv(0x05, b""), True)},
         "a CA with an unknown critical extension"),
    ]
    for name, over, what in bad_cas:
        cert(name, ca_cert("Test CA EC", k_int, "Test Root EC", k_root, **over))
        case("invalid", "example.com", now, ["root"], ["leaf", name], what)
    cert("int-noeku", ca_cert("Test CA EC", k_int, "Test Root EC", k_root, eku=None))
    case("valid", "example.com", now, ["root"], ["leaf", "int-noeku"], "a CA without extendedKeyUsage")
    cert("int-odd", ca_cert("Test CA EC", k_int, "Test Root EC", k_root,
                            odd=der_ext("1.3.6.1.4.1.55555.1", der_tlv(0x05, b""))))
    case("valid", "example.com", now, ["root"], ["leaf", "int-odd"], "a CA with an unknown extension, not critical")
    permitted = der_seq(der_tlv(0xA0, der_seq(der_tlv(0x82, b"example.com"))))
    cert("int-nc", ca_cert("Test CA EC", k_int, "Test Root EC", k_root, nc=der_ext("2.5.29.30", permitted, True)))
    case("invalid", "example.com", now, ["root"], ["leaf", "int-nc"], "a CA with name constraints", "strict")
    cert("int-v1", make_cert("Test CA EC", k_int, "Test Root EC", k_root, [], *ca_t, version=1))
    info("int-v1")
    case("invalid", "example.com", now, ["root"], ["leaf", "int-v1"], "a version 1 CA")

    # path length
    cert("int-top", ca_cert("Test CA Top", k_int2, "Test Root EC", k_root, pathlen=None))
    cert("int-top0", ca_cert("Test CA Top", k_int2, "Test Root EC", k_root, pathlen=0))
    cert("int-mid", ca_cert("Test CA EC", k_int, "Test CA Top", k_int2))
    info("int-top")
    case("valid", "example.com", now, ["root"], ["leaf", "int-mid", "int-top"], "two CAs")
    case("invalid", "example.com", now, ["root"], ["leaf", "int-mid", "int-top0"], "two CAs under path length 0")

    # the server's certificate
    # (TLS 1.3 signs with the server's key, so RFC 8446 4.4.2.2 wants
    # digitalSignature; the CA/B Forum wants serverAuth in every server
    # certificate)
    bad_leaves = [
        ("leaf-ca", {"basic": der_ext("2.5.29.19", der_seq(der_tlv(0x01, b"\xff")), True)}, "a CA's certificate", ""),
        ("leaf-ku", {"ku": der_ext("2.5.29.15", ku_bits(KU_ENCIPHER), True)}, "keyUsage without digitalSignature",
         "strict"),
        ("leaf-client", {"eku": der_ext("2.5.29.37", der_seq(der_oid(CLIENT_AUTH)))}, "for clients only", ""),
        ("leaf-nosan", {"san": None}, "no subjectAltName", ""),
        ("leaf-critical", {"odd": der_ext("1.3.6.1.4.1.55555.1", der_tlv(0x05, b""), True)},
         "an unknown critical extension", ""),
    ]
    for name, over, what, mark in bad_leaves:
        cert(name, leaf_cert(k_leaf, "Test CA EC", k_int, **over))
        case("invalid", "example.com", now, ["root"], [name, "int"], what, mark)
    cert("leaf-noeku", leaf_cert(k_leaf, "Test CA EC", k_int, eku=None))
    case("invalid", "example.com", now, ["root"], ["leaf-noeku", "int"], "no extendedKeyUsage", "strict")
    cert("leaf-noku", leaf_cert(k_leaf, "Test CA EC", k_int, ku=None))
    case("valid", "example.com", now, ["root"], ["leaf-noku", "int"], "no keyUsage")
    cert("leaf-odd", leaf_cert(k_leaf, "Test CA EC", k_int, odd=der_ext("1.3.6.1.4.1.55555.1", der_tlv(0x05, b""))))
    case("valid", "example.com", now, ["root"], ["leaf-odd", "int"], "an unknown extension, not critical")
    cert("leaf-badsig", leaf_cert(k_leaf, "Test CA EC", k_int, tamper=True))
    case("invalid", "example.com", now, ["root"], ["leaf-badsig", "int"], "a bad signature")
    cert("leaf-wrongkey", leaf_cert(k_leaf, "Test CA EC", k_other))
    case("invalid", "example.com", now, ["root"], ["leaf-wrongkey", "int"], "signed by another key")
    sans = ["WWW.Mixed.Example", "*.wild.example.com", "w*.part.example.com", "exact.example.net"]
    cert("leaf-names", leaf_cert(k_leaf, "Test CA EC", k_int, sans=sans))
    info("leaf-names")
    for host, expect, what in [
            ("www.mixed.example", "valid", "a name in capitals"),
            ("a.wild.example.com", "valid", "a wildcard"),
            ("wild.example.com", "invalid", "a wildcard's own domain"),
            ("wpart.part.example.com", "invalid", "a partial wildcard"),
            ("exact.example.net", "valid", "the last name")]:
        case(expect, host, now, ["root"], ["leaf-names", "int"], what)
    cert("leaf-tld", leaf_cert(k_leaf, "Test CA EC", k_int, sans=["*.com"]))
    case("invalid", "example.com", now, ["root"], ["leaf-tld", "int"], "a wildcard over a top-level domain", "strict")

    # a new root cross-signed by an old one, as ISRG's Root YR and Google's GTS Root R4 are
    cert("root-new", root_cert("Test Root New", k_new))
    cert("cross", ca_cert("Test Root New", k_new, "Test Root RSA", k_root_rsa, pathlen=None))
    cert("cross-old", ca_cert("Test Root New", k_new, "Test Root RSA", k_root_rsa, pathlen=None, t=(y(2020), y(2026))))
    cert("int-new", ca_cert("Test CA New", k_int2, "Test Root New", k_new))
    cert("leaf-new", leaf_cert(k_leaf, "Test CA New", k_int2))
    cross = ["leaf-new", "int-new", "cross"]
    case("valid", "example.com", now, ["root-rsa"], cross, "cross-signed, the old root trusted")
    case("valid", "example.com", now, ["root-new"], cross, "cross-signed, the new root trusted")
    case("valid", "example.com", now, ["root-rsa", "root-new"], cross, "cross-signed, both trusted")
    case("invalid", "example.com", now, ["root"], cross, "cross-signed, neither trusted")
    case("valid", "example.com", now, ["root-new"], ["leaf-new", "int-new", "cross-old"],
         "an expired cross-sign past a trusted root")
    case("invalid", "example.com", now, ["root-rsa"], ["leaf-new", "int-new", "cross-old"],
         "only an expired cross-sign")

    # two CAs that sign each other, and no root: the search must end
    cert("loop-x", ca_cert("Loop X", k_int, "Loop Y", k_int2, pathlen=None))
    cert("loop-y", ca_cert("Loop Y", k_int2, "Loop X", k_int, pathlen=None))
    cert("leaf-loop", leaf_cert(k_leaf, "Loop X", k_int))
    case("invalid", "example.com", now, ["root"], ["leaf-loop", "loop-x", "loop-y"], "a loop")

    # malformed certificates
    good = certs["leaf"]
    malformed("truncated", good[:-1])
    malformed("a trailing byte", good + b"\x00")
    assert good[1] == 0x82
    malformed("a length not in its shortest form", b"\x30\x83\x00" + good[2:])
    for what, nb in [("month 13", b"261301000000Z"), ("February 30", b"260230000000Z"),
                     ("no Z", b"2603010000000"), ("hour 24", b"260301240000Z")]:
        malformed(what, leaf_cert(k_leaf, "Test CA EC", k_int, times=(der_tlv(0x17, nb), der_time(leaf_t[1]))))
    malformed("version 4", leaf_cert(k_leaf, "Test CA EC", k_int, version=4))
    malformed("an inner algorithm unlike the outer", leaf_cert(k_leaf, "Test CA EC", k_int, inner_alg="ecdsa-sha384"),
              strict=True)
    malformed("an extension twice", leaf_cert(k_leaf, "Test CA EC", k_int,
                                               san2=der_ext("2.5.29.17", der_seq(der_tlv(0x82, b"x.example.com")))))
    malformed("a signature not whole bytes", leaf_cert(k_leaf, "Test CA EC", k_int, sig_unused=1), strict=True)
    malformed("an empty subjectAltName", leaf_cert(k_leaf, "Test CA EC", k_int, sans=[]), strict=True)
    malformed("extensions in version 1", make_cert("example.com", k_leaf, "Test CA EC", k_int,
                                                   profile("leaf", k_leaf, k_int, names), *leaf_t, version=1),
              strict=True)

    # the captured chains, as of the day they were captured
    real = datetime.datetime(2026, 9, 24, 8, tzinfo=UTC)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for host in ["discord.com", "gateway.discord.gg", "callook.info"]:
            text = open(os.path.join(ROOT, "tests", "certs", host + ".pem"), "rb").read()
            for i, c in enumerate(pyx509.load_pem_x509_certificates(text)):
                cert("%s/%d" % (host, i), c.public_bytes(serialization.Encoding.DER))
                info("%s/%d" % (host, i))
        text = open(os.path.join(ROOT, "tests", "certs", "roots.pem"), "rb").read()
        root_names = ["gts-r4", "isrg-x1", "isrg-x2", "godaddy-g2", "p521", "sha1"]
        for name, c in zip(root_names, pyx509.load_pem_x509_certificates(text)):
            cert("roots/" + name, c.public_bytes(serialization.Encoding.DER))
            info("roots/" + name)
    every = ["roots/" + n for n in root_names]
    d3 = ["discord.com/0", "discord.com/1", "discord.com/2"]
    g3 = ["gateway.discord.gg/0", "gateway.discord.gg/1", "gateway.discord.gg/2"]
    c3 = ["callook.info/0", "callook.info/1", "callook.info/2"]
    case("valid", "discord.com", real, ["roots/gts-r4"], d3, "discord.com")
    case("valid", "www.discord.com", real, every, d3, "discord.com's wildcard")
    case("invalid", "discord.gg", real, every, d3, "discord.com's chain for discord.gg")
    case("invalid", "discord.com", datetime.datetime(2026, 12, 1, tzinfo=UTC), every, d3, "discord.com after it expires")
    case("valid", "gateway.discord.gg", real, every, g3, "the Gateway")
    case("valid", "discord.gg", real, ["roots/gts-r4"], g3, "discord.gg")
    case("valid", "callook.info", real, ["roots/isrg-x1"], c3, "callook.info through the cross-signed Root YR")
    case("valid", "www.callook.info", real, every, c3, "www.callook.info")
    case("invalid", "callook.info", real, ["roots/gts-r4"], c3, "callook.info under another root")
    case("invalid", "callook.info", real, every, c3[:2], "callook.info without the cross-sign")

    # (from here on, certificates are signed with RSA, which is
    # deterministic, and given their serial numbers, so they take nothing
    # from RNG and the vectors made after them stay as they were)

    # addresses: a host that is an IPv4 or IPv6 address matches only a
    # certificate's IP addresses, byte for byte, and a name only its DNS
    # names
    def alt(*items):
        return der_ext("2.5.29.17", der_seq(*items))

    v4, v6 = ipaddress.ip_address("192.0.2.7").packed, ipaddress.ip_address("2001:db8::1").packed
    cert("leaf-ip", leaf_cert(k_leaf, "Test CA RSA", k_int_rsa, serial=101,
                              san=alt(der_tlv(0x82, b"example.com"), der_tlv(0x87, v4), der_tlv(0x87, v6))))
    for host, expect, what in [
            ("192.0.2.7", "valid", "an IPv4 address"),
            ("2001:db8::1", "valid", "an IPv6 address"),
            ("2001:0DB8:0:0:0:0:0:1", "valid", "an IPv6 address spelled out"),
            ("192.0.2.8", "invalid", "another IPv4 address"),
            ("2001:db8::2", "invalid", "another IPv6 address"),
            ("::ffff:192.0.2.7", "invalid", "the IPv4 address mapped into IPv6"),
            ("example.com", "valid", "the DNS name beside the addresses")]:
        case(expect, host, now, ["root-rsa"], ["leaf-ip", "int-rsa"], what)
    cert("leaf-ip-as-name", leaf_cert(k_leaf, "Test CA RSA", k_int_rsa, serial=102, sans=["192.0.2.7"]))
    case("invalid", "192.0.2.7", now, ["root-rsa"], ["leaf-ip-as-name", "int-rsa"], "an address as a DNS name")
    cert("leaf-ip-only", leaf_cert(k_leaf, "Test CA RSA", k_int_rsa, serial=103, san=alt(der_tlv(0x87, v4))))
    case("invalid", "example.com", now, ["root-rsa"], ["leaf-ip-only", "int-rsa"], "a name, and only an address")
    malformed("an IP address of 5 bytes",
              leaf_cert(k_leaf, "Test CA RSA", k_int_rsa, serial=104, san=alt(der_tlv(0x87, v4 + b"\x00"))))

    # certificates built to be tried in every order, which the search must
    # get through quickly: seven CAs with one name and key, each able to
    # issue the others, alone and with the way out a root issued (a CA of
    # that name allowing no CA below it, so no long path gets there
    # first); and six levels of three CAs, each level's three alike but
    # for the serial number and each able to issue all three below it,
    # with nothing a root issued at the top (3 + 9 + ... + 729 signatures
    # to try every path)
    ring = ["ring-%d" % j for j in range(7)]
    for j, name in enumerate(ring):
        cert(name, ca_cert("Ring", k_int_rsa, "Ring", k_int_rsa, pathlen=None, serial=200 + j))
    cert("ring-out", ca_cert("Ring", k_int_rsa, "Test Root RSA", k_root_rsa, serial=207))
    cert("leaf-ring", leaf_cert(k_leaf, "Ring", k_int_rsa, serial=105))
    case("invalid", "example.com", now, ["root-rsa"], ["leaf-ring"] + ring, "seven CAs with one name and key")
    # (the reference, which tries a CA again under another of its name and
    # key, spends its own limit of signature checks going round the ring
    # and refuses this; nxtls, as Go, takes the way out)
    case("valid", "example.com", now, ["root-rsa"], ["leaf-ring"] + ring + ["ring-out"],
         "seven CAs with one name and key, and the way out", "lenient")
    keys = [k_int_rsa, k_root_rsa]
    maze = []
    for level in range(1, 7):
        for j in range(3):
            maze.append("maze-%d%s" % (level, "abc"[j]))
            cert(maze[-1], ca_cert("Maze %d" % level, keys[level % 2], "Maze %d" % (level + 1), keys[(level + 1) % 2],
                                   pathlen=None, serial=300 + 10 * level + j))
    cert("leaf-maze", leaf_cert(k_leaf, "Maze 1", keys[1], serial=106))
    case("invalid", "example.com", now, ["root-rsa"], ["leaf-maze"] + maze, "a maze of CAs that ends nowhere")

    # the reference agrees wherever the vectors do not say otherwise
    wrong = []
    for line in bad_lines:
        f = line.split(" ")
        if not f[1].endswith("_strict") and ref_well_formed(bytes.fromhex(f[2])):
            wrong.append("the reference reads " + f[1])
    for line in chain_lines:
        f = line.split(" ")
        if f[6].endswith("_strict") or f[6].endswith("_lenient"):
            continue
        at = datetime.datetime.fromtimestamp(int(f[3]) // 1000, UTC)
        roots = [] if f[4] == "-" else f[4].split(",")
        got = ref_chain(certs, roots, f[5].split(","), f[2], at)
        if got != (f[1] == "valid"):
            wrong.append("the reference disagrees on " + f[6])
    assert not wrong, "\n".join(wrong)
    head = ["# cert name der",
            "# info name version not-before not-after key sig-alg ca path-len key-usage server-auth dns-names",
            "#   (as the reference reads them; times in ms since the epoch; ca and server-auth 1, 0, or - for",
            "#   no such extension; -1 for no path length or key usage)",
            "# malformed what der",
            "# chain expect host now roots certs what (the server's certificate first; - for none)",
            "# nxtls refuses what the reference accepts where marked strict, and accepts what it refuses",
            "# where marked lenient"]
    return "\n".join(head + cert_lines + info_lines + bad_lines + chain_lines) + "\n"


# ------------------------------------------------------------------ TLS 1.3

def tls13_rfc8448_vectors():
    """RFC 8448's simple handshake, its values checked here by the
    reference's parts (X25519, hmac, hashlib) before the file is written."""
    v = {k: bytes.fromhex(h) for k, h in RFC8448.items()}
    sha = hashlib.sha256
    assert x25519(v["client_private"], v["server_public"]) == v["shared"]
    assert X25519PrivateKey.from_private_bytes(v["client_private"]).public_key().public_bytes_raw() == v["client_public"]
    empty = sha(b"").digest()
    early = pyhmac.new(b"\x00" * 32, b"\x00" * 32, sha).digest()
    hs = pyhmac.new(expand_label(sha, early, b"derived", empty, 32), v["shared"], sha).digest()
    assert hs == v["handshake_secret"]
    th = sha(v["client_hello"] + v["server_hello"]).digest()
    assert expand_label(sha, hs, b"c hs traffic", th, 32) == v["c_hs"]
    assert expand_label(sha, hs, b"s hs traffic", th, 32) == v["s_hs"]
    master = pyhmac.new(expand_label(sha, hs, b"derived", empty, 32), b"\x00" * 32, sha).digest()
    assert master == v["master"]
    t = v["client_hello"] + v["server_hello"] + v["encrypted_extensions"] + v["certificate"] + v["certificate_verify"]
    fk = expand_label(sha, v["s_hs"], b"finished", b"", 32)
    assert pyhmac.new(fk, sha(t).digest(), sha).digest() == v["server_finished"][4:]
    t += v["server_finished"]
    assert expand_label(sha, master, b"c ap traffic", sha(t).digest(), 32) == v["c_ap"]
    assert expand_label(sha, master, b"s ap traffic", sha(t).digest(), 32) == v["s_ap"]
    fk = expand_label(sha, v["c_hs"], b"finished", b"", 32)
    assert pyhmac.new(fk, sha(t).digest(), sha).digest() == v["client_finished"][4:]
    lines = ["# RFC 8448 section 3, the simple 1-RTT handshake: name hex"]
    lines += ["%s %s" % (k, h) for k, h in RFC8448.items()]
    return "\n".join(lines) + "\n"


TLS_SCHEMES = [0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]
HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()


def u16(v):
    return v.to_bytes(2, "big")


def u24(v):
    return v.to_bytes(3, "big")


def ext_of(kind, data):
    return u16(kind) + u16(len(data)) + data


def hs_msg(kind, body):
    return bytes([kind]) + u24(len(body)) + body


def plain_rec(kind, data, version=0x0303):
    return bytes([kind]) + u16(version) + u16(len(data)) + data


def tls_client_hello(host, random, sid, public, cookie=b""):
    """The ClientHello nxtls sends (RFC 8446 4.1.2), written out here."""
    name = host.encode()
    ext = ext_of(0, u16(len(name) + 3) + b"\x00" + u16(len(name)) + name)
    ext += ext_of(10, u16(2) + u16(0x001D))
    ext += ext_of(13, u16(2 * len(TLS_SCHEMES)) + b"".join(u16(x) for x in TLS_SCHEMES))
    ext += ext_of(43, b"\x02" + u16(0x0304))
    ext += ext_of(51, u16(len(public) + 4) + u16(0x001D) + u16(len(public)) + public)
    if cookie:
        ext += ext_of(44, u16(len(cookie)) + cookie)
    body = u16(0x0303) + random + bytes([len(sid)]) + sid + u16(2) + u16(0x1303) + b"\x01\x00" + u16(len(ext)) + ext
    return hs_msg(1, body)


def tls_keys(secret):
    sha = hashlib.sha256
    return {"secret": secret, "key": expand_label(sha, secret, b"key", b"", 32),
            "iv": expand_label(sha, secret, b"iv", b"", 12), "seq": 0}


def tls_seal(k, kind, data, pad=0):
    """A protected record (RFC 8446 5.2), by the reference's ChaCha20-Poly1305."""
    inner = data + bytes([kind]) + b"\x00" * pad
    header = bytes([23, 3, 3]) + u16(len(inner) + 16)
    nonce = bytes(a ^ b for a, b in zip(k["iv"], k["seq"].to_bytes(12, "big")))
    k["seq"] += 1
    return header + ChaCha20Poly1305(k["key"]).encrypt(nonce, inner, header)


def tls_sign(leaf, scheme, content):
    """CertificateVerify's signature, checked by the reference."""
    if scheme in (0x0403, 0x0503):
        fn, halg = (hashlib.sha256, hashes.SHA256()) if scheme == 0x0403 else (hashlib.sha384, hashes.SHA384())
        digest = fn(content).digest()
        k = int.from_bytes(rand_bytes(leaf["size"] + 8), "big") % (leaf["c"]["n"] - 1) + 1
        sig = der_sig(*ec_sign(leaf["curve"], leaf["c"], leaf["size"], leaf["d"], digest, k))
        assert ref_ecdsa(leaf["curve"], leaf["point"], digest, sig, halg)
        return sig
    if scheme in (0x0804, 0x0805, 0x0806):
        fn, halg = {0x0804: (hashlib.sha256, hashes.SHA256()), 0x0805: (hashlib.sha384, hashes.SHA384()),
                    0x0806: (hashlib.sha512, hashes.SHA512())}[scheme]
        digest = fn(content).digest()
        sig = pss_sign(leaf, fn, digest)
        assert ref_rsa(leaf["n"], leaf["e"], "pss", halg, digest, sig)
        return sig
    assert scheme == 0x0401
    return rsa_raw(leaf, pkcs1_encode(leaf["k"], "sha256", hashlib.sha256(content).digest()))


class TlsScript:
    """One exchange for tests/vectors/tls13.txt: the server's side played
    here from the reference's parts (X25519 and ChaCha20-Poly1305 from
    cryptography, HKDF and HMAC from hashlib and hmac), and the client's
    side worked out alongside it, so that every byte nxtls must send is
    known."""

    def __init__(self, out, name, host, now, roots, chain, leaf):
        self.out = out
        self.random, self.sid, self.key = rand_bytes(32), rand_bytes(32), rand_bytes(32)
        self.public = X25519PrivateKey.from_private_bytes(self.key).public_key().public_bytes_raw()
        self.server_key = rand_bytes(32)
        self.server_public = X25519PrivateKey.from_private_bytes(self.server_key).public_key().public_bytes_raw()
        self.host, self.chain, self.leaf = host, chain, leaf
        out.append("exchange " + name)
        out.append("client %s %s %s %s" % (host, self.random.hex(), self.sid.hex(), self.key.hex()))
        out.append("now %d" % ms_of(now))
        for r in roots:
            out.append("root " + r.hex())
        self.ch = tls_client_hello(host, self.random, self.sid, self.public)
        self.transcript = self.ch
        self.cw = None
        self.sr = None
        self.ccs_sent = False
        self.expect(plain_rec(22, self.ch, 0x0301))

    def line(self, *words):
        self.out.append(" ".join(str(w) for w in words))

    def expect(self, data):
        self.line("expect", hx(data))

    def feed(self, data, chunk=0):
        self.line("feed", chunk, hx(data))

    def end(self):
        self.line("end")

    def alert(self, desc):
        """The alert the client sends when it fails: protected once it has keys."""
        body = bytes([2, desc])
        return plain_rec(21, body) if self.cw is None else tls_seal(self.cw, 21, body)

    def hello(self, suite=0x1303, version=0x0304, sid=None, share=None, extra=b"", retry=False,
              group=0x001D, cookie=b"", legacy=0x0303):
        """A ServerHello (or HelloRetryRequest) message."""
        ext = b""
        if retry:
            if group:
                ext += ext_of(51, u16(group))
            if cookie:
                ext += ext_of(44, u16(len(cookie)) + cookie)
        else:
            key = self.server_public if share is None else share
            ext += ext_of(51, u16(group) + u16(len(key)) + key)
        if version:
            ext += ext_of(43, u16(version))
        ext += extra
        sid = self.sid if sid is None else sid
        random = HRR_RANDOM if retry else rand_bytes(32)
        body = u16(legacy) + random + bytes([len(sid)]) + sid + u16(suite) + b"\x00" + u16(len(ext)) + ext
        return hs_msg(2, body)

    def keys(self, sh):
        """After the ServerHello: the handshake secrets, as both sides make them."""
        sha = hashlib.sha256
        self.transcript += sh
        shared = x25519(self.key, self.server_public)
        assert shared == x25519(self.server_key, self.public)
        empty = sha(b"").digest()
        early = pyhmac.new(b"\x00" * 32, b"\x00" * 32, sha).digest()
        hs = pyhmac.new(expand_label(sha, early, b"derived", empty, 32), shared, sha).digest()
        th = sha(self.transcript).digest()
        self.c_hs = expand_label(sha, hs, b"c hs traffic", th, 32)
        self.s_hs = expand_label(sha, hs, b"s hs traffic", th, 32)
        self.master = pyhmac.new(expand_label(sha, hs, b"derived", empty, 32), b"\x00" * 32, sha).digest()
        self.sr = tls_keys(self.s_hs)
        self.cw = tls_keys(self.c_hs)

    def retry(self, hrr):
        """The client's answer to a HelloRetryRequest: a change_cipher_spec
        and the ClientHello again with the cookie."""
        cookie = b""
        body = hrr[4:]
        at = 2 + 32 + 1 + body[34] + 2 + 1 + 2
        while at < len(body):
            kind, n = int.from_bytes(body[at:at + 2], "big"), int.from_bytes(body[at + 2:at + 4], "big")
            if kind == 44:
                cookie = body[at + 6:at + 4 + n]
            at += 4 + n
        ch2 = tls_client_hello(self.host, self.random, self.sid, self.public, cookie)
        self.transcript = b"\xfe\x00\x00\x20" + hashlib.sha256(self.transcript).digest() + hrr + ch2
        self.ccs_sent = True
        return plain_rec(20, b"\x01") + plain_rec(22, ch2)

    def flight(self, scheme=0x0403, ee=b"", request=None, entries=None, bad_sig=False, bad_finished=False):
        """EncryptedExtensions, [CertificateRequest,] Certificate,
        CertificateVerify and Finished, as messages; the transcript and the
        application secrets move on with them."""
        sha = hashlib.sha256
        msgs = [hs_msg(8, u16(len(ee)) + ee)]
        self.request = request
        if request is not None:
            exts = ext_of(13, u16(2) + u16(0x0403))
            msgs.append(hs_msg(13, bytes([len(request)]) + request + u16(len(exts)) + exts))
        if entries is None:
            entries = b"".join(u24(len(c)) + c + u16(0) for c in self.chain)
        msgs.append(hs_msg(11, b"\x00" + u24(len(entries)) + entries))
        for m in msgs:
            self.transcript += m
        content = b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + sha(self.transcript).digest()
        sig = tls_sign(self.leaf, scheme, content)
        if bad_sig:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        cv = hs_msg(15, u16(scheme) + u16(len(sig)) + sig)
        self.transcript += cv
        vd = pyhmac.new(expand_label(sha, self.s_hs, b"finished", b"", 32), sha(self.transcript).digest(), sha).digest()
        if bad_finished:
            vd = vd[:-1] + bytes([vd[-1] ^ 1])
        fin = hs_msg(20, vd)
        self.transcript += fin
        th = sha(self.transcript).digest()
        self.c_ap = expand_label(sha, self.master, b"c ap traffic", th, 32)
        self.s_ap = expand_label(sha, self.master, b"s ap traffic", th, 32)
        return msgs + [cv, fin]

    def after_finished(self):
        """The server's records after its Finished use its application keys."""
        self.sr = tls_keys(self.s_ap)

    def finish(self):
        """The client's last flight once its check of the chain passes."""
        sha = hashlib.sha256
        out = b""
        if not self.ccs_sent:
            out += plain_rec(20, b"\x01")
            self.ccs_sent = True
        if self.request is not None:
            cm = hs_msg(11, bytes([len(self.request)]) + self.request + u24(0))
            self.transcript += cm
            out += tls_seal(self.cw, 22, cm)
        vd = pyhmac.new(expand_label(sha, self.c_hs, b"finished", b"", 32), sha(self.transcript).digest(), sha).digest()
        fin = hs_msg(20, vd)
        self.transcript += fin
        out += tls_seal(self.cw, 22, fin)
        self.cw = tls_keys(self.c_ap)
        return out

    def handshake(self, check=True, **kw):
        """The usual way there: ServerHello and a change_cipher_spec in the
        clear, the rest in one protected record, the client's check passed."""
        sh = self.hello()
        self.keys(sh)
        msgs = self.flight(**kw)
        self.feed(plain_rec(22, sh) + plain_rec(20, b"\x01") + tls_seal(self.sr, 22, b"".join(msgs)))
        self.after_finished()
        self.line("state", "check")
        if check:
            self.line("check")
            self.expect(self.finish())
            self.line("state", "open")


def tls13_vectors():
    y = lambda year, month=1, day=1: datetime.datetime(year, month, day, tzinfo=UTC)  # noqa: E731
    now = y(2026, 6)
    k_root, k_int = test_key("p384"), test_key("p256")
    k_ec, k_384, k_rsa = test_key("p256"), test_key("p384"), test_key("rsa")
    root = make_cert("TLS Test Root", k_root, "TLS Test Root", k_root, profile("root", k_root, k_root), y(2020), y(2040))
    inter = make_cert("TLS Test CA", k_int, "TLS Test Root", k_root, profile("ca", k_int, k_root), y(2025), y(2030))

    def leaf(key, names):
        return make_cert(names[0], key, "TLS Test CA", k_int, profile("leaf", key, k_int, names), y(2026, 3), y(2026, 9))

    ec_chain = [leaf(k_ec, ["tls.example", "*.tls.example"]), inter]
    p384_chain = [leaf(k_384, ["p384.example"]), inter]
    rsa_chain = [leaf(k_rsa, ["rsa.example"]), inter]
    out = ["# exchange name, then steps: client host random session-id x25519-key (and start);",
           "# root der; now ms; expect bytes (what the client has sent since; - for nothing);",
           "# feed chunk-size bytes (0 for all at once); check (the chain, then accept or",
           "# reject); state waiting|check|open|closed; alert code (the one the client sent);",
           "# send data; app data (what the client received); send_pattern and app_pattern n",
           "# (n bytes, i % 251); peer_closed; eof (the server's side of TCP closed); truncated 0|1",
           "# (whether it closed without close_notify); close; end"]

    def ex(name, host="tls.example", chain=ec_chain, key=k_ec):
        return TlsScript(out, name, host, now, [root], chain, key)

    # the way it goes: a P-256 server, a request, a ticket, an answer, both closing
    t = ex("ecdsa")
    t.handshake()
    request = b"GET / HTTP/1.1\r\nHost: tls.example\r\n\r\n"
    t.line("send", hx(request))
    t.expect(tls_seal(t.cw, 23, request))
    answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    t.feed(tls_seal(t.sr, 22, hs_msg(4, rand_bytes(40))) + tls_seal(t.sr, 23, answer))
    t.line("app", hx(answer))
    t.feed(tls_seal(t.sr, 21, b"\x01\x00"))
    t.line("peer_closed")
    # TCP closing after close_notify is the clean end, and the client may
    # still send its own
    t.line("eof")
    t.line("truncated", 0)
    t.line("close")
    t.expect(tls_seal(t.cw, 21, b"\x01\x00"))
    t.line("state", "closed")
    t.end()

    # the same, a byte at a time, one message to a record, padded
    t = ex("a byte at a time")
    sh = t.hello()
    t.keys(sh)
    flight = b"".join(tls_seal(t.sr, 22, m, pad=i * 7) for i, m in enumerate(t.flight()))
    t.feed(plain_rec(22, sh) + flight, 1)
    t.after_finished()
    t.line("check")
    t.expect(t.finish())
    # past the largest record: 16384 bytes, then the rest (the data is
    # bytes i % 251, written as a length to keep the file small)
    big = bytes(i % 251 for i in range(16400))
    t.feed(tls_seal(t.sr, 23, big[:16384]) + tls_seal(t.sr, 23, big[16384:]), 1000)
    t.line("app_pattern", len(big))
    t.line("send_pattern", len(big))
    t.expect(tls_seal(t.cw, 23, big[:16384]) + tls_seal(t.cw, 23, big[16384:]))
    # TCP closing without close_notify: what came may be cut short
    t.line("eof")
    t.line("truncated", 1)
    t.line("state", "closed")
    t.end()

    for name, host, chain, key, scheme in [("RSA-PSS", "rsa.example", rsa_chain, k_rsa, 0x0804),
                                           ("RSA-PSS with SHA-384", "rsa.example", rsa_chain, k_rsa, 0x0805),
                                           ("P-384", "p384.example", p384_chain, k_384, 0x0503)]:
        t = ex(name, host, chain, key)
        t.handshake(scheme=scheme)
        t.line("send", hx(b"ping"))
        t.expect(tls_seal(t.cw, 23, b"ping"))
        t.end()

    # a Certificate split across two records, with the other messages
    t = ex("a message across records")
    sh = t.hello()
    t.keys(sh)
    msgs = b"".join(t.flight())
    cut = len(msgs) // 2
    t.feed(plain_rec(22, sh) + tls_seal(t.sr, 22, msgs[:cut]) + tls_seal(t.sr, 22, msgs[cut:]))
    t.after_finished()
    t.line("check")
    t.expect(t.finish())
    t.line("state", "open")
    t.end()

    # data from the server right after its Finished (0.5-RTT), kept until the check
    t = ex("data before the check")
    sh = t.hello()
    t.keys(sh)
    msgs = t.flight()
    early = tls_seal(t.sr, 22, b"".join(msgs))
    t.after_finished()
    t.feed(plain_rec(22, sh) + early + tls_seal(t.sr, 23, b"early words"))
    t.line("state", "check")
    t.line("check")
    t.expect(t.finish())
    t.line("app", hx(b"early words"))
    t.end()

    # the server updates its keys and asks for the client's to change too
    t = ex("key update")
    t.handshake()
    t.feed(tls_seal(t.sr, 22, hs_msg(24, b"\x01")))
    t.sr = tls_keys(expand_label(hashlib.sha256, t.sr["secret"], b"traffic upd", b"", 32))
    t.expect(tls_seal(t.cw, 22, hs_msg(24, b"\x00")))
    t.cw = tls_keys(expand_label(hashlib.sha256, t.cw["secret"], b"traffic upd", b"", 32))
    t.feed(tls_seal(t.sr, 23, b"under new keys"))
    t.line("app", hx(b"under new keys"))
    t.line("send", hx(b"and mine"))
    t.expect(tls_seal(t.cw, 23, b"and mine"))
    t.end()

    # a server that asks for a client certificate is told there is none
    t = ex("certificate request")
    t.handshake(request=b"ctx")
    t.end()

    # a HelloRetryRequest with a cookie, then the handshake
    t = ex("hello retry")
    hrr = t.hello(retry=True, group=0, cookie=rand_bytes(24))
    t.feed(plain_rec(22, hrr))
    t.expect(t.retry(hrr))
    t.handshake()
    t.end()

    # the chain is refused: a certificate for another host
    t = ex("the wrong host", host="other.example")
    t.handshake(check=False)
    t.line("check")
    t.expect(t.alert(42))
    t.line("state", "closed")
    t.line("alert", 42)
    t.end()

    # what the client refuses before there are keys (alerts in the clear)
    for name, desc, kw in [("a TLS 1.2 server", 70, {"version": 0}),
                           ("another cipher suite", 47, {"suite": 0x1301}),
                           ("another session id", 47, {"sid": rand_bytes(32)}),
                           ("an extension not asked for", 110, {"extra": ext_of(23, b"")}),
                           ("a key share of small order", 47, {"share": b"\x00" * 32}),
                           ("a wrong legacy version", 47, {"legacy": 0x0301})]:
        t = ex(name)
        t.feed(plain_rec(22, t.hello(**kw)))
        t.expect(t.alert(desc))
        t.line("state", "closed")
        t.line("alert", desc)
        t.end()
    for name, desc, hrr_kw in [("a HelloRetryRequest for X25519", 47, {"group": 0x001D}),
                               ("a HelloRetryRequest for nothing", 47, {"group": 0})]:
        t = ex(name)
        t.feed(plain_rec(22, t.hello(retry=True, **hrr_kw)))
        t.expect(t.alert(desc))
        t.line("alert", desc)
        t.end()
    t = ex("a second HelloRetryRequest")
    hrr = t.hello(retry=True, group=0, cookie=b"cookie")
    t.feed(plain_rec(22, hrr))
    t.expect(t.retry(hrr))
    t.feed(plain_rec(22, t.hello(retry=True, group=0, cookie=b"again")))
    t.expect(t.alert(10))
    t.line("alert", 10)
    t.end()
    for name, desc, data in [("application data before the handshake", 10, plain_rec(23, b"hello")),
                             ("a record too long", 22, bytes([23, 3, 3]) + u16(18000))]:
        t = ex(name)
        t.feed(data)
        t.expect(t.alert(desc))
        t.line("alert", desc)
        t.end()
    for name, body in [("the server's alert", b"\x02\x28"), ("a close during the handshake", b"\x01\x00")]:
        t = ex(name)
        t.feed(plain_rec(21, body))
        t.expect(b"")
        t.line("state", "closed")
        t.line("alert", 0)
        t.end()

    # what the client refuses once there are keys (protected alerts)
    def refused(name, desc, host="tls.example", chain=ec_chain, key=k_ec, tamper=False, trailing=b"", **kw):
        t = ex(name, host, chain, key)
        sh = t.hello()
        t.keys(sh)
        rec = tls_seal(t.sr, 22, b"".join(t.flight(**kw)))
        if tamper:
            rec = rec[:20] + bytes([rec[20] ^ 1]) + rec[21:]
        t.feed(plain_rec(22, sh) + rec + trailing)
        t.expect(t.alert(desc))
        t.line("state", "closed")
        t.line("alert", desc)
        t.end()

    refused("a bad Finished", 51, bad_finished=True)
    refused("a bad signature", 51, bad_sig=True)
    refused("PKCS #1 in CertificateVerify", 47, "rsa.example", rsa_chain, k_rsa, scheme=0x0401)
    refused("a scheme for another key", 47, "p384.example", p384_chain, k_384, scheme=0x0403)
    refused("an extension not asked for, encrypted", 110, ee=ext_of(16, u16(9) + b"\x08http/1.1"))
    refused("a tampered record", 20, tamper=True)
    refused("certificate entry extensions", 110, entries=u24(len(ec_chain[0])) + ec_chain[0] + u16(4) + ext_of(5, b""))
    refused("no certificate", 50, entries=b"")
    refused("a change_cipher_spec after Finished", 10, trailing=plain_rec(20, b"\x01"))
    t = ex("a ServerHello running into the next message")
    sh = t.hello()
    t.keys(sh)
    t.feed(plain_rec(22, sh + hs_msg(8, u16(0))))
    t.expect(t.alert(10))
    t.line("alert", 10)
    t.end()
    t = ex("a KeyUpdate asking for the impossible")
    t.handshake()
    t.feed(tls_seal(t.sr, 22, hs_msg(24, b"\x02")))
    t.expect(t.alert(47))
    t.line("alert", 47)
    t.end()
    # TCP closing before the ServerHello: a failed handshake, not a
    # truncation
    t = ex("the server gone at once")
    t.line("eof")
    t.line("state", "closed")
    t.line("truncated", 0)
    t.end()
    return "\n".join(out) + "\n"


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
    "tests/vectors/x509.txt": x509_vectors,
    "tests/vectors/tls13_rfc8448.txt": tls13_rfc8448_vectors,
    "tests/vectors/tls13.txt": tls13_vectors,
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
