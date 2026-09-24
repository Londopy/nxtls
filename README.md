<div align="center">

<img src="assets/nxtls.svg" width="96" height="96" alt="">

# nxtls

**Cryptography, and later a TLS 1.3 client, written entirely in Nexium.**<br>
No C libraries, no `@cImport`, no `unsafe`: code a reviewer can read end to end.

[![CI](https://github.com/Londopy/nxtls/actions/workflows/ci.yml/badge.svg)](https://github.com/Londopy/nxtls/actions/workflows/ci.yml)
[![Tag](https://img.shields.io/github/v/tag/Londopy/nxtls?sort=semver&color=0F766E)](https://github.com/Londopy/nxtls/tags)
[![Written in Nexium](https://img.shields.io/badge/written%20in-Nexium-7C3AED)](https://github.com/Londopy/nexium)
[![unsafe: 0](https://img.shields.io/badge/unsafe-0-14B8A6)](#tests)
[![Status: early](https://img.shields.io/badge/status-early-orange)](#plan)
[![License: MIT](https://img.shields.io/github/license/Londopy/nxtls?color=blue)](LICENSE)

[Modules](#modules) · [Use](#use) · [Tests](#tests) · [Plan](#plan)

</div>

---

nxtls exists so that Nexium programs can verify signatures and speak
HTTPS without handing their security to a C library. The first user is
[QNI](https://github.com/Londopy/qni), a Discord helper for an amateur
radio club, which checks every request's Ed25519 signature with it.

> [!WARNING]
> **Early.** What is here is tested against published vectors; the TLS
> client is not written yet. Do not use nxtls to protect anything that
> matters until the whole plan below has been reviewed by someone who
> knows TLS.

## Modules

| module | what | tested against |
| --- | --- | --- |
| `sha2` | SHA-256, SHA-384, SHA-512 | FIPS 180-4 messages, every padding boundary, a million a's |
| `sha1` | SHA-1, and the WebSocket handshake's `Sec-WebSocket-Accept` (never for signatures or integrity: SHA-1 is broken) | FIPS 180-4 messages, every padding boundary, a million a's, RFC 6455's example |
| `hmac` | HMAC over each of them, constant-time `verify` | RFC 4231, keys either side of the block size |
| `hkdf` | HKDF extract and expand, TLS 1.3 `expand_label` and `derive_secret` | RFC 5869, RFC 8448's early and derived secrets |
| `ed25519` | signature verification (verify only) | RFC 8032, random keys, tampering, S + L, non-canonical and small-order inputs |
| `x25519` | X25519 key agreement, constant time; refuses an all-zero shared secret | RFC 7748 (the iterated test to 1000, Alice and Bob), random keys, points on the twist, u with bit 255 set, small-order points |
| `chacha20poly1305` | ChaCha20, Poly1305 and their AEAD, constant time | RFC 8439 (every vector of its appendix, among them the Poly1305 carry and reduction cases), random lengths and counters, tampering |
| `ecdsa` | ECDSA verification on P-256 and P-384, signatures in DER (verify only) | curve checks (G on the curve, n G at infinity), deterministic signatures from Python's cryptography, malleable s, tampering, keys off the curve, r and s out of range, strict DER |
| `f25519` | arithmetic mod 2^255 - 19, shared by `ed25519` and `x25519` | through both |
| `bn` | big integers with Montgomery multiplication, for verification (public values only) | known products, powers and inverses; through `ecdsa` |
| `der` | a strict DER reader: shortest lengths, positive minimal integers | malformed and non-minimal encodings |
| `ct` | constant-time comparison | every byte value |

`ed25519.verify` is stricter than RFC 8032 in the ways libsodium is: it
also rejects non-canonical encodings and public keys or R values of small
order. The vectors marked `strict` in `tests/vectors/ed25519.txt` are the
cases where that differs from a permissive verifier such as OpenSSL's.

## Use

```toml
[dependencies]
nxtls = { git = "https://github.com/Londopy/nxtls", tag = "v0.3.0" }
```

```nexium
import nxtls.sha2
import nxtls.ed25519

let digest = sha2.sha256("abc")        // 32 bytes
if !ed25519.verify(public_key, message, signature) { ... }
```

`nx fetch` gets it into `nexium_modules/` and pins the commit in
`nexium.lock`. It needs a 64-bit target: the field arithmetic uses
128-bit integers.

## Tests

```sh
nx test src/hkdf.nx                    # also runs the tests of what it imports
nx test src/ed25519.nx
nx test src/sha1.nx
nx test src/x25519.nx
nx test src/chacha20poly1305.nx
nx test src/ecdsa.nx
python tools/gen.py --check            # the vectors and tables are current
```

`tools/gen.py` is test tooling only. It derives every constant in
`src/tables.nx` from its definition and writes the vectors in
`tests/vectors/` from Python's `hashlib`, `hmac` and the `cryptography`
package, asserting the published values from each standard along the way.

CI runs the tests on Linux (built against glibc, whose debug build traps
on undefined behaviour), Windows and macOS. It also checks that no module
has an `unsafe` block, a mutable global or a foreign call, and that the
tables and vectors are current.

## Plan

The order lets each piece be tested alone:

1. ~~SHA-2, HMAC and HKDF~~ (and SHA-1, for WebSocket)
2. ~~Ed25519 verification~~
3. ~~ChaCha20-Poly1305 and X25519~~
4. DER, PEM, X.509, RSA and ECDSA verification
5. The record layer and the TLS 1.3 handshake: replayed against RFC 8448
   byte for byte, then live hosts, with badssl.com's broken hosts as
   negative tests
6. Secure randomness (waits on an OS entropy source in Nexium's std)

Code that touches secrets (X25519, HMAC and HKDF over traffic secrets,
ChaCha20-Poly1305) is written constant time: fixed-length loops, no early
exits on mismatch, no secret-indexed tables, wrapping arithmetic only.
Code over public data (hashing transcripts, signature verification,
certificate parsing) is ordinary code.

## License

[MIT](LICENSE)
