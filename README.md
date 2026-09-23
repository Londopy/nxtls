# nxtls

Cryptography and, later, a TLS 1.3 client, written entirely in Nexium: no
C libraries, no `@cImport`, no `unsafe`. It exists so that Nexium programs
(the first is [QNI](https://github.com/Londopy/qni), a Discord helper for an
amateur radio club) can verify signatures and speak HTTPS with code a
reviewer can read end to end.

**Status: early.** What is here is tested against published vectors; the
TLS client is not written yet. Do not use nxtls to protect anything that
matters until the whole plan below has been reviewed by someone who knows
TLS.

| module | what | tested against |
| --- | --- | --- |
| `sha2` | SHA-256, SHA-384, SHA-512 | FIPS 180-4 messages, every padding boundary, a million a's |

## Use

```toml
[dependencies]
nxtls = { git = "https://github.com/Londopy/nxtls", tag = "v0.1.0" }
```

```nexium
import nxtls.sha2

let digest = sha2.sha256("abc")        // 32 bytes
```

## Tests

```sh
nx test src/sha2.nx
python tools/gen.py --check            # the vectors and tables are current
```

`tools/gen.py` is test tooling only. It derives every constant in
`src/tables.nx` from its definition and writes the vectors in
`tests/vectors/` from Python's `hashlib`, `hmac` and the `cryptography`
package, asserting the published values from each standard along the way.

## Plan

The order lets each piece be tested alone: SHA-2, HMAC and HKDF; Ed25519
verification; ChaCha20-Poly1305 and X25519; DER, PEM, X.509, RSA and ECDSA
verification; the record layer and the TLS 1.3 handshake (replayed against
RFC 8448 byte for byte, then live hosts, with badssl.com's broken hosts as
negative tests); secure randomness.

Code that touches secrets (X25519, HMAC and HKDF over traffic secrets,
ChaCha20-Poly1305) is written constant time: fixed-length loops, no early
exits on mismatch, no secret-indexed tables, wrapping arithmetic only.
Code over public data (hashing transcripts, signature verification,
certificate parsing) is ordinary code.

## License

MIT
