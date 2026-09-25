<div align="center">

<img src="assets/nxtls.svg" width="96" height="96" alt="">

# nxtls

**Cryptography and a TLS 1.3 client, written entirely in Nexium.**<br>
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
radio club, which checks every request's Ed25519 signature with it and
talks to Discord through its TLS client.

> [!WARNING]
> **New.** The TLS client works against Discord, GitHub, Google,
> Cloudflare and OpenSSL 3, and replays 36 recorded exchanges byte for
> byte; everything under it is tested against published vectors and
> Python's `cryptography`. None of it has been reviewed by someone who
> knows TLS yet: weigh that before trusting it with anything that matters.

## Modules

| module | what | tested against |
| --- | --- | --- |
| `tls` | a TLS 1.3 client: TLS_CHACHA20_POLY1305_SHA256, X25519, the server's signature by ECDSA P-256/P-384 or RSA-PSS, its chain checked by `x509`; HelloRetryRequest, KeyUpdate, a server asking for a client certificate; one deadline for the whole handshake, and a connection cut without close_notify told from a closed one. `Client` is the protocol alone (bytes in, bytes out); `Conn` runs it over TCP | RFC 8448's key schedule and Finished values; 36 exchanges with a server gen.py plays from Python's `cryptography`, byte for byte (every alert the client sends among them); OpenSSL 3's `s_server` in twelve configurations; live, Discord, callook.info, GitHub, Google and Cloudflare, by name and by IP address |
| `sha2` | SHA-256, SHA-384, SHA-512 | FIPS 180-4 messages, every padding boundary, a million a's |
| `sha1` | SHA-1, and the WebSocket handshake's `Sec-WebSocket-Accept` (never for signatures or integrity: SHA-1 is broken) | FIPS 180-4 messages, every padding boundary, a million a's, RFC 6455's example |
| `hmac` | HMAC over each of them, constant-time `verify` | RFC 4231, keys either side of the block size |
| `hkdf` | HKDF extract and expand, TLS 1.3 `expand_label` and `derive_secret` | RFC 5869, RFC 8448's early and derived secrets |
| `ed25519` | signature verification (verify only) | RFC 8032, random keys, tampering, S + L, non-canonical and small-order inputs |
| `x25519` | X25519 key agreement, constant time; refuses an all-zero shared secret | RFC 7748 (the iterated test to 1000, Alice and Bob), random keys, points on the twist, u with bit 255 set, small-order points |
| `chacha20poly1305` | ChaCha20, Poly1305 and their AEAD, constant time | RFC 8439 (every vector of its appendix, among them the Poly1305 carry and reduction cases), random lengths and counters, tampering |
| `ecdsa` | ECDSA verification on P-256 and P-384, signatures in DER (verify only) | curve checks (G on the curve, n G at infinity), deterministic signatures from Python's cryptography, malleable s, tampering, keys off the curve, r and s out of range, strict DER |
| `rsa` | RSA verification: PKCS #1 v1.5 (certificates) and PSS (TLS 1.3), keys of 2048 to 8192 bits (verify only) | keys of 2048, 2049, 3072 and 4096 bits made from a seed, signatures checked by Python's cryptography, PSS's emBits edge cases, salt and trailer errors, Bleichenbacher's e = 3 forgery |
| `x509` | X.509 certificates: reading them, and checking a server's chain against trusted roots for a host name or an IP address: path building across cross-signed CAs, validity, CA constraints and path lengths, key usage and extended key usage, host names with wildcards, IPv4 and IPv6 addresses; the search bounded, so chains built to stall it end quickly | 80 chains and 14 malformed certificates, judged by Python's cryptography's own path validation (marked where nxtls is stricter or, once, more lenient); the real chains of discord.com, gateway.discord.gg and callook.info; roots that must still load (a zero serial, P-521, SHA-1) |
| `entropy` | random bytes from the operating system (/dev/urandom, refusing a regular file planted in its place; none on Windows, where it says so) | lengths, repeats, every byte value in 64 KB |
| `pem` | PEM blocks, as certificate files and CA bundles hold them | text around the blocks, CRLF, broken and unterminated blocks |
| `f25519` | arithmetic mod 2^255 - 19, shared by `ed25519` and `x25519` | through both |
| `bn` | big integers with Montgomery multiplication, for verification (public values only) | known products, powers and inverses; through `ecdsa` and `rsa` |
| `der` | a strict DER reader: shortest lengths, positive minimal integers | malformed and non-minimal encodings |
| `ct` | constant-time comparison | every byte value |

`ed25519.verify` is stricter than RFC 8032 in the ways libsodium is: it
also rejects non-canonical encodings and public keys or R values of small
order. The vectors marked `strict` in `tests/vectors/ed25519.txt` are the
cases where that differs from a permissive verifier such as OpenSSL's.

## Use

```toml
[dependencies]
nxtls = { git = "https://github.com/Londopy/nxtls", tag = "v0.3.1" }
```

```nexium
import std.fs
import nxtls.tls
import nxtls.x509

let roots = x509.store_from_pem(try fs.read("/etc/ssl/certs/ca-certificates.crt"))
var conn = tls.connect("discord.com", 443, &roots, time.now(), 10000)
if !conn.is_open() {
    println("{}", .{conn.problem})        // why: the certificate, an alert, the network
}
try conn.send("GET /api/v10/gateway HTTP/1.1\r\nHost: discord.com\r\nConnection: close\r\n\r\n")
let answer = try conn.read_all(1 << 20)   // until the server closes
conn.close()
```

`timeout_ms` bounds the whole handshake, connecting included, and then
each wait for the server. `read_all` fails with `error.Truncated` when
the connection ends without the server's close_notify, since the answer
may then be cut short; some servers (Google's, for one) always end that
way, so for them read with `recv`, which returns "" at either end, and
trust the answer's own framing (an HTTP Content-Length, a WebSocket
close), with `conn.truncated()` saying which end it was. Certificates
are not checked for revocation: no OCSP, no CRLs.

```nexium
import nxtls.sha2
import nxtls.ed25519

let digest = sha2.sha256("abc")        // 32 bytes
if !ed25519.verify(public_key, message, signature) { ... }
```

`nx fetch` gets it into `nexium_modules/` and pins the commit in
`nexium.lock`. It needs a 64-bit target: the field arithmetic uses
128-bit integers. The TLS client needs /dev/urandom (Linux, macOS, the
BSDs) and a CA bundle; on Windows `tls.connect` says there is no
randomness rather than use a weaker kind.

## Tests

```sh
nx test src/hkdf.nx                    # also runs the tests of what it imports
nx test src/ed25519.nx
nx test src/sha1.nx
nx test src/x25519.nx
nx test src/chacha20poly1305.nx
nx test src/ecdsa.nx
nx test src/rsa.nx
nx test src/pem.nx
nx test src/x509.nx
nx test src/entropy.nx
nx test src/tls.nx
python tools/gen.py --check            # the vectors and tables are current
bash tools/interop/run.sh              # against openssl s_server (Linux, macOS)
nx run tools/interop/live.nx           # against Discord, callook.info and more
```

`tools/gen.py` is test tooling only. It derives every constant in
`src/tables.nx` from its definition and writes the vectors in
`tests/vectors/` from Python's `hashlib`, `hmac` and the `cryptography`
package, asserting the published values from each standard along the way;
the X.509 chains are judged by the `cryptography` package's own path
validation. `tests/certs/` holds the chains discord.com, gateway.discord.gg
and callook.info sent on 2026-09-24, and the roots from Mozilla's store
that they and the tests need.

CI runs the tests on Linux (built against glibc, whose debug build traps
on undefined behaviour), Windows and macOS. It also checks that no module
has an `unsafe` block, a mutable global or a foreign call, that the tables
and vectors are current, and that the TLS client does what it must against
OpenSSL's TLS 1.3 server in each configuration of `tools/interop/run.sh`:
connecting to P-256, P-384 and RSA servers, through a HelloRetryRequest
and a request for a client certificate, over small records; refusing a
server without ChaCha20-Poly1305 or X25519, a certificate for another host
or one that has expired, and TLS 1.2.

## Plan

The order lets each piece be tested alone:

1. ~~SHA-2, HMAC and HKDF~~ (and SHA-1, for WebSocket)
2. ~~Ed25519 verification~~
3. ~~ChaCha20-Poly1305 and X25519~~
4. ~~DER, PEM, X.509, RSA and ECDSA verification~~
5. ~~The record layer and the TLS 1.3 handshake~~: RFC 8448's key
   schedule, recorded exchanges byte for byte, OpenSSL, live hosts
6. ~~Secure randomness~~, from /dev/urandom (Nexium's std has no entropy
   source yet)

Next: a review by someone who knows TLS. AES-GCM, P-256 key exchange and
resumption wait until a server needs them; every host QNI talks to speaks
ChaCha20-Poly1305 over X25519.

Code that touches secrets (X25519, HMAC and HKDF over traffic secrets,
ChaCha20-Poly1305) is written constant time: fixed-length loops, no early
exits on mismatch, no secret-indexed tables, wrapping arithmetic only.
Code over public data (hashing transcripts, signature verification,
certificate parsing) is ordinary code.

## License

[MIT](LICENSE)
