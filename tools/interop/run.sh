#!/usr/bin/env bash
# nxtls's TLS client against OpenSSL's TLS 1.3 server (openssl s_server),
# once for each way a server may differ, each with the outcome it must
# have. Linux or macOS, with openssl and Python's cryptography installed:
#
#     bash tools/interop/run.sh            # builds tools/interop/local.nx
#     LOCAL_BIN=path/to/local bash tools/interop/run.sh   # a binary built already
#
# CI runs this; `nx run tools/interop/live.nx` tries real hosts too.
set -u
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 "$here/pki.py" "$work" || exit 2
bin=${LOCAL_BIN:-}
if [ -z "$bin" ]; then
    (cd "$here" && nx build local.nx --out-dir "$work/bin" > /dev/null) || exit 2
    bin=$work/bin/local
fi
openssl version
port=44330
fails=0
case_() {
    local want=$1 what=$2
    shift 2
    openssl s_server -accept "$port" -www "${PROTO:--tls1_3}" -quiet "$@" > "$work/server.log" 2>&1 &
    local pid=$!
    # wait for the server to listen
    for _ in $(seq 50); do
        (echo > "/dev/tcp/127.0.0.1/$port") 2> /dev/null && break
        sleep 0.1
    done
    "$bin" "$port" "$work/root.pem" "$want" "$what" || fails=$((fails + 1))
    kill "$pid" 2> /dev/null
    wait "$pid" 2> /dev/null
    port=$((port + 1))
}
p256=(-cert "$work/p256.pem" -key "$work/p256.key")
case_ open "a P-256 server" "${p256[@]}"
case_ open "a P-384 server" -cert "$work/p384.pem" -key "$work/p384.key"
case_ open "an RSA server (PSS)" -cert "$work/rsa.pem" -key "$work/rsa.key"
case_ open "a HelloRetryRequest with a cookie (stateless)" "${p256[@]}" -stateless
case_ open "a server asking for a client certificate" "${p256[@]}" -verify 1
case_ open "ChaCha20-Poly1305 and nothing else" "${p256[@]}" -ciphersuites TLS_CHACHA20_POLY1305_SHA256
case_ open "records of 512 bytes" "${p256[@]}" -max_send_frag 512
case_ refused "a server without ChaCha20-Poly1305" "${p256[@]}" -ciphersuites TLS_AES_128_GCM_SHA256
case_ refused "a server without X25519" "${p256[@]}" -groups P-256
case_ refused "a certificate for another host" -cert "$work/wrong.pem" -key "$work/wrong.key"
case_ refused "an expired certificate" -cert "$work/expired.pem" -key "$work/expired.key"
PROTO=-tls1_2 case_ refused "a TLS 1.2 server" "${p256[@]}"
if [ "$fails" -ne 0 ]; then
    echo "$fails failed"
    exit 1
fi
echo "all passed"
