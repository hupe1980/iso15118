#!/bin/sh
# Fetches x509-limbo — the X.509 path-validation suite rustls-webpki, Go,
# pyca/cryptography, Botan and GnuTLS run — at a pinned commit, for
# tests/x509_limbo.rs. The suite is Apache-2.0 and 41 MB of JSON, so it is
# fetched, checked by hash and never committed.
#
#   scripts/fetch-x509-limbo.sh [dir]     # default: concepts/reference/x509-limbo
#   ISO15118_X509_LIMBO=<dir>/limbo.json cargo test --all-features --test x509_limbo
#
# A mismatch is refused by name: a suite that changed under the pin is a
# different suite, and the divergence list was written against this one.
set -eu

BASE="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1:-$BASE/concepts/reference/x509-limbo}"
REPO=C2SP/x509-limbo
# 2026-11-02, after #631 (CRL time-field cases).
COMMIT=519f4bcf6a31d20e1b7011a0586e233dbbd3e732
SHA256=56799cefd65fc9e0bdb9cb0f97fce6734533b45df3de4fc17fdc7b7b79654fca

command -v curl >/dev/null 2>&1 || { echo "fetch-x509-limbo: curl not found" >&2; exit 2; }

mkdir -p "$DIR"
FILE="$DIR/limbo.json"

check() {
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$SHA256  $FILE" | sha256sum -c - >/dev/null 2>&1
    else
        echo "$SHA256  $FILE" | shasum -a 256 -c - >/dev/null 2>&1
    fi
}

if [ -f "$FILE" ] && check; then
    echo "x509-limbo @ ${COMMIT%"${COMMIT#???????}"} already at $FILE"
    exit 0
fi

curl -sSfL -o "$FILE" "https://raw.githubusercontent.com/$REPO/$COMMIT/limbo.json"
if ! check; then
    echo "fetch-x509-limbo: $FILE does not match the pinned SHA-256 $SHA256" >&2
    rm -f "$FILE"
    exit 1
fi
echo "x509-limbo @ ${COMMIT%"${COMMIT#???????}"} -> $FILE"
