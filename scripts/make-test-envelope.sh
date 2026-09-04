#!/bin/sh
# Build a `ContractSignatureEncryptedPrivateKey` with OpenSSL, for
# `tests/envelope.rs` to open.
#
# This is the evidence that matters for the contract-key envelope, and it is
# the same argument as everywhere else here: a crate that seals a key and then
# opens it has proved that its own two halves agree. What ISO 15118-2
# §7.9.2.4.3 actually requires is that a *secondary actor's* envelope opens, and
# the only way to check that without a secondary actor is to have a third
# implementation build one.
#
# So OpenSSL does the ECDH, the concatenation KDF and the AES-128-CBC, from the
# requirement text rather than from this crate's source:
#
#   Z = ECDH(ephemeral private, static public)              [V2G2-818]
#   K = leftmost 16 bytes of SHA-256(00000001 ‖ Z ‖ 015556) [V2G2-818]
#   C = AES-128-CBC(K, IV, private key), no padding         [V2G2-815]
#   envelope = IV ‖ C
#
# Every input is fixed, so the fixture is reproducible and the test can assert
# the exact bytes.
set -eu

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$BASE_DIR/tests/fixtures/pki"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export OPENSSL_CONF=/dev/null
cd "$WORK"

# The receiver's static key — in the field this is the one inside the OEM
# Provisioning Certificate [V2G2-820] or the existing Contract Certificate
# [V2G2-821]. Fixed here so the fixture is reproducible.
openssl ecparam -name prime256v1 -genkey -noout -out static.key 2>/dev/null
# The sender's ephemeral key, which [V2G2-819] puts on the wire as DHpublickey.
openssl ecparam -name prime256v1 -genkey -noout -out ephemeral.key 2>/dev/null
# The contract private key being delivered. A real key pair rather than random
# bytes, because [V2G2-823] has the receiver check the delivered scalar against
# the public key of the contract certificate — so the fixture needs both halves.
openssl ecparam -name prime256v1 -genkey -noout -out contract.key 2>/dev/null

openssl pkey -in static.key -pubout -out static.pub 2>/dev/null

# The raw 32-byte scalar of an EC private key, big-endian, as ISO 15118 carries
# one [V2G2-816]. `-text` prints it as hex; this is the whole of the extraction.
scalar() {
    openssl ec -in "$1" -text -noout 2>/dev/null \
        | sed -n '/^priv:/,/^pub:/p' | tr -d ' :\n' \
        | sed 's/^priv//; s/pub$//' \
        | tail -c 65 | xxd -r -p
}

# The uncompressed public point, 65 bytes — the tail of a DER
# SubjectPublicKeyInfo, which is exactly what [V2G2-819] puts on the wire.
point() {
    openssl ec -in "$1" -pubout -conv_form uncompressed -outform DER 2>/dev/null | tail -c 65
}

scalar contract.key > contract.bin

# Z: the shared secret's x-coordinate. `-derive` is exactly C(1,1,ECC CDH)'s
# output before any KDF, which is what [V2G2-818] feeds the concat KDF.
openssl pkeyutl -derive -inkey ephemeral.key -peerkey static.pub -out z.bin

# K = leftmost 128 bits of SHA-256(counter ‖ Z ‖ AlgorithmID ‖ IDU ‖ IDV).
printf '\000\000\000\001' > kdf.bin
cat z.bin >> kdf.bin
printf '\001UV' >> kdf.bin
openssl dgst -sha256 -binary -out digest.bin kdf.bin
dd if=digest.bin of=key.bin bs=1 count=16 2>/dev/null

# A fixed IV. In the field this must be random and never reused [V2G2-815];
# fixed here so the fixture is a fixture.
printf '0123456789abcdef' > iv.bin

hex() { od -An -v -tx1 < "$1" | tr -d ' \n'; }

openssl enc -aes-128-cbc -nopad \
    -K "$(hex key.bin)" -iv "$(hex iv.bin)" \
    -in contract.bin -out cipher.bin

mkdir -p "$OUT"
cat iv.bin cipher.bin       > "$OUT/envelope.bin"          # the wire field
cp contract.bin               "$OUT/contract-key.bin"      # what must come out
point contract.key          > "$OUT/contract-public.bin"   # what [V2G2-823] checks
point ephemeral.key         > "$OUT/dh-public-key.bin"     # DHpublickey [V2G2-819]
scalar static.key           > "$OUT/receiver-key.bin"      # the receiver's static key

for f in envelope contract-key contract-public dh-public-key receiver-key; do
    printf '%-16s %s bytes\n' "$f" "$(wc -c < "$OUT/$f.bin" | tr -d ' ')"
done
