#!/bin/sh
# Mint the V2G certificate chains `tests/pki.rs` validates, with OpenSSL.
#
# The evidence question this answers is "does the parser agree with somebody
# else", and the honest answer here is a qualified one. These chains are minted
# by **OpenSSL**, which nobody in this workspace wrote, so a certificate this
# crate parses is one an independent implementation built to the same
# ASN.1 — and the profile fields (path length, key usage, basic constraints,
# domain components) come out where Annex F says they do or OpenSSL would not
# have put them there.
#
# A chain from a *published* V2G test pool is separate evidence:
# tests/pki_pool.rs validates Hubject's public openPlugnCharge archive, which
# needs no registration.
#
# The output is DER, checked in, and regenerating it is only necessary when the
# shape of a fixture changes: the validity windows are fixed dates, so the tests
# do not rot.
#
# Usage: scripts/make-test-pki.sh [base|amd1|all]   (default: all)
#
# Each set has its own keys, so minting one leaves the other's files
# byte-for-byte as they were: `base` is the -2 profile set, `amd1` the
# ISO 15118-20 Amd 1 rules (validity nesting, the 1 600-byte bound,
# cross-certification), written to tests/fixtures/pki/amd1/.
set -eu
SET="${1:-all}"
case "$SET" in base|amd1|all) ;; *) echo "usage: $0 [base|amd1|all]" >&2; exit 2 ;; esac

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$BASE_DIR/tests/fixtures/pki"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Every validity window is an **absolute** date rather than `-days N`, so the
# fixtures do not rot: a chain minted with `-days 90` stops validating ninety
# days after somebody ran this, and a test that fails on a Tuesday in March is
# worse than no test. `tests/pki.rs` names instants inside and outside these
# windows directly.
#
#   root, other root  2020-01-01 .. 2060-01-01   ([V2G2-011]: forty years)
#   sub 1, sub 2      2020-01-01 .. 2050-01-01
#   leaves            2020-01-01 .. 2050-01-01
#   expired leaf      2020-01-01 .. 2021-01-01   (for the validity-window test)
export OPENSSL_CONF=/dev/null
FROM=20200101000000Z
UNTIL_ROOT=20600101000000Z
UNTIL=20500101000000Z
EXPIRED=20210101000000Z

mkdir -p "$OUT"
cd "$WORK"

key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null; }

if [ "$SET" = base ] || [ "$SET" = all ]; then

# --- V2G Root (Table F.1): CA, keyCertSign, DC=V2G, no pathLen -------------
key root
cat > root.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
O = V2G Test Root Operator
CN = V2G Root CA
DC = V2G
[v3]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
openssl req -new -x509 -key root.key -config root.cnf -extensions v3 \
    -set_serial 1 -sha256 -not_before "$FROM" -not_after "$UNTIL_ROOT" -out root.pem 2>/dev/null

# --- CPO Sub-CA 1 (Table F.2): CA, pathLen 1 -------------------------------
key sub1
cat > sub1.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
O = V2G Test CPO
CN = CPO Sub-CA 1
[v3]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
openssl req -new -key sub1.key -config sub1.cnf -out sub1.csr 2>/dev/null
openssl x509 -req -in sub1.csr -CA root.pem -CAkey root.key -set_serial 2 \
    -extfile sub1.cnf -extensions v3 -sha256 -not_before "$FROM" -not_after "$UNTIL" \
    -out sub1.pem 2>/dev/null

# --- CPO Sub-CA 2 (Table F.2): CA, pathLen 0 -------------------------------
key sub2
cat > sub2.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
O = V2G Test CPO
CN = CPO Sub-CA 2
[v3]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
openssl req -new -key sub2.key -config sub2.cnf -out sub2.csr 2>/dev/null
openssl x509 -req -in sub2.csr -CA sub1.pem -CAkey sub1.key -set_serial 3 \
    -extfile sub2.cnf -extensions v3 -sha256 -not_before "$FROM" -not_after "$UNTIL" \
    -out sub2.pem 2>/dev/null

# --- SECC leaf (Table F.2): not a CA, digitalSignature, DC=CPO, CN=CPID ----
key secc
cat > secc.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
C = DE
O = V2G Test CPO
CN = DE*ABC*E00001
DC = CPO
[v3]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
openssl req -new -key secc.key -config secc.cnf -out secc.csr 2>/dev/null
openssl x509 -req -in secc.csr -CA sub2.pem -CAkey sub2.key -set_serial 4 \
    -extfile secc.cnf -extensions v3 -sha256 -not_before "$FROM" -not_after "$UNTIL" \
    -out secc.pem 2>/dev/null

# --- Contract leaf (Table F.4): digitalSignature + nonRepudiation, CN=EMAID
key contract
cat > contract.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
O = V2G Test Mobility Operator
CN = DE8AA1A2B3C4D5
[v3]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation,keyAgreement
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
openssl req -new -key contract.key -config contract.cnf -out contract.csr 2>/dev/null
openssl x509 -req -in contract.csr -CA sub2.pem -CAkey sub2.key -set_serial 5 \
    -extfile contract.cnf -extensions v3 -sha256 -not_before "$FROM" -not_after "$UNTIL" \
    -out contract.pem 2>/dev/null

# --- A leaf that asserts cA, which [V2G2-867] and every Annex F leaf row
#     forbid. Same key and issuer as the SECC leaf, so the only thing a test
#     can be failing on is the profile.
cat > rogue.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
C = DE
O = V2G Test CPO
CN = DE*ABC*E00002
DC = CPO
[v3]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign
subjectKeyIdentifier = hash
EOF
openssl req -new -key secc.key -config rogue.cnf -out rogue.csr 2>/dev/null
openssl x509 -req -in rogue.csr -CA sub2.pem -CAkey sub2.key -set_serial 6 \
    -extfile rogue.cnf -extensions v3 -sha256 -not_before "$FROM" -not_after "$UNTIL" \
    -out rogue.pem 2>/dev/null

# --- A decoy root: the same subject DN as the real one, a different key.
#     [V2G2-878] allows up to ten concurrently valid V2G Root Certificates for
#     one Root CA, so anchors that share a subject are the normal case during a
#     rollover — and an implementation that picks by name and then checks fails
#     every chain at every station on the day one is added.
key decoy
openssl req -new -x509 -key decoy.key -config root.cnf -extensions v3 \
    -set_serial 99 -sha256 -not_before "$FROM" -not_after "$UNTIL_ROOT" \
    -out decoy.pem 2>/dev/null

# --- A second, unrelated root, so "validates to the wrong anchor" has a
#     fixture. [V2G2-925].
key other
cat > other.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
O = Some Other Root Operator
CN = Unrelated Root CA
DC = V2G
[v3]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
openssl req -new -x509 -key other.key -config other.cnf -extensions v3 \
    -set_serial 7 -sha256 -not_before "$FROM" -not_after "$UNTIL_ROOT" -out other.pem 2>/dev/null

# --- An SECC leaf whose validity ended in 2021, so the window check has a
#     fixture rather than a clock trick. Same key, same issuer, same profile.
openssl x509 -req -in secc.csr -CA sub2.pem -CAkey sub2.key -set_serial 8 \
    -extfile secc.cnf -extensions v3 -sha256 -not_before "$FROM" -not_after "$EXPIRED" \
    -out expired.pem 2>/dev/null

# One generator, two consumers: `tests/pki.rs` validates these, and the
# `certificate` fuzz target seeds from them. Writing both here is what keeps them
# from drifting — a seed corpus that no longer parses is a fuzz run that spends
# its budget rediscovering the format.
SEEDS="$BASE_DIR/fuzz/seeds/certificate"
mkdir -p "$SEEDS"
for name in root sub1 sub2 secc contract rogue other expired decoy; do
    openssl x509 -in "$name.pem" -outform DER -out "$OUT/$name.der"
    cp "$OUT/$name.der" "$SEEDS/$name.der"
done

echo "wrote $(ls "$OUT"/*.der | wc -l | tr -d ' ') certificates to tests/fixtures/pki"
echo "and seeded fuzz/seeds/certificate from the same files"
fi

# --- ISO 15118-20 Amd 1 ------------------------------------------------------
#
# Its own roots and keys, so this set can be minted without touching the one
# above. Every window is absolute again:
#
#   root A, root B        2020-01-01 .. 2060-01-01
#   sub, leaves, cross    2020-01-01 .. 2050-01-01
#   outlives-sub leaf     2020-01-01 .. 2055-01-01   (past its sub-CA)
#   long sub-CA           2020-01-01 .. 2065-01-01   (past root A)
if [ "$SET" = amd1 ] || [ "$SET" = all ]; then
A1="$OUT/amd1"
mkdir -p "$A1" "$WORK/amd1"
cd "$WORK/amd1"
OUTLIVE=20550101000000Z
LONG=20650101000000Z

ca_cnf() { # file O CN [pathlen]
    pl=${4:+,pathlen:$4}
    printf '%s\n' "[req]" "distinguished_name = dn" "prompt = no" "[dn]" \
        "O = $2" "CN = $3" "[v3]" "basicConstraints = critical,CA:TRUE$pl" \
        "keyUsage = critical,keyCertSign,cRLSign" "subjectKeyIdentifier = hash" > "$1"
}
leaf_cnf() { # file CN [comment-bytes]
    printf '%s\n' "[req]" "distinguished_name = dn" "prompt = no" "[dn]" \
        "C = DE" "O = V2G Amd1 Test CPO" "CN = $2" "DC = CPO" "[v3]" \
        "basicConstraints = critical,CA:FALSE" "keyUsage = critical,digitalSignature" \
        "subjectKeyIdentifier = hash" > "$1"
    # A non-critical extension the parser skips, to make a certificate large
    # without changing anything the profile reads.
    if [ -n "${3:-}" ]; then
        printf 'nsComment = "%s"\n' "$(head -c "$3" /dev/zero | tr '\0' 'x')" >> "$1"
    fi
}
issue() { # name csr-config issuer-name serial not_after
    openssl req -new -key "$1.key" -config "$2" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -set_serial "$4" \
        -extfile "$2" -extensions v3 -sha256 -not_before "$FROM" -not_after "$5" \
        -out "$1.pem" 2>/dev/null
}

# Root A, and a nested chain under it.
key root-a; ca_cnf root-a.cnf "V2G Amd1 Root A" "Amd1 Root A"
openssl req -new -x509 -key root-a.key -config root-a.cnf -extensions v3 \
    -set_serial 101 -sha256 -not_before "$FROM" -not_after "$UNTIL_ROOT" -out root-a.pem 2>/dev/null
key sub; ca_cnf sub.cnf "V2G Amd1 Test CPO" "Amd1 Sub-CA" 0
issue sub sub.cnf root-a 102 "$UNTIL"
key leaf; leaf_cnf leaf.cnf "DE*AMD*E00001"
issue leaf leaf.cnf sub 103 "$UNTIL"

# A leaf that outlives its sub-CA: [V2G20-3000]/[V2G20-3001] under -20, fine under -2.
key outlives-sub; leaf_cnf outlives-sub.cnf "DE*AMD*E00002"
issue outlives-sub outlives-sub.cnf sub 104 "$OUTLIVE"

# A sub-CA that outlives root A, and a nested leaf under it: the failing link is
# the one to the anchor, which is where anchor *selection* has to apply the rule.
key long-sub; ca_cnf long-sub.cnf "V2G Amd1 Test CPO" "Amd1 Long Sub-CA" 0
issue long-sub long-sub.cnf root-a 105 "$LONG"
key under-long; leaf_cnf under-long.cnf "DE*AMD*E00003"
issue under-long under-long.cnf long-sub 106 "$UNTIL"

# A leaf over 1 600 bytes of DER, otherwise exactly like `leaf`.
key oversize; leaf_cnf oversize.cnf "DE*AMD*E00004" 1700
issue oversize oversize.cnf sub 107 "$UNTIL"

# Root B — another ecosystem — with its own chain, and a cross-certificate:
# root B's name and key, issued by root A (RFC 5280 §7.1). A side that holds
# only root A reaches B's leaves through it.
key root-b; ca_cnf root-b.cnf "V2G Amd1 Root B" "Amd1 Root B"
openssl req -new -x509 -key root-b.key -config root-b.cnf -extensions v3 \
    -set_serial 201 -sha256 -not_before "$FROM" -not_after "$UNTIL_ROOT" -out root-b.pem 2>/dev/null
key sub-b; ca_cnf sub-b.cnf "V2G Amd1 Test CPO B" "Amd1 Sub-CA B" 0
issue sub-b sub-b.cnf root-b 202 "$UNTIL"
key leaf-b; leaf_cnf leaf-b.cnf "DE*AMB*E00001"
issue leaf-b leaf-b.cnf sub-b 203 "$UNTIL"
cp root-b.key cross-b.key
issue cross-b root-b.cnf root-a 204 "$UNTIL"

for name in root-a sub leaf outlives-sub long-sub under-long oversize root-b sub-b leaf-b cross-b; do
    openssl x509 -in "$name.pem" -outform DER -out "$A1/$name.der"
done
echo "wrote $(ls "$A1"/*.der | wc -l | tr -d ' ') certificates to tests/fixtures/pki/amd1"
for name in leaf oversize cross-b; do
    printf '  %-10s %5s bytes\n' "$name" "$(wc -c < "$A1/$name.der" | tr -d ' ')"
done
fi
