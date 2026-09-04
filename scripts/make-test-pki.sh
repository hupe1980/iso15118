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
# What it is not is a chain from a *published* V2G test pool. Hubject's and
# OPNC's pools need registration, so the strongest available claim stays "the
# Annex F profile is enforced against certificates a third implementation
# encoded", not "interoperable with the pools the field uses". See
# concepts/ROADMAP.md M6.
#
# The output is DER, checked in, and regenerating it is only necessary when the
# shape of a fixture changes: the validity windows are fixed dates, so the tests
# do not rot.
set -eu

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
openssl x509 -in secc.pem -noout -text | sed -n '1,24p'
