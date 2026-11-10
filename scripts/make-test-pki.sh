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
# Usage: scripts/make-test-pki.sh [base|amd1|revocation|iso20-crypto|all]   (default: all)
#
# Each set has its own keys, so minting one leaves the other's files
# byte-for-byte as they were: `base` is the -2 profile set, `amd1` the
# ISO 15118-20 Amd 1 rules (validity nesting, the 1 600-byte bound,
# cross-certification), written to tests/fixtures/pki/amd1/; `revocation` the
# OCSP responses and CRLs, written to tests/fixtures/pki/revocation/;
# `iso20-crypto` the ISO 15118-20 envelopes and Ed448 material, written to
# tests/fixtures/pki/iso20-crypto/ (needs python3 with `cryptography`).
set -eu
SET="${1:-all}"
case "$SET" in base|amd1|revocation|iso20-crypto|all) ;; *) echo "usage: $0 [base|amd1|revocation|iso20-crypto|all]" >&2; exit 2 ;; esac

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
# ISO 15118-20 has no secp256r1 profile (Annex B): this set is secp521r1,
# signed with SHA-512 [V2G20-2473].
key() { openssl ecparam -name secp521r1 -genkey -noout -out "$1.key" 2>/dev/null; }
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
        -extfile "$2" -extensions v3 -sha512 -not_before "$FROM" -not_after "$5" \
        -out "$1.pem" 2>/dev/null
}

# Root A, and a nested chain under it.
key root-a; ca_cnf root-a.cnf "V2G Amd1 Root A" "Amd1 Root A"
openssl req -new -x509 -key root-a.key -config root-a.cnf -extensions v3 \
    -set_serial 101 -sha512 -not_before "$FROM" -not_after "$UNTIL_ROOT" -out root-a.pem 2>/dev/null
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
    -set_serial 201 -sha512 -not_before "$FROM" -not_after "$UNTIL_ROOT" -out root-b.pem 2>/dev/null
key sub-b; ca_cnf sub-b.cnf "V2G Amd1 Test CPO B" "Amd1 Sub-CA B" 0
issue sub-b sub-b.cnf root-b 202 "$UNTIL"
key leaf-b; leaf_cnf leaf-b.cnf "DE*AMB*E00001"
issue leaf-b leaf-b.cnf sub-b 203 "$UNTIL"
cp root-b.key cross-b.key
issue cross-b root-b.cnf root-a 204 "$UNTIL"

for name in root-a sub leaf outlives-sub long-sub under-long oversize root-b sub-b leaf-b cross-b; do
    openssl x509 -in "$name.pem" -outform DER -out "$A1/$name.der"
    cp "$A1/$name.der" "$BASE_DIR/fuzz/seeds/certificate/amd1-$name.der"
done
echo "wrote $(ls "$A1"/*.der | wc -l | tr -d ' ') certificates to tests/fixtures/pki/amd1"
for name in leaf oversize cross-b; do
    printf '  %-10s %5s bytes\n' "$name" "$(wc -c < "$A1/$name.der" | tr -d ' ')"
done
fi

# --- Revocation evidence: OCSP responses and CRLs ----------------------------
#
# OpenSSL is the responder and the CRL issuer, so every response and list the
# tests read is bytes somebody else's implementation built from RFC 6960 and
# RFC 5280. Three PKIs, each with its own keys:
#
#   r2/   P-256, ISO 15118-2: V2G root, CPO Sub-CA 1, Sub-CA 2, SECC leaf,
#         contract leaf, a delegated OCSP signer under each CA, and a rogue
#         signer without id-kp-OCSPSigning
#   r20/  P-521, ISO 15118-20: the same shape, signed with SHA-512
#   pe/   P-521, a private environment: PE root, PE Sub-CA, PE leaf
#
# Certificates and CRLs carry absolute dates (2020..2050; CRLs 2025..2035).
# `openssl ocsp` stamps thisUpdate with the time it runs and has no option to
# set it, so OCSP responses cannot; the script records that instant in
# `minted-at` (Unix seconds) and the tests derive "now" from it.
if [ "$SET" = revocation ] || [ "$SET" = all ]; then
RV="$OUT/revocation"
rm -rf "$RV"
mkdir -p "$RV/r2" "$RV/r20" "$RV/pe" "$WORK/rv"
cd "$WORK/rv"
CRL_FROM=20250101000000Z
CRL_UNTIL=20350101000000Z
STALE_UNTIL=20240101000000Z

rv_ca() { # file O CN DC|- [pathlen]
    pl=${5:+,pathlen:$5}
    {
        printf '%s\n' "[req]" "distinguished_name = dn" "prompt = no" "[dn]" "O = $2" "CN = $3"
        [ "$4" = - ] || printf 'DC = %s\n' "$4"
        printf '%s\n' "[v3]" "basicConstraints = critical,CA:TRUE$pl" \
            "keyUsage = critical,keyCertSign,cRLSign" "subjectKeyIdentifier = hash"
    } > "$1"
}
rv_leaf() { # file CN DC|- keyUsage
    {
        printf '%s\n' "[req]" "distinguished_name = dn" "prompt = no" "[dn]" "O = V2G Revocation Test" "CN = $2"
        [ "$3" = - ] || printf 'DC = %s\n' "$3"
        printf '%s\n' "[v3]" "basicConstraints = critical,CA:FALSE" "keyUsage = critical,$4" \
            "subjectKeyIdentifier = hash" "authorityKeyIdentifier = keyid"
    } > "$1"
}
rv_signer() { # file CN [eku]
    {
        printf '%s\n' "[req]" "distinguished_name = dn" "prompt = no" "[dn]" "O = V2G Revocation Test" "CN = $2"
        printf '%s\n' "[v3]" "basicConstraints = critical,CA:FALSE" "keyUsage = critical,digitalSignature" \
            "subjectKeyIdentifier = hash" "authorityKeyIdentifier = keyid"
        [ -z "${3:-}" ] || printf '%s\n' "extendedKeyUsage = OCSPSigning" "noCheck = ignored"
    } > "$1"
}
rv_key() { openssl ecparam -name "$CURVE" -genkey -noout -out "$1.key" 2>/dev/null; }
rv_root() { # name cnf serial
    openssl req -new -x509 -key "$1.key" -config "$2" -extensions v3 -set_serial "$3" \
        -"$MD" -not_before "$FROM" -not_after "$UNTIL_ROOT" -out "$1.pem" 2>/dev/null
}
rv_issue() { # name cnf issuer serial
    openssl req -new -key "$1.key" -config "$2" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -set_serial "$4" \
        -extfile "$2" -extensions v3 -"$MD" -not_before "$FROM" -not_after "$UNTIL" \
        -out "$1.pem" 2>/dev/null
}
# An OpenSSL `ca` database for one issuer: `index-<ca>.txt`, revoked entries
# added by rv_revoke.
rv_db() { : > "index-$1.txt"; echo 01 > "crlnumber-$1"; }
rv_revoke() { # ca cert reason
    serial=$(openssl x509 -in "$2.pem" -noout -serial | cut -d= -f2)
    subj=$(openssl x509 -in "$2.pem" -noout -subject -nameopt compat | sed 's/^subject=//')
    printf 'R\t500101000000Z\t250601000000Z,%s\t%s\tunknown\t%s\n' "$3" "$serial" "$subj" >> "index-$1.txt"
}
rv_valid() { # ca cert
    serial=$(openssl x509 -in "$2.pem" -noout -serial | cut -d= -f2)
    subj=$(openssl x509 -in "$2.pem" -noout -subject -nameopt compat | sed 's/^subject=//')
    printf 'V\t500101000000Z\t\t%s\tunknown\t%s\n' "$serial" "$subj" >> "index-$1.txt"
}
# rv_ocsp out issuer cert signer index days [extra openssl ocsp flags...]
rv_ocsp() {
    out=$1 issuer=$2 cert=$3 signer=$4 index=$5 days=$6; shift 6
    # Extra flags first: OpenSSL wants a CertID digest before -cert.
    openssl ocsp "$@" -index "index-$index.txt" -CA "$issuer.pem" -issuer "$issuer.pem" \
        -cert "$cert.pem" -rsigner "$signer.pem" -rkey "$signer.key" -rmd "$MD" -ndays "$days" \
        -no_nonce -respout "$DEST/$out.der" > /dev/null 2>&1 || true
    [ -s "$DEST/$out.der" ] || { echo "openssl ocsp failed for $out" >&2; exit 1; }
}
# rv_crl out ca next_update [with-number]
rv_crl() {
    out=$1 ca=$2 next=$3 numbered=${4:-yes}
    {
        printf '%s\n' "[ca]" "default_ca = c" "[c]" "database = index-$ca.txt" \
            "certificate = $ca.pem" "private_key = $ca.key" "default_md = $MD" \
            "default_crl_days = 1"
        # Without `crlnumber` OpenSSL omits the CRLNumber extension, which is
        # what the unnumbered fixture is for.
        if [ "$numbered" = yes ]; then printf 'crlnumber = crlnumber-%s\n' "$ca"; fi
        printf '%s\n' "[ext]" "authorityKeyIdentifier = keyid"
    } > "crl-$out.cnf"
    openssl ca -config "crl-$out.cnf" -gencrl -crlexts ext -crl_lastupdate "$CRL_FROM" \
        -crl_nextupdate "$next" -out "$out.pem" > /dev/null 2>&1
    openssl crl -in "$out.pem" -outform DER -out "$DEST/$out.der"
}

date -u +%s > "$RV/minted-at"

# -- r2: P-256 / SHA-256 -----------------------------------------------------
CURVE=prime256v1 MD=sha256 DEST="$RV/r2"
rv_key root;  rv_ca root.cnf "V2G Revocation Root Operator" "V2G Root CA" V2G; rv_root root root.cnf 1
rv_key sub1;  rv_ca sub1.cnf "V2G Revocation CPO" "CPO Sub-CA 1" - 1; rv_issue sub1 sub1.cnf root 2
rv_key sub2;  rv_ca sub2.cnf "V2G Revocation CPO" "CPO Sub-CA 2" - 0; rv_issue sub2 sub2.cnf sub1 3
rv_key secc;  rv_leaf secc.cnf "DE*REV*E00001" CPO digitalSignature; rv_issue secc secc.cnf sub2 4
rv_key contract; rv_leaf contract.cnf "DE8AARV0000001" - digitalSignature,nonRepudiation
rv_issue contract contract.cnf sub2 5
rv_key ocsp-root; rv_signer ocsp-root.cnf "OCSP Signer for Root" eku; rv_issue ocsp-root ocsp-root.cnf root 6
rv_key ocsp-sub1; rv_signer ocsp-sub1.cnf "OCSP Signer for Sub-CA 1" eku; rv_issue ocsp-sub1 ocsp-sub1.cnf sub1 7
rv_key rogue-sub1; rv_signer rogue-sub1.cnf "Not an OCSP Signer"; rv_issue rogue-sub1 rogue-sub1.cnf sub1 8
for c in root sub1 sub2; do rv_db "$c"; done
rv_valid root sub1; rv_valid sub1 sub2; rv_valid sub2 secc
: > index-sub1-revoked.txt; rv_revoke sub1-revoked sub2 keyCompromise
: > index-sub1-unknown.txt
# Sub-CA 1 answered by the root itself, without certs: the signature is the
# response's last bytes, which the bad-signature test flips.
rv_ocsp sub1-good root sub1 root root 7 -resp_no_certs
rv_ocsp sub2-good sub1 sub2 ocsp-sub1 sub1 7
rv_ocsp sub2-good-sha256-bykey sub1 sub2 ocsp-sub1 sub1 7 -sha256 -resp_key_id
rv_ocsp sub2-revoked sub1 sub2 ocsp-sub1 sub1-revoked 7
rv_ocsp sub2-unknown sub1 sub2 ocsp-sub1 sub1-unknown 7
rv_ocsp sub2-rogue sub1 sub2 rogue-sub1 sub1 7
rv_ocsp sub2-29days sub1 sub2 ocsp-sub1 sub1 29
rv_ocsp sub2-28days sub1 sub2 ocsp-sub1 sub1 28
# CRLs from Sub-CA 2 (about the leaves) and Sub-CA 1 (about Sub-CA 2).
rv_crl crl-sub2-empty sub2 "$CRL_UNTIL"
rv_revoke sub2 contract keyCompromise
rv_crl crl-sub2-contract sub2 "$CRL_UNTIL"
rv_crl crl-sub2-stale sub2 "$STALE_UNTIL"
rv_crl crl-sub2-unnumbered sub2 "$CRL_UNTIL" no
: > index-sub1.txt; rv_revoke sub1 sub2 cACompromise
rv_crl crl-sub1-sub2 sub1 "$CRL_UNTIL"
for n in root sub1 sub2 secc contract ocsp-root ocsp-sub1 rogue-sub1; do
    openssl x509 -in "$n.pem" -outform DER -out "$DEST/$n.der"
done

# -- r20: P-521 / SHA-512 ----------------------------------------------------
cd "$WORK" && rm -rf rv20 && mkdir rv20 && cd rv20
CURVE=secp521r1 MD=sha512 DEST="$RV/r20"
rv_key root;  rv_ca root.cnf "V2G20 Revocation Root Operator" "V2G Root CA 20" V2G; rv_root root root.cnf 21
rv_key sub1;  rv_ca sub1.cnf "V2G20 Revocation CPO" "CPO Sub-CA 1 (20)" - 1; rv_issue sub1 sub1.cnf root 22
rv_key sub2;  rv_ca sub2.cnf "V2G20 Revocation CPO" "CPO Sub-CA 2 (20)" - 0; rv_issue sub2 sub2.cnf sub1 23
rv_key secc;  rv_leaf secc.cnf "DE*REV*E00020" CPO digitalSignature; rv_issue secc secc.cnf sub2 24
rv_key ocsp-sub2; rv_signer ocsp-sub2.cnf "OCSP Signer for Sub-CA 2 (20)" eku; rv_issue ocsp-sub2 ocsp-sub2.cnf sub2 25
for c in root sub1 sub2; do rv_db "$c"; done
rv_valid root sub1; rv_valid sub1 sub2; rv_valid sub2 secc
: > index-sub2-revoked.txt; rv_revoke sub2-revoked secc keyCompromise
rv_ocsp sub1-good root sub1 root root 7
rv_ocsp sub2-good sub1 sub2 sub1 sub1 7
rv_ocsp secc-good sub2 secc ocsp-sub2 sub2 7
rv_ocsp secc-revoked sub2 secc ocsp-sub2 sub2-revoked 7
rv_ocsp secc-8days sub2 secc ocsp-sub2 sub2 8
for n in root sub1 sub2 secc ocsp-sub2; do
    openssl x509 -in "$n.pem" -outform DER -out "$DEST/$n.der"
done

# -- pe: a private environment, P-521 ----------------------------------------
cd "$WORK" && rm -rf rvpe && mkdir rvpe && cd rvpe
CURVE=secp521r1 MD=sha512 DEST="$RV/pe"
rv_key root; rv_ca root.cnf "PE Test Operator" "PE Private Root" - 1; rv_root root root.cnf 31
rv_key sub;  rv_ca sub.cnf "PE Test Operator" "PE Sub-CA" - 0; rv_issue sub sub.cnf root 32
rv_key leaf; rv_leaf leaf.cnf "DE*PEV*E00001" CPO digitalSignature; rv_issue leaf leaf.cnf sub 33
for c in root sub; do rv_db "$c"; done
rv_valid root sub; rv_valid sub leaf
rv_ocsp sub-good root sub root root 7
rv_ocsp leaf-good sub leaf sub sub 7
for n in root sub leaf; do
    openssl x509 -in "$n.pem" -outform DER -out "$DEST/$n.der"
done

echo "wrote $(find "$RV" -name '*.der' | wc -l | tr -d ' ') revocation fixtures to tests/fixtures/pki/revocation (minted at $(cat "$RV/minted-at"))"
fi

# --- ISO 15118-20 cryptography: envelopes, Ed448, Annex B ----------------------
#
# scripts/lib/iso20_crypto.py seals SECP521_EncryptedPrivateKey and
# X448_EncryptedPrivateKey and signs an Ed448 vector with `cryptography`
# (OpenSSL-backed), every input fixed. OpenSSL then mints an Ed448 chain, an
# Ed448 OEM provisioning certificate carrying the X448 key as
# subjectAltPublicKeyInfo (Annex B.7.2), and a secp521r1 leaf with an extension
# Annex B does not name [V2G20-2323].
if [ "$SET" = iso20-crypto ] || [ "$SET" = all ]; then
I20="$OUT/iso20-crypto"
rm -rf "$I20"
mkdir -p "$I20" "$WORK/i20"
python3 -I "$BASE_DIR/scripts/lib/iso20_crypto.py" "$I20"
cd "$WORK/i20"

ed_key() { openssl genpkey -algorithm ED448 -out "$1.key" 2>/dev/null; }
ed_root() { # name cnf serial
    openssl req -new -x509 -key "$1.key" -config "$2" -extensions v3 -set_serial "$3" \
        -not_before "$FROM" -not_after "$UNTIL_ROOT" -out "$1.pem" 2>/dev/null
}
ed_issue() { # name cnf issuer serial
    openssl req -new -key "$1.key" -config "$2" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -set_serial "$4" \
        -extfile "$2" -extensions v3 -not_before "$FROM" -not_after "$UNTIL" -out "$1.pem" 2>/dev/null
}
cnf() { # file CN DC|- basicConstraints keyUsage [extra line]
    {
        printf '%s\n' "[req]" "distinguished_name = dn" "prompt = no" "[dn]" "O = V2G20 Ed448 Test" "CN = $2"
        [ "$3" = - ] || printf 'DC = %s\n' "$3"
        printf '%s\n' "[v3]" "basicConstraints = critical,$4" "keyUsage = critical,$5" "subjectKeyIdentifier = hash"
        [ -z "${6:-}" ] || printf '%s\n' "$6"
    } > "$1"
}

ed_key root; cnf root.cnf "V2G Root CA Ed448" V2G "CA:TRUE" "keyCertSign,cRLSign"; ed_root root root.cnf 41
ed_key sub1; cnf sub1.cnf "CPO Sub-CA 1 Ed448" - "CA:TRUE,pathlen:1" "keyCertSign,cRLSign"; ed_issue sub1 sub1.cnf root 42
ed_key sub2; cnf sub2.cnf "CPO Sub-CA 2 Ed448" - "CA:TRUE,pathlen:0" "keyCertSign,cRLSign"; ed_issue sub2 sub2.cnf sub1 43
ed_key secc; cnf secc.cnf "DE*E44*E00001" CPO "CA:FALSE" "digitalSignature"; ed_issue secc secc.cnf sub2 44
# subjectAltPublicKeyInfo ::= SEQUENCE { SEQUENCE { id-X448 }, BIT STRING } — 68 bytes.
ALT=$(printf '3042300506032b656f033900%s' "$(od -An -tx1 -v "$I20/x448-oem-public.bin" | tr -d ' \n')")
ed_key oem; cnf oem.cnf "WMIV1234567890ABC1" - "CA:FALSE" "digitalSignature,keyAgreement" "2.5.29.72 = critical,DER:$ALT"
ed_issue oem oem.cnf sub2 45
for n in root sub1 sub2 secc oem; do openssl x509 -in "$n.pem" -outform DER -out "$I20/ed448-$n.der"; done

# A secp521r1 OEM provisioning certificate carrying TPM information in
# SubjectInfoAccess [V2G20-2594]–[V2G20-2596]: the storage key (X ‖ Y) and a
# policy digest, base64 in uniformResourceIdentifier.
B64KEY=$(base64 < "$I20/tpm-storage-key.bin" | tr -d '\n')
B64POL=$(base64 < "$I20/tpm-policy-digest.bin" | tr -d '\n')
openssl ecparam -name secp521r1 -genkey -noout -out tpmca.key 2>/dev/null
cnf tpmca.cnf "OEM Sub-CA 2 TPM" - "CA:TRUE,pathlen:0" "keyCertSign,cRLSign"
openssl req -new -x509 -key tpmca.key -config tpmca.cnf -extensions v3 -set_serial 61 -sha512 \
    -not_before "$FROM" -not_after "$UNTIL_ROOT" -out tpmca.pem 2>/dev/null
openssl ecparam -name secp521r1 -genkey -noout -out tpmoem.key 2>/dev/null
cnf tpmoem.cnf "WMIV1234567890ABC1" - "CA:FALSE" "digitalSignature,keyAgreement" \
    "subjectInfoAccess = 1.0.15118.20.0.4;URI:$B64KEY, 1.0.15118.20.0.5;URI:$B64POL"
openssl req -new -key tpmoem.key -config tpmoem.cnf -out tpmoem.csr 2>/dev/null
openssl x509 -req -in tpmoem.csr -CA tpmca.pem -CAkey tpmca.key -set_serial 62 -extfile tpmoem.cnf \
    -extensions v3 -sha512 -not_before "$FROM" -not_after "$UNTIL" -out tpmoem.pem 2>/dev/null
openssl x509 -in tpmoem.pem -outform DER -out "$I20/p521-tpm-oem.der"

# secp521r1, signed with SHA-512, one leaf carrying nsComment.
p5_key() { openssl ecparam -name secp521r1 -genkey -noout -out "$1.key" 2>/dev/null; }
p5_key proot; cnf proot.cnf "V2G Root CA P-521" V2G "CA:TRUE" "keyCertSign,cRLSign"
openssl req -new -x509 -key proot.key -config proot.cnf -extensions v3 -set_serial 51 -sha512 \
    -not_before "$FROM" -not_after "$UNTIL_ROOT" -out proot.pem 2>/dev/null
for n in plain commented; do
    extra=""; [ "$n" = commented ] && extra='nsComment = "not in Annex B"'
    p5_key "$n"; cnf "$n.cnf" "DE*P52*E0000${#n}" CPO "CA:FALSE" "digitalSignature" "$extra"
    openssl req -new -key "$n.key" -config "$n.cnf" -out "$n.csr" 2>/dev/null
    openssl x509 -req -in "$n.csr" -CA proot.pem -CAkey proot.key -set_serial "$((52 + ${#n}))" \
        -extfile "$n.cnf" -extensions v3 -sha512 -not_before "$FROM" -not_after "$UNTIL" -out "$n.pem" 2>/dev/null
done
for n in proot plain commented; do openssl x509 -in "$n.pem" -outform DER -out "$I20/p521-$n.der"; done
echo "wrote $(ls "$I20" | wc -l | tr -d ' ') ISO 15118-20 crypto fixtures to tests/fixtures/pki/iso20-crypto"
fi
