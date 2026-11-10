#!/bin/sh
# A TPM nobody here wrote imports the contract key this crate seals.
#
# ISO 15118-20 §7.9.2.5.3: an SA encrypts the contract key for a vehicle's
# TPM 2.0 as an outer duplication wrapper under its storage key, and the vehicle
# imports it with TPM2_Import. Here `swtpm` (libtpms) plays the vehicle's TPM in
# a Debian container: it creates a Table 19 storage key, `examples/tpm_seal.rs`
# seals a contract key for it, the TPM imports and loads the result, signs with
# it, and the signature is verified on the host under the contract public key —
# once without a policy and once with one (PolicyAuthValue) [V2G20-2517].
#
# Local, like the other differential scripts: needs Docker and python3 with
# `cryptography`.
set -eu
BASE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
NAME="iso15118-tpm-$$"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

docker run -d --name "$NAME" -v "$WORK:/w" -w /w debian:trixie-slim sleep infinity >/dev/null
docker exec "$NAME" sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq swtpm swtpm-tools tpm2-tools >/dev/null 2>&1'
docker exec "$NAME" swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
    --tpmstate dir=/tmp --flags not-need-init,startup-clear --daemon
sleep 1
# No resource manager: flush transient objects after every command.
tpm() {
    docker exec -e TPM2TOOLS_TCTI=swtpm:port=2321 "$NAME" "$@" >/dev/null
    docker exec -e TPM2TOOLS_TCTI=swtpm:port=2321 "$NAME" tpm2_flushcontext -t >/dev/null
}
PARENT=0x81000001

# The vehicle's storage key, Table 19.
tpm tpm2_createprimary -C o -G ecc521:aes256cfb -g sha512 \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt' -c parent.ctx
tpm tpm2_evictcontrol -C o -c parent.ctx "$PARENT"
tpm tpm2_readpublic -c "$PARENT" -o parent.pub
# TPM2B_PUBLIC ends with unique: TPM2B x (66), TPM2B y (66).
STORAGE=$(python3 -I -c 'import sys; d=open(sys.argv[1],"rb").read(); print((d[-134:-68]+d[-66:]).hex())' "$WORK/parent.pub")
printf 'ISO 15118-20 contract key in a TPM' > "$WORK/message"

run() { # case [policy hex]
    case_dir="$1"
    cargo run -q --manifest-path "$BASE/Cargo.toml" --example tpm_seal --features pnc-rustcrypto -- \
        "$STORAGE" "$WORK/$case_dir" ${2:-}
    tpm tpm2_import -C "$PARENT" -G ecc -u "$case_dir/object.pub" -i "$case_dir/duplicate.priv" \
        -s "$case_dir/seed.dat" -r "$case_dir/key.priv"
    tpm tpm2_load -C "$PARENT" -u "$case_dir/object.pub" -r "$case_dir/key.priv" -c "$case_dir/key.ctx"
    if [ -n "${2:-}" ]; then
        tpm tpm2_startauthsession --policy-session -S "$case_dir/session.ctx" -g sha512
        tpm tpm2_policyauthvalue -S "$case_dir/session.ctx"
        tpm tpm2_sign -c "$case_dir/key.ctx" -p "session:$case_dir/session.ctx" -g sha512 -s ecdsa \
            -f plain -o "$case_dir/signature" message
        tpm tpm2_flushcontext "$case_dir/session.ctx"
    else
        tpm tpm2_sign -c "$case_dir/key.ctx" -g sha512 -s ecdsa -f plain -o "$case_dir/signature" message
    fi
    python3 -I - "$WORK/$case_dir" "$WORK/message" <<'PY'
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
d, msg = sys.argv[1], open(sys.argv[2], "rb").read()
key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP521R1(), open(d + "/contract.pub", "rb").read())
sig = open(d + "/signature", "rb").read()
if sig[0] != 0x30:  # raw r ‖ s
    sig = utils.encode_dss_signature(int.from_bytes(sig[:66], "big"), int.from_bytes(sig[66:], "big"))
key.verify(sig, msg, ec.ECDSA(hashes.SHA512()))
PY
    echo "ok: the TPM imported the sealed key ($case_dir) and its signature verifies"
}

run no-policy
tpm tpm2_startauthsession -S trial.ctx -g sha512
tpm tpm2_policyauthvalue -S trial.ctx -L policy.digest
tpm tpm2_flushcontext trial.ctx
run policy "$(python3 -I -c 'import sys; print(open(sys.argv[1],"rb").read().hex())' "$WORK/policy.digest")"
