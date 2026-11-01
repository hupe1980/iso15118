#!/bin/sh
# Replays V2G sessions real hardware recorded: decode, byte-identical re-encode,
# and Plug & Charge signature verification for every message.
#
# The corpus is dSPACE's dsV2Gshark example captures — a DS5366 bench driving
# Josev and RiseV2G — fetched at a pinned commit. Everything under its
# Wireshark/ directory is GPL-2.0, so the captures are kept in a gitignored
# directory (concepts/reference/captures, or $ISO15118_CAPTURES_SRC) and never
# committed. tshark reassembles each TCP stream and removes TLS with the key log
# every TLS capture carries; tests/captures.rs does the rest.
#
# Requirements, none of which CI has: network access (first run), tshark,
# python3. Exits 2 with the reason when one is missing — a replay that cannot
# run is not a pass.
set -eu

BASE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ISO15118_CAPTURES_SRC:-$BASE/concepts/reference/captures}"
WORK="${ISO15118_VERIFY_DIR:-${TMPDIR:-/tmp}/iso15118-captures}"
REPO=dspace-group/dsV2Gshark
# 2025-11-05, "add more pcaps": 16 captures, including the two ISO 15118-20 DC
# sessions over TLS 1.3 and mutual TLS.
COMMIT=0ec5d96e3c8c6a1631a43cbb184b2152228ba84b
CAPTURES="DIN_DC_DS5366_Josev.pcapng
IEC61851_AC_PWM_Basic.pcapng
ISO-20_BPT_AC_DS5366_Josev.pcapng
ISO-20_TLS13_DC_DS5366_Josev.pcapng
ISO-20_mTLS_DC_DS5366_Josev.pcapng
ISO-2_AC_DS5366.pcapng
ISO-2_AC_PnC_TLS_Contract_MeteringReceipt_DS5366_RiseV2G.pcapng
ISO-2_DC_BatteryDataExchange_DS5366_RiseV2G.pcapng
ISO-2_DC_DS5366.pcapng
ISO-2_DC_Pause_DS5366.pcapng
ISO-2_DC_PnC_TLS_CertInstallation_DS5366_RiseV2G.pcapng
ISO-2_DC_PnC_TLS_CertUpdate_DS5366_RiseV2G.pcapng
ISO-2_DC_PnC_TLS_Contract_DS5366_RiseV2G.pcapng
ISO-2_DC_Renegotiation_DS5366_RiseV2G.pcapng
ISO-2_DC_SalesTariffSchedule_DS5366_RiseV2G.pcapng
ISO-2_DC_multi_EVSE_SLAC_DS5366_Josev.pcapng"

for tool in tshark python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "skip: $tool not found — the replay did not run" >&2; exit 2; }
done

mkdir -p "$SRC"
for f in $CAPTURES; do
    [ -s "$SRC/$f" ] && continue
    echo "fetching $f"
    curl -sfSL -o "$SRC/$f.part" \
        "https://raw.githubusercontent.com/$REPO/$COMMIT/Wireshark/dsV2Gshark_examples/$f" ||
        { echo "skip: could not fetch $f — the replay did not run" >&2; rm -f "$SRC/$f.part"; exit 2; }
    mv "$SRC/$f.part" "$SRC/$f"
done

rm -rf "$WORK"
mkdir -p "$WORK"
for f in $CAPTURES; do
    python3 -I "$BASE/tools/extract_streams.py" "$SRC/$f" "$WORK/${f%.pcapng}"
done

out="$WORK/captures.out"
status=0
ISO15118_CAPTURES="$WORK" cargo test --manifest-path "$BASE/Cargo.toml" \
    --all-features --test captures -- --nocapture 2>&1 | tee "$out" || status=1
grep -q "test result: ok" "$out" || status=1

if [ "$status" -eq 0 ]; then
    n=$(sed -n 's/^total: \([0-9]*\) messages decoded.*/\1/p' "$out")
    . "$BASE/scripts/lib/claims.sh"
    claims_agree "$BASE" "$n messages decoded" || status=1
    g=$(grouped "$n")
    claims_say "$BASE" README.md "$g messages from captured" || status=1
    claims_say "$BASE" README.md "$g messages from sixteen" || status=1
    claims_say "$BASE" site/content/docs/verification.md "**$g** messages" || status=1
    claims_say "$BASE" site/content/docs/verification.md "$n real captured messages" || status=1
fi
exit "$status"
