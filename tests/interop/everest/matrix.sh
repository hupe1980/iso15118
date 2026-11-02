#!/bin/sh
# Every row of the EVerest matrix, inside one container: a veth pair is the
# link, EVerest's SIL station listens on v0 (IsoMux, in front of EvseV2G and
# Evse15118D20) and `v2g_node evcc` is on v1. Prints one line
# `INTEROP-REPORT <json array>` at the end, which `tests/everest.rs` reads.
#
# A row passes only if both ends say so: our node's verdict (a normal close
# after SessionStop) and EVerest's log (it saw SessionStopReq, logged no ERRO
# from its ISO 15118 modules and no failed response code).

set -u
PEER_VERSION=2025.10.0
CERTS=/ext/dist/etc/everest/certs
# IsoMux in front of both stations; EvseV2G alone for Plug & Charge.
MUX=/ext/source/config/config-sil-dc-ours.yaml
DIRECT=/ext/source/config/config-sil-dc-pnc-ours.yaml
OUT=/tmp/rows
mkdir -p "$OUT"

ip link add v0 type veth peer name v1 && ip link set v0 up && ip link set v1 up
tries=0
until ip -6 addr show dev v1 | grep -q 'inet6 fe80' && ! ip -6 addr show tentative | grep -q fe80; do
  tries=$((tries + 1)); [ "$tries" -gt 50 ] && break; sleep 0.1
done
mosquitto -d

# The contract: EVerest's test MO leaf, its two sub-CAs issuer-first, the
# P-256 scalar out of the encrypted key, and the eMAID its subject names.
CONTRACT=/tmp/contract
mkdir -p "$CONTRACT"
cp "$CERTS/client/mo/MO_LEAF.der" "$CONTRACT/leaf.der"
cp "$CERTS/ca/mo/MO_SUB_CA2.der" "$CONTRACT/sub1.der"
cp "$CERTS/ca/mo/MO_SUB_CA1.der" "$CONTRACT/sub2.der"
openssl ec -in "$CERTS/client/mo/MO_LEAF.key" -passin "file:$CERTS/client/mo/MO_LEAF_PASSWORD.txt" \
  -no_public -outform DER 2>/dev/null > "$CONTRACT/key.der"
python3 -I -c 'import sys; d=open(sys.argv[1],"rb").read(); i=d.index(b"\x04\x20"); print(d[i+2:i+34].hex())' \
  "$CONTRACT/key.der" > "$CONTRACT/key.hex"
openssl x509 -in "$CERTS/client/mo/MO_LEAF.pem" -noout -subject -nameopt multiline \
  | sed -n 's/^ *commonName *= *//p' > "$CONTRACT/emaid.txt"

# $1 name, $2 generation, $3 extra v2g_node flags, $4 auth, $5 station config
row() {
  n=$1; gen=$2; flags=$3; auth=$4; config=$5
  if ! ip -6 addr show dev v1 | grep -q 'inet6 fe80'; then
    printf '{"peer":"everest","peer_version":"%s","role":"evcc","generation":"%s","service":"dc","auth":"%s","tls":%s,"outcome":"skip","reason":"no IPv6 link-local on veth","messages":0,"elapsed_ms":0}\n' \
      "$PEER_VERSION" "$gen" "$auth" "$( [ -n "$flags" ] && echo true || echo false )" > "$OUT/$n.json"
    return
  fi
  (cd /ext/build/run-scripts && LD_LIBRARY_PATH=/ext/dist/lib PATH=/ext/dist/bin:$PATH \
    exec timeout 150 manager --prefix /ext/dist --conf "$config") > "$OUT/$n.everest.log" 2>&1 &
  station=$!
  # A vehicle starts SDP once SLAC has matched, not before: IsoMux answers SDP
  # from start-up, but the station enables HLC only after the match.
  t=0; until grep -q "SLAC MATCHED" "$OUT/$n.everest.log" 2>/dev/null || [ $t -ge 600 ]; do
    sleep 0.2; t=$((t + 1)); done
  # shellcheck disable=SC2086
  timeout 120 v2g_node evcc --iface v1 --generation "$gen" --service dc --deadline-ms 110000 $flags \
    > "$OUT/$n.ours" 2> "$OUT/$n.ours.log"
  sleep 2
  # The station is a process tree whose modules rename themselves
  # (`iso_mux:IsoMux --prefix /ext/dist --module …`); the next row needs all of
  # it gone, or a stale IsoMux answers its SDP.
  kill "$station" 2>/dev/null; wait "$station" 2>/dev/null
  pkill -f -- "--prefix /ext/dist" 2>/dev/null
  t=0; while pgrep -f -- "--prefix /ext/dist" >/dev/null && [ $t -lt 50 ]; do
    sleep 0.2; t=$((t + 1)); done
  pkill -9 -f -- "--prefix /ext/dist" 2>/dev/null
  python3 -I - "$gen" "$auth" "$OUT/$n.ours" "$OUT/$n.everest.log" "$PEER_VERSION" > "$OUT/$n.json" <<'PY'
import json, re, sys
gen, auth, ours_path, log_path, version = sys.argv[1:6]
row = {"peer": "everest", "peer_version": version, "role": "evcc", "generation": gen,
       "service": "dc", "auth": auth, "tls": False, "messages": 0, "elapsed_ms": 0}
try:
    lines = [l for l in open(ours_path).read().splitlines() if l.startswith("{")]
    ours = json.loads(lines[-1])
except Exception as e:
    ours = {"outcome": "fail", "reason": f"our node printed no row ({e})"}
row.update({k: ours[k] for k in ("messages", "elapsed_ms", "last_request", "tls") if k in ours})
theirs = None
try:
    log = re.sub(r"\x1b\[[0-9;]*m", "", open(log_path, errors="replace").read())
except Exception:
    log = None
if log is None:
    theirs = "EVerest's log could not be read"
else:
    for line in log.splitlines():
        if "Failed response code" in line or (
            "[ERRO]" in line and any(m in line for m in ("iso15118_2:", "iso15118_20:", "iso_mux:"))
            and "cert_info" not in line
        ):
            theirs = "EVerest: " + line.split("::", 1)[-1].strip()[:200]
            break
    if theirs is None and "SessionStopReq" not in log:
        theirs = "EVerest never saw SessionStopReq"
if ours.get("outcome") == "pass" and theirs is None:
    row.update(outcome="pass", reason=None)
else:
    row.update(outcome="fail", reason="; ".join(r for r in (ours.get("reason"), theirs) if r) or "unknown")
print(json.dumps(row))
PY
}

TLS="--tls $CERTS/ca/v2g/V2G_ROOT_CA.pem --tls-name SECCCert"
row e1-iso2-tcp-eim iso2 "" eim "$MUX"
row e2-iso20-tcp-eim iso20 "" eim "$MUX"
row e3-iso2-tls-eim iso2 "$TLS" eim "$MUX"
row e4-iso2-tls-pnc iso2 "$TLS --contract $CONTRACT" pnc "$DIRECT"

for f in "$OUT"/*.json; do
  if ! grep -q '"outcome": "pass"' "$f" && ! grep -q '"outcome":"skip"' "$f"; then
    n=$(basename "$f" .json)
    echo "===== $n: ours"; tail -n 30 "$OUT/$n.ours.log" 2>/dev/null
    echo "===== $n: everest"
    sed 's/\x1b\[[0-9;]*m//g' "$OUT/$n.everest.log" 2>/dev/null \
      | grep -E 'ERRO|Failed response|CAR ISO|EVSE ISO' | cut -c28-300 | tail -n 25
  fi
done

printf 'INTEROP-REPORT ['
first=1
for f in "$OUT"/e*.json; do
  [ -f "$f" ] || continue
  if [ $first -eq 1 ]; then first=0; else printf ','; fi
  tr -d '\n' < "$f"
done
printf ']\n'
