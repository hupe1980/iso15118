#!/bin/sh
# Every row of the Josev matrix, inside one container: a veth pair is the link,
# Josev plays one end and `v2g_node` the other. Prints one line
# `INTEROP-REPORT <json array>` at the end, which `tests/josev.rs` reads.
#
# A row passes only if both ends say so: our node's own verdict (a normal close
# after SessionStop) and Josev's log (it decoded the SessionStop exchange and
# logged no traceback, decoding error or FAILED code).

set -u
PEER_VERSION=0.31.2
DEADLINE_MS=${DEADLINE_MS:-45000}
EXAMPLES=/usr/local/lib/python3.11/site-packages/iso15118/shared/examples/evcc
OUT=/tmp/rows
mkdir -p "$OUT"
export LOG_LEVEL=INFO

ip link add v0 type veth peer name v1 && ip link set v0 up && ip link set v1 up
# Duplicate address detection holds a fresh link-local address for a moment.
tries=0
until ip -6 addr show dev v0 | grep -q 'inet6 fe80' && ip -6 addr show dev v1 | grep -q 'inet6 fe80' \
    && ! ip -6 addr show tentative | grep -q fe80; do
  tries=$((tries + 1))
  if [ "$tries" -gt 50 ]; then break; fi
  sleep 0.1
done

no_ipv6() { ! ip -6 addr show dev v0 | grep -q 'inet6 fe80'; }

# $1 role, $2 generation, $3 service, $4 our row json file, $5 josev log, $6 josev marker
assemble() {
  python3 -I - "$@" <<'PY'
import json, sys
role, gen, svc, ours_path, log_path, marker = sys.argv[1:7]
row = {"peer": "josev", "peer_version": "0.31.2", "role": role, "generation": gen,
       "service": svc, "auth": "eim", "tls": False, "messages": 0, "elapsed_ms": 0}
try:
    lines = [l for l in open(ours_path).read().splitlines() if l.startswith("{")]
    ours = json.loads(lines[-1])
except Exception as e:
    ours = {"outcome": "fail", "reason": f"our node printed no row ({e})"}
row.update({k: ours.get(k) for k in ("messages", "elapsed_ms", "last_request") if k in ours})
try:
    log = open(log_path, errors="replace").read()
except Exception:
    log = None
theirs = None
if log is None:
    theirs = "Josev's log could not be read"
else:
    decoded = [l for l in log.splitlines() if "Decoded message" in l]
    for bad in ("Traceback", "EXIDecodingError", "FAILED"):
        if bad in log:
            hit = next(l for l in log.splitlines() if bad in l)
            theirs = f"Josev: {hit.strip()[:200]}"
            break
    if theirs is None and not any(marker in l for l in decoded):
        theirs = f"Josev never decoded {marker}"
if ours.get("outcome") == "pass" and theirs is None:
    row.update(outcome="pass", reason=None)
else:
    reasons = [r for r in (ours.get("reason"), theirs) if r]
    row.update(outcome="fail", reason="; ".join(reasons) or "unknown")
print(json.dumps(row))
PY
}

skip_row() {
  printf '{"peer":"josev","peer_version":"%s","role":"%s","generation":"%s","service":"%s","auth":"eim","tls":false,"outcome":"skip","reason":"%s","messages":0,"elapsed_ms":0}\n' \
    "$PEER_VERSION" "$1" "$2" "$3" "$4"
}

# Our vehicle, Josev's station.
evcc_row() {
  gen=$1; svc=$2; n="evcc-$gen-$svc"
  if no_ipv6; then skip_row evcc "$gen" "$svc" "no IPv6 link-local on veth" > "$OUT/$n.json"; return; fi
  NETWORK_INTERFACE=v0 timeout 60 python3 -m iso15118.secc.main > "$OUT/$n.josev.log" 2>&1 &
  josev=$!
  timeout 60 v2g_node evcc --iface v1 --generation "$gen" --service "$svc" \
    --deadline-ms "$DEADLINE_MS" > "$OUT/$n.ours" 2> "$OUT/$n.ours.log"
  sleep 1
  kill "$josev" 2>/dev/null; wait "$josev" 2>/dev/null
  assemble evcc "$gen" "$svc" "$OUT/$n.ours" "$OUT/$n.josev.log" SessionStopReq > "$OUT/$n.json"
}

# Josev's vehicle, our station.
secc_row() {
  gen=$1; svc=$2; config=$3; n="secc-$gen-$svc"
  if no_ipv6; then skip_row secc "$gen" "$svc" "no IPv6 link-local on veth" > "$OUT/$n.json"; return; fi
  python3 -I - "$EXAMPLES/$config" > "$OUT/$n.config.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c["useTls"] = False
print(json.dumps(c))
PY
  timeout 60 v2g_node secc --iface v0 --generation "$gen" --service "$svc" \
    --deadline-ms "$DEADLINE_MS" > "$OUT/$n.ours" 2> "$OUT/$n.ours.log" &
  ours=$!
  sleep 0.5
  # Josev's vehicle does not exit when its SDP retries run out, so `timeout`
  # is what bounds it.
  EVCC_CONFIG_PATH="$OUT/$n.config.json" NETWORK_INTERFACE=v1 \
    timeout 60 python3 -m iso15118.evcc.main > "$OUT/$n.josev.log" 2>&1
  wait "$ours"
  assemble secc "$gen" "$svc" "$OUT/$n.ours" "$OUT/$n.josev.log" SessionStopRes > "$OUT/$n.json"
}

evcc_row iso2 dc
evcc_row iso2 ac
evcc_row iso20 dc
evcc_row iso20 ac
secc_row iso2 dc iso15118_2/evcc_config_eim_dc.json
secc_row iso2 ac iso15118_2/evcc_config_eim_ac.json
secc_row iso20 dc iso15118_20/evcc_config_dc.json
secc_row iso20 ac iso15118_20/evcc_config_ac.json

# The logs of every row that did not pass, for reading it back.
for f in "$OUT"/*.json; do
  case "$f" in *config.json) continue ;; esac
  if ! grep -q '"outcome": "pass"' "$f" && ! grep -q '"outcome":"skip"' "$f"; then
    n=$(basename "$f" .json)
    echo "===== $n: ours"; tail -n 40 "$OUT/$n.ours.log" 2>/dev/null
    echo "===== $n: josev"; grep -E 'Decoded message|Message to encode|ERROR|Traceback|Error|FAILED' "$OUT/$n.josev.log" 2>/dev/null | cut -c1-400 | tail -n 25
  fi
done

printf 'INTEROP-REPORT ['
first=1
for f in "$OUT"/evcc-*.json "$OUT"/secc-*.json; do
  case "$f" in *config.json) continue ;; esac
  [ -f "$f" ] || continue
  if [ $first -eq 1 ]; then first=0; else printf ','; fi
  tr -d '\n' < "$f"
done
printf ']\n'
