#!/usr/bin/env python3
"""Extracts the TCP byte streams of a V2G capture, decrypting TLS where it can.

    extract_streams.py <capture.pcapng> <out-dir>

Writes `<out-dir>/<stream>.a.bin` and `<stream>.b.bin`: the two directions of
every TCP stream, in order, with TLS removed when the capture carries its own key
log. Which direction is the vehicle is not decided here — the replay test learns
it from who sends `supportedAppProtocolReq`.

dsV2Gshark's captures carry their key log as text in a UDP packet: TLS 1.2 as
`CLIENT_RANDOM` lines, TLS 1.3 as the four traffic-secret lines. Both are
collected, so one capture with both forms still decrypts.

TCP reassembly and TLS are `tshark`'s, deliberately: they are the transport,
which this crate leaves to its caller. What arrives at the test is what a caller
would hand the crate.
"""

import os
import subprocess
import sys
import tempfile

LABELS = (
    "CLIENT_RANDOM",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
)


def tshark(*args):
    return subprocess.run(
        ["tshark", *args], check=True, capture_output=True, text=True
    ).stdout


def key_log(capture):
    payloads = tshark("-r", capture, "-Y", "udp", "-T", "fields", "-e", "udp.payload")
    lines = []
    for hexed in payloads.split():
        try:
            text = bytes.fromhex(hexed).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        lines += [l.strip() for l in text.splitlines() if l.strip().startswith(LABELS)]
    return lines


def follow(capture, kind, stream, keylog):
    """`tshark -z follow,<kind>,raw,<n>` split into the two directions.

    In raw mode the first peer's segments are unindented hex lines and the
    second's are indented by a tab.
    """
    args = ["-r", capture, "-q", "-z", f"follow,{kind},raw,{stream}"]
    if keylog:
        args = ["-o", f"tls.keylog_file:{keylog}", *args]
    out = tshark(*args)
    a, b = bytearray(), bytearray()
    body = out.split("=" * 10)
    # Header block, then the data, then a closing rule.
    for line in out.splitlines():
        if not line or line.startswith(("=", "Follow:", "Filter:", "Node ")):
            continue
        target = b if line.startswith("\t") else a
        try:
            target += bytes.fromhex(line.strip())
        except ValueError:
            continue
    del body
    return bytes(a), bytes(b)


def main():
    capture, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    lines = key_log(capture)
    keylog = None
    if lines:
        handle = tempfile.NamedTemporaryFile("w", suffix=".keylog", delete=False)
        handle.write("\n".join(lines) + "\n")
        handle.close()
        keylog = handle.name
    streams = sorted(
        {int(s) for s in tshark("-r", capture, "-Y", "tcp.len > 0", "-T", "fields", "-e", "tcp.stream").split()}
    )
    tls_streams = {
        int(s)
        for s in tshark("-r", capture, "-Y", "tls", "-T", "fields", "-e", "tcp.stream").split()
    }
    written = 0
    for stream in streams:
        kind = "tls" if stream in tls_streams else "tcp"
        a, b = follow(capture, kind, stream, keylog)
        if not a and not b:
            continue
        with open(os.path.join(out_dir, f"{stream}.a.bin"), "wb") as f:
            f.write(a)
        with open(os.path.join(out_dir, f"{stream}.b.bin"), "wb") as f:
            f.write(b)
        written += 1
    if keylog:
        os.unlink(keylog)
    print(f"{os.path.basename(capture)}: {written} stream(s), "
          f"{len(tls_streams)} over TLS, {len(lines)} key-log line(s)")


if __name__ == "__main__":
    main()
