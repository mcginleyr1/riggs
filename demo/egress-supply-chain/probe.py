#!/usr/bin/env python3
"""Probe the Riggs daemon's egress decision engine directly over its Unix socket.

This proves the *brain* of the differentiator — the per-process allow/deny
decision — without needing the macOS Network Extension loaded. It speaks the same
length-prefixed JSON protocol the riggs-filter extension uses:

    request:  [4-byte LE len][ {"EgressCheckFlow": {...}} ]
    response: [4-byte LE len][ {"EgressVerdict":   {...}} ]

Usage:
    probe.py <process_path> <hostname> [port]     # single check
    probe.py suite [candc_host]                    # canonical demo matrix

Exit code for single checks: 0 = allowed, 3 = denied, 2 = error.
"""
import json
import socket
import struct
import sys

SOCK = "/var/run/riggs.sock"


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("daemon closed the connection early")
        buf += chunk
    return buf


def check(process_path, hostname, port=443, remote_ip=""):
    req = {
        "EgressCheckFlow": {
            "pid": 0,
            "process_path": process_path,
            "remote_hostname": hostname,
            "remote_ip": remote_ip,
            "remote_port": int(port),
        }
    }
    payload = json.dumps(req).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect(SOCK)
        s.sendall(struct.pack("<I", len(payload)) + payload)
        (length,) = struct.unpack("<I", _recv_exact(s, 4))
        resp = json.loads(_recv_exact(s, length))
    finally:
        s.close()
    v = resp.get("EgressVerdict", {})
    return {
        "allow": bool(v.get("allow", True)),
        "would_block": bool(v.get("would_block", False)),
        "reason": v.get("reason") or "",
        "mode": v.get("mode", "?"),
    }


def _fmt(process_path, host, v):
    tag = "ALLOW" if v["allow"] else "DENY "
    proc = process_path.rsplit("/", 1)[-1]
    return f"  [{tag}] {proc:>6} -> {host:<24} ({v['mode']})  {v['reason']}"


def suite(candc):
    """Read-only matrix against whatever policy is currently loaded."""
    print(f"egress decision matrix (C&C stand-in = {candc})\n")
    rows = [
        ("/usr/local/bin/node", "registry.npmjs.org", "npm reaching its registry"),
        ("/usr/local/bin/node", candc, "npm's postinstall beaconing to C&C"),
        ("/usr/bin/curl", candc, "unrelated process reaching C&C"),
        ("/usr/bin/curl", "github.com", "unrelated process reaching a globally-allowed host"),
    ]
    for proc, host, desc in rows:
        try:
            v = check(proc, host)
        except Exception as e:  # noqa: BLE001
            print(f"  [ERR ] {proc} -> {host}: {e}")
            continue
        print(_fmt(proc, host, v))
        print(f"         ^ {desc}")
    print(
        f"\nThe money shot: run `riggs egress allow {candc}` then re-run.\n"
        f"`curl -> {candc}` flips to ALLOW, but `node -> {candc}` stays DENY —\n"
        "per-process confinement a network-layer ACL cannot do."
    )


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "suite":
        candc = argv[1] if len(argv) > 1 else "example.com"
        suite(candc)
        return 0
    if len(argv) < 2:
        print(__doc__)
        return 2
    process_path, hostname = argv[0], argv[1]
    port = argv[2] if len(argv) > 2 else 443
    try:
        v = check(process_path, hostname, port)
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(_fmt(process_path, hostname, v).strip())
    return 0 if v["allow"] else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
