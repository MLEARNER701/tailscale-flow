#!/usr/bin/env python3
"""Generate a deterministic, fully synthetic tsflow.v1 trace for the demo page and the tests.

Nothing here comes from a real tailnet: machine names, DERP regions, byte counts and round-trip times are
made up. The scenario is 180 s between "desk" and "laptop":
  0-60 s    idle chatter over a DERP relay (no direct path yet)
  60-75 s   NAT traversal succeeds, path switches to a direct WAN connection
  75-130 s  a ~40 MB file copy from desk to laptop, plus a short burst back
  130-180 s idle again; two pings are lost along the way

Usage: python3 tools/make_synthetic_trace.py [--out demo/synthetic-trace.json] [--seconds 180] [--seed 7]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from flow_collector import PING_FIELDS, SAMPLE_FIELDS, SCHEMA, Srtt  # noqa: E402

START = 1767268800.0   # 2026-01-01T12:00:00Z, a fixed fictional start


def build(seconds=180, seed=7):
    rnd = random.Random(seed)
    rx = tx = 0
    pi = po = bi = bo = 0
    ui = uo = 0
    orx = otx = 0
    samples, pings = [], []
    hs = START - 40.0
    est = Srtt()
    switch_at = 60 + rnd.randint(4, 12)
    for i in range(seconds + 1):
        t = round(START + i, 2)
        path = "derp:fra" if i < switch_at else "direct:wan"
        # bytes this second, each direction
        up = rnd.randint(600, 2400)
        down = rnd.randint(500, 1800)
        if 75 <= i < 130:                       # file copy desk -> laptop
            up = int(rnd.gauss(740_000, 90_000))
            down = int(rnd.gauss(22_000, 4_000))  # ACKs
        if 104 <= i < 110:                      # short burst back
            down += int(rnd.gauss(260_000, 40_000))
        up, down = max(0, up), max(0, down)
        if i:
            tx += up
            rx += down
            p_out = max(1, round(up / rnd.uniform(1050, 1250)))
            p_in = max(1, round(down / rnd.uniform(180, 900)))
            po += p_out
            pi += p_in
            bo += up + 32 * p_out
            bi += down + 32 * p_in
            uo += max(0, p_out - rnd.randint(0, 2))
            ui += max(0, p_in - rnd.randint(0, 2))
        if i and i % 120 == 0:
            hs = t
        samples.append([t, rx, tx, pi, po, bi, bo, ui, uo, path, 1, 1, round(hs, 1), orx, otx])

        # one ping per second, answered a little later
        base = 170.0 if path.startswith("derp") else 68.0
        rtt = round(max(5.0, rnd.gauss(base, base * 0.06) + (35.0 if 75 <= i < 130 else 0.0)), 2)
        lost = i in (23, 141)
        if lost:
            srtt = round(est.srtt, 2) if est.srtt is not None else None
            var = round(est.rttvar, 2) if est.rttvar is not None else None
            pings.append([round(t + 0.05, 2), None, None, srtt, var])
        else:
            srtt, var = est.update(rtt)
            pings.append([round(t + 0.05, 2), rtt, path, srtt, var])

    return {
        "schema": SCHEMA, "mode": "trace", "synthetic": True, "generated_at": round(START + seconds + 1, 2),
        "every_s": 1.0, "ping_every_s": 1.0,
        "meta": {"backend_state": "Running", "tailscale_version": None,
                 "self": {"name": "desk", "os": "macOS", "home_derp": "ams", "form": "desktop"},
                 "peer": {"name": "laptop", "host": "laptop", "os": "macOS", "home_derp": "fra", "found": True,
                          "form": "laptop"},
                 "iface": "utun4"},
        "sample_fields": SAMPLE_FIELDS, "ping_fields": PING_FIELDS,
        "samples": samples, "pings": pings, "errors": {},
        "recorded": {"started_at": START, "seconds": seconds, "host_tz": "+0000"},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join("demo", "synthetic-trace.json"))
    ap.add_argument("--seconds", type=int, default=180)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args(argv)
    doc = build(a.seconds, a.seed)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"))
        fh.write("\n")
    print("wrote %s: %d samples, %d pings" % (a.out, len(doc["samples"]), len(doc["pings"])))


if __name__ == "__main__":
    main()
