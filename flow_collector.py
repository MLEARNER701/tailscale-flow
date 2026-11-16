#!/usr/bin/env python3
"""Tailscale flow collector: this machine <-> one tailnet peer. Read-only, stdlib only.

Produces the `tsflow.v1` JSON that tailscale-flow.html replays (embedded trace) or polls (?src=...).
It never changes Tailscale, launchd or the dashboard. It only runs:
  - `tailscale status --json`              -> per-peer RxBytes/TxBytes, path (direct / DERP region / peer relay),
                                              Online/Active, LastHandshake
  - `tailscale metrics print`              -> wire packets/bytes in/out summed over paths (ALL peers; includes
                                              traffic tailscaled serves itself, e.g. `tailscale serve`)
  - `netstat -ib -I <utun>`                -> OS tunnel interface packets (ALL peers; misses tailscaled-internal
                                              traffic such as `tailscale serve`, so it is lower than the wire count)
  - `tailscale ping -c 1 --timeout 3s P`   -> one disco round trip (separate thread, back-to-back, >= --ping-every)

Modes
  once                      print one snapshot (2 samples 1 s apart) as tsflow.v1 JSON
  record --seconds N --out F  sample every --every s for N s and write a trace file
  serve  --port P           127.0.0.1-only HTTP server: GET /flow.json[?since=<t>]; samples only while polled
                            (stops sampling after --idle s without a request)

Schema tsflow.v1 (all counters cumulative; the page derives rates from deltas; null = not observed):
  samples: [t, rx, tx, pi, po, bi, bo, ui, uo, path, online, active, hs, orx, otx]
     t        unix seconds (0.01)
     rx, tx   bytes received from / sent to the peer (tailscale status, this peer only)
     pi, po   wire packets in / out, all peers, all paths (tailscale metrics)
     bi, bo   wire bytes in / out, all peers, all paths (tailscale metrics)
     ui, uo   packets in / out on the OS utun interface (all peers)
     path     "direct:lan" | "direct:wan" | "derp:<region>" | "peer-relay" | "offline" | "none"
     online, active  0/1 from tailscale status
     hs       last WireGuard handshake (unix s) or null
     orx, otx bytes received from / sent to every OTHER peer (sum), to show how much of the wire count is this peer
  pings:   [t, rtt_ms|null(lost), via, srtt_ms, rttvar_ms]
     via      "derp:<region>" | "direct:lan" | "direct:wan" | "peer-relay" | null
     srtt/rttvar  RFC 6298 (alpha 1/8, beta 1/4); lost probes do not update (Karn)
Public IPs are never written: a direct endpoint is reduced to lan/wan. Tailnet IPs are not written either.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SCHEMA = "tsflow.v1"
SAMPLE_FIELDS = ["t", "rx", "tx", "pi", "po", "bi", "bo", "ui", "uo", "path", "online", "active", "hs", "orx", "otx"]
PING_FIELDS = ["t", "rtt_ms", "via", "srtt_ms", "rttvar_ms"]
TS_CANDIDATES = ("/Applications/Tailscale.app/Contents/MacOS/Tailscale",
                 "/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale", "/usr/bin/tailscale")
ALPHA, BETA = 0.125, 0.25
PING_TIMEOUT_S = 3
_PONG = re.compile(r"pong from (\S+) \(([^)]*)\) via (.+?) in ([0-9.]+)(µs|us|ms|s)\b")
_DERP = re.compile(r"^DERP\(([^)]+)\)$")


# ---------------------------------------------------------------- helpers (pure)

def find_binary():
    env = os.environ.get("TAILSCALE_BIN")
    if env and os.access(env, os.X_OK):
        return env
    for p in TS_CANDIDATES:
        if os.access(p, os.X_OK):
            return p
    return shutil.which("tailscale")


# Address ranges treated as "same network": RFC 1918, CGNAT (also Tailscale's own range), IPv6 ULA, loopback.
_LAN_NETS = tuple(ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "fc00::/7", "::1/128"))


def endpoint_class(addr):
    """'1.2.3.4:41641' -> 'lan' | 'wan' | '?'. Never returns the address."""
    host = (addr or "").rpartition(":")[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "?"
    lan = ip.is_link_local or any(ip in n for n in _LAN_NETS if n.version == ip.version)
    return "lan" if lan else "wan"


def status_path(peer):
    if not peer.get("Online"):
        return "offline"
    if peer.get("CurAddr"):
        return "direct:" + endpoint_class(peer["CurAddr"])
    if peer.get("PeerRelay"):
        return "peer-relay"
    if peer.get("Relay"):
        return "derp:" + str(peer["Relay"])
    return "none"


def parse_ping(text):
    """stdout of `tailscale ping -c 1` -> (rtt_ms, via) or (None, None) when no pong."""
    m = _PONG.search(text or "")
    if not m:
        return None, None
    via_raw, val, unit = m.group(3).strip(), float(m.group(4)), m.group(5)
    ms = val / 1000.0 if unit in ("µs", "us") else val * 1000.0 if unit == "s" else val
    d = _DERP.match(via_raw)
    if d:
        via = "derp:" + d.group(1)
    elif "relay" in via_raw.lower():
        via = "peer-relay"
    else:
        via = "direct:" + endpoint_class(via_raw)
    return round(ms, 2), via


def parse_handshake(s):
    if not s or s.startswith("0001-"):
        return None
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)$", s)
    if not m:
        return None
    frac = (m.group(2) or "")[:7]
    tz = "+00:00" if m.group(3) == "Z" else m.group(3)
    try:
        return round(datetime.fromisoformat(m.group(1) + frac + tz).timestamp(), 1)
    except ValueError:
        return None


def short_name(p):
    return ((p.get("DNSName") or "").split(".")[0] or p.get("HostName") or "?").lower()


def find_peer(status, want):
    want = want.lower()
    for p in (status.get("Peer") or {}).values():
        if isinstance(p, dict) and (short_name(p) == want or (p.get("HostName") or "").lower() == want):
            return p
    return None


def parse_netstat_ib(text, iface):
    """`netstat -ib -I utunN` -> (ipk, ib, opk, ob) from the <Link#> row, or None."""
    for line in (text or "").splitlines():
        cols = line.split()
        if len(cols) >= 10 and cols[0] == iface and cols[2].startswith("<Link#"):
            try:
                return int(cols[3]), int(cols[5]), int(cols[6]), int(cols[8])
            except ValueError:
                return None
    return None


_METRIC = re.compile(r'^tailscaled_(inbound|outbound)_(packets|bytes)_total\{path="[^"]*"\}\s+([0-9]+)\s*$')


def parse_metrics(text):
    """`tailscale metrics print` -> (pkts_in, pkts_out, bytes_in, bytes_out) summed over paths, or None."""
    acc = {}
    for line in (text or "").splitlines():
        m = _METRIC.match(line.strip())
        if m:
            k = (m.group(1), m.group(2))
            acc[k] = acc.get(k, 0) + int(m.group(3))
    if not acc:
        return None
    return (acc.get(("inbound", "packets")), acc.get(("outbound", "packets")),
            acc.get(("inbound", "bytes")), acc.get(("outbound", "bytes")))


def iface_for_ip(netstat_all, ip):
    """Find the utun whose address row carries the tailnet v4 address."""
    if not ip:
        return None
    for line in (netstat_all or "").splitlines():
        cols = line.split()
        if len(cols) >= 3 and cols[0].startswith("utun") and cols[2].startswith(ip + "/"):
            return cols[0]
    for line in (netstat_all or "").splitlines():   # fallback: Network column may be "100.x.y.z/32"
        cols = line.split()
        if len(cols) >= 4 and cols[0].startswith("utun") and ip in (cols[2], cols[3]):
            return cols[0]
    return None


class Srtt:
    """RFC 6298 smoothed RTT (Jacobson-Karels). Successful samples only."""

    def __init__(self):
        self.srtt = self.rttvar = None

    def update(self, r):
        if self.srtt is None:
            self.srtt, self.rttvar = float(r), r / 2.0
        else:
            self.rttvar = (1 - BETA) * self.rttvar + BETA * abs(self.srtt - r)
            self.srtt = (1 - ALPHA) * self.srtt + ALPHA * r
        return round(self.srtt, 2), round(self.rttvar, 2)


# ---------------------------------------------------------------- sampler

class Flow:
    def __init__(self, peer, every=1.0, ping_every=1.0, keep_s=600, tsbin=None):
        self.bin = tsbin or find_binary()
        if not self.bin:
            raise SystemExit("tailscale binary not found")
        self.want, self.every, self.ping_every = peer, every, ping_every
        self.samples = deque()
        self.pings = deque()
        self.keep_s = keep_s
        self.lock = threading.Lock()
        self.est = Srtt()
        self.meta = {}
        self.iface = None
        self.errors = {}
        self.demand_until = float("inf")   # serve mode lowers this; sampling pauses when time > demand_until
        self.stop = threading.Event()

    def _run(self, args, timeout):
        env = dict(os.environ, TAILSCALE_BE_CLI="1")   # Tailscale.app binary outside a terminal otherwise tries its GUI
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False,
                           stdin=subprocess.DEVNULL, env=env)
        return r.stdout

    def _status(self):
        return json.loads(self._run([self.bin, "status", "--json"], 5))

    def sample_once(self):
        try:
            st = self._status()
        except Exception as e:  # noqa: BLE001 - reported as a code, never raised to the page
            self.errors["status"] = type(e).__name__
            return None
        self.errors.pop("status", None)
        me = st.get("Self") or {}
        v4 = next((ip for ip in (me.get("TailscaleIPs") or []) if ":" not in ip), None)
        if self.iface is None:
            try:
                self.iface = iface_for_ip(self._run(["/usr/sbin/netstat", "-ib"], 5), v4)
            except Exception as e:  # noqa: BLE001
                self.errors["netstat"] = type(e).__name__
        cnt = None
        if self.iface:
            try:
                cnt = parse_netstat_ib(self._run(["/usr/sbin/netstat", "-ib", "-I", self.iface], 5), self.iface)
                self.errors.pop("netstat", None)
            except Exception as e:  # noqa: BLE001
                self.errors["netstat"] = type(e).__name__
        wire = None
        try:
            wire = parse_metrics(self._run([self.bin, "metrics", "print"], 5))
            self.errors.pop("metrics", None)
        except Exception as e:  # noqa: BLE001
            self.errors["metrics"] = type(e).__name__
        p = find_peer(st, self.want)
        orx = otx = 0
        for q in (st.get("Peer") or {}).values():
            if isinstance(q, dict) and q is not p:
                orx += q.get("RxBytes") or 0
                otx += q.get("TxBytes") or 0
        t = round(time.time(), 2)
        self.meta = {
            "backend_state": st.get("BackendState"), "tailscale_version": (st.get("Version") or "").split("-")[0],
            "self": {"name": short_name(me), "os": me.get("OS"), "home_derp": me.get("Relay") or None},
            "peer": ({"name": short_name(p), "host": p.get("HostName"), "os": p.get("OS"),
                      "home_derp": p.get("Relay") or None, "found": True} if p else {"name": self.want, "found": False}),
            "iface": self.iface,
        }
        row = [t, p.get("RxBytes"), p.get("TxBytes")] if p else [t, None, None]
        row += list(wire) if wire else [None, None, None, None]
        row += [cnt[0], cnt[2]] if cnt else [None, None]
        row += [status_path(p) if p else "none", int(bool(p and p.get("Online"))), int(bool(p and p.get("Active"))),
                parse_handshake(p.get("LastHandshake")) if p else None, orx, otx]
        with self.lock:
            self.samples.append(row)
            while self.samples and t - self.samples[0][0] > self.keep_s:
                self.samples.popleft()
        return row

    def ping_once(self):
        name = (self.meta.get("peer") or {}).get("name") or self.want
        t0 = time.time()
        try:
            out = self._run([self.bin, "ping", "-c", "1", "--timeout", "%ds" % PING_TIMEOUT_S, name], PING_TIMEOUT_S + 3)
            rtt, via = parse_ping(out)
            self.errors.pop("ping", None)
        except Exception as e:  # noqa: BLE001
            self.errors["ping"] = type(e).__name__
            rtt, via = None, None
        with self.lock:
            if rtt is not None:
                srtt, var = self.est.update(rtt)
            else:
                srtt = round(self.est.srtt, 2) if self.est.srtt is not None else None
                var = round(self.est.rttvar, 2) if self.est.rttvar is not None else None
            self.pings.append([round(t0, 2), rtt, via, srtt, var])
            while self.pings and t0 - self.pings[0][0] > self.keep_s:
                self.pings.popleft()

    def _wanted(self):
        return time.time() <= self.demand_until

    def sample_loop(self):
        nxt = time.monotonic()
        while not self.stop.is_set():
            if self._wanted():
                self.sample_once()
            nxt += self.every
            self.stop.wait(max(0.0, nxt - time.monotonic()))
            if nxt < time.monotonic() - 5 * self.every:   # fell far behind (sleep/wake): resync
                nxt = time.monotonic()

    def ping_loop(self):
        while not self.stop.is_set():
            if not self._wanted() or not (self.meta.get("peer") or {}).get("found"):
                self.stop.wait(0.5)
                continue
            t0 = time.monotonic()
            self.ping_once()
            self.stop.wait(max(0.05, self.ping_every - (time.monotonic() - t0)))

    def start(self):
        for fn, name in ((self.sample_loop, "flow-sample"), (self.ping_loop, "flow-ping")):
            threading.Thread(target=fn, name=name, daemon=True).start()

    def document(self, since=None, window_s=None, mode="live"):
        now = time.time()
        with self.lock:
            s = list(self.samples)
            pg = list(self.pings)
        lo = since if since is not None else (now - window_s if window_s else -1)
        s = [r for r in s if r[0] > lo]
        pg = [r for r in pg if r[0] > lo]
        return {"schema": SCHEMA, "mode": mode, "generated_at": round(now, 2),
                "every_s": self.every, "ping_every_s": self.ping_every,
                "meta": self.meta, "sample_fields": SAMPLE_FIELDS, "ping_fields": PING_FIELDS,
                "samples": s, "pings": pg, "errors": dict(self.errors)}


# ---------------------------------------------------------------- modes

def cmd_once(a):
    f = Flow(a.peer, every=1.0)
    f.sample_once()
    f.ping_once()
    time.sleep(1.0)
    f.sample_once()
    json.dump(f.document(mode="once"), sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")


def cmd_record(a):
    f = Flow(a.peer, every=a.every, ping_every=a.ping_every, keep_s=a.seconds + 60)
    started = time.time()
    f.start()
    f.stop.wait(a.seconds)
    f.stop.set()
    time.sleep(0.2)
    doc = f.document(mode="trace")
    doc["recorded"] = {"started_at": round(started, 2), "seconds": a.seconds, "host_tz": time.strftime("%z")}
    tmp = a.out + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, a.out)
    print("wrote %s: %d samples, %d pings, errors=%s" % (a.out, len(doc["samples"]), len(doc["pings"]), doc["errors"]))


def cmd_serve(a):
    f = Flow(a.peer, every=a.every, ping_every=a.ping_every, keep_s=a.keep)
    f.demand_until = 0.0   # idle until the first request
    f.start()

    class H(BaseHTTPRequestHandler):
        server_version = "tsflow/1"

        def log_message(self, *args):   # quiet
            pass

        def do_GET(self):
            u = urlparse(self.path)
            if u.path.rstrip("/").split("/")[-1] != "flow.json":
                self.send_error(404)
                return
            f.demand_until = time.time() + a.idle
            q = parse_qs(u.query)
            try:
                since = float(q["since"][0]) if "since" in q else None
            except ValueError:
                since = None
            body = json.dumps(f.document(since=since, window_s=a.window), ensure_ascii=False,
                              separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            if a.cors:
                self.send_header("Access-Control-Allow-Origin", a.cors)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):          # read-only service
            self.send_error(405)

        do_PUT = do_DELETE = do_PATCH = do_POST

    srv = ThreadingHTTPServer((a.bind, a.port), H)
    print("tsflow serving http://%s:%d/flow.json (peer=%s, idle=%ss)" % (a.bind, a.port, a.peer, a.idle), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        f.stop.set()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--peer", default=os.environ.get("TSFLOW_PEER"), help="peer hostname / MagicDNS label (or set TSFLOW_PEER)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("once")
    r = sub.add_parser("record")
    r.add_argument("--seconds", type=int, default=180)
    r.add_argument("--every", type=float, default=1.0)
    r.add_argument("--ping-every", type=float, default=1.0)
    r.add_argument("--out", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8791)
    s.add_argument("--every", type=float, default=1.0)
    s.add_argument("--ping-every", type=float, default=2.5)
    s.add_argument("--window", type=float, default=180.0, help="seconds returned when no ?since=")
    s.add_argument("--keep", type=int, default=600)
    s.add_argument("--idle", type=float, default=60.0, help="stop sampling this long after the last request")
    s.add_argument("--cors", default=None, help="optional exact Origin for Access-Control-Allow-Origin (off by default)")
    a = ap.parse_args(argv)
    if not a.peer:
        ap.error("--peer is required (the MagicDNS short name of the other machine, see `tailscale status`)")
    {"once": cmd_once, "record": cmd_record, "serve": cmd_serve}[a.cmd](a)


if __name__ == "__main__":
    main()
