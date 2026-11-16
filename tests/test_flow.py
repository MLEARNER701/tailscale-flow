"""Offline tests: parsers of the collector, the synthetic trace and the page's embedded trace.

Run: python3 -m unittest discover -s tests -v
No tailscale binary or network is needed.
"""
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import flow_collector as fc  # noqa: E402
import embed_trace  # noqa: E402
import make_synthetic_trace  # noqa: E402


class Parsers(unittest.TestCase):
    def test_endpoint_class_never_returns_the_address(self):
        self.assertEqual(fc.endpoint_class("192.168.1.20:41641"), "lan")
        self.assertEqual(fc.endpoint_class("100.101.102.103:41641"), "lan")   # CGNAT range counts as LAN
        self.assertEqual(fc.endpoint_class("203.0.113.9:41641"), "wan")
        self.assertEqual(fc.endpoint_class("[2001:db8::1]:41641"), "wan")
        self.assertEqual(fc.endpoint_class("nonsense"), "?")

    def test_status_path(self):
        self.assertEqual(fc.status_path({"Online": False}), "offline")
        self.assertEqual(fc.status_path({"Online": True, "CurAddr": "203.0.113.9:41641"}), "direct:wan")
        self.assertEqual(fc.status_path({"Online": True, "CurAddr": "", "Relay": "fra"}), "derp:fra")
        self.assertEqual(fc.status_path({"Online": True, "PeerRelay": "x"}), "peer-relay")
        self.assertEqual(fc.status_path({"Online": True}), "none")

    def test_parse_ping(self):
        self.assertEqual(fc.parse_ping("pong from laptop (100.64.0.2) via DERP(fra) in 171ms"), (171.0, "derp:fra"))
        self.assertEqual(fc.parse_ping("pong from laptop (100.64.0.2) via 192.168.1.20:41641 in 3.5ms"), (3.5, "direct:lan"))
        self.assertEqual(fc.parse_ping("pong from laptop (100.64.0.2) via 203.0.113.9:41641 in 850µs"), (0.85, "direct:wan"))
        self.assertEqual(fc.parse_ping("pong from laptop (100.64.0.2) via 203.0.113.9:41641 in 1.2s"), (1200.0, "direct:wan"))
        self.assertEqual(fc.parse_ping("timeout waiting for pong"), (None, None))

    def test_parse_handshake(self):
        self.assertIsNone(fc.parse_handshake("0001-01-01T00:00:00Z"))
        self.assertIsNone(fc.parse_handshake(""))
        self.assertEqual(fc.parse_handshake("2026-01-01T12:00:00Z"), 1767268800.0)
        self.assertEqual(fc.parse_handshake("2026-01-01T21:00:00.123456789+09:00"), 1767268800.1)

    def test_parse_metrics_sums_paths(self):
        text = "\n".join([
            '# HELP something',
            'tailscaled_inbound_packets_total{path="direct_ipv4"} 10',
            'tailscaled_inbound_packets_total{path="derp"} 5',
            'tailscaled_outbound_packets_total{path="direct_ipv4"} 7',
            'tailscaled_inbound_bytes_total{path="direct_ipv4"} 1000',
            'tailscaled_outbound_bytes_total{path="derp"} 700',
        ])
        self.assertEqual(fc.parse_metrics(text), (15, 7, 1000, 700))
        self.assertIsNone(fc.parse_metrics("nothing here"))

    def test_netstat_parsing(self):
        all_rows = ("Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\n"
                    "utun4 1280  <Link#21>                          120     0      9000      80     0       6400     0\n"
                    "utun4 1280  100.64.0.1/32 100.64.0.1           120     -      9000      80     -       6400     -\n")
        self.assertEqual(fc.iface_for_ip(all_rows, "100.64.0.1"), "utun4")
        self.assertIsNone(fc.iface_for_ip(all_rows, "100.64.0.9"))
        self.assertEqual(fc.parse_netstat_ib(all_rows, "utun4"), (120, 9000, 80, 6400))

    def test_srtt_rfc6298(self):
        e = fc.Srtt()
        self.assertEqual(e.update(100.0), (100.0, 50.0))
        srtt, var = e.update(200.0)
        self.assertAlmostEqual(srtt, 112.5)
        self.assertAlmostEqual(var, 62.5)

    def test_cli_requires_peer(self):
        env = dict(os.environ)
        env.pop("TSFLOW_PEER", None)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "flow_collector.py"), "once"],
                           capture_output=True, text=True, env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--peer is required", r.stderr)


class Traces(unittest.TestCase):
    def test_synthetic_trace_schema(self):
        doc = make_synthetic_trace.build()
        self.assertEqual(doc["schema"], "tsflow.v1")
        self.assertTrue(doc["synthetic"])
        self.assertEqual(doc["sample_fields"], fc.SAMPLE_FIELDS)
        self.assertEqual(doc["ping_fields"], fc.PING_FIELDS)
        for row in doc["samples"]:
            self.assertEqual(len(row), len(fc.SAMPLE_FIELDS))
        for row in doc["pings"]:
            self.assertEqual(len(row), len(fc.PING_FIELDS))
        ts = [r[0] for r in doc["samples"]]
        self.assertEqual(ts, sorted(ts))
        for k in (1, 2, 3, 4, 5, 6):   # cumulative counters never go backwards
            col = [r[k] for r in doc["samples"]]
            self.assertEqual(col, sorted(col))
        paths = {r[9] for r in doc["samples"]}
        self.assertEqual(paths, {"derp:fra", "direct:wan"})

    def test_synthetic_trace_is_deterministic(self):
        self.assertEqual(make_synthetic_trace.build(), make_synthetic_trace.build())

    def test_page_embeds_exactly_the_synthetic_trace(self):
        with open(os.path.join(ROOT, "tailscale-flow.html"), encoding="utf-8") as fh:
            html = fh.read()
        embedded = embed_trace.extract(html)
        self.assertEqual(embedded, json.loads(json.dumps(make_synthetic_trace.build())))
        with open(os.path.join(ROOT, "demo", "synthetic-trace.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), embedded)

    def test_embed_roundtrip_escapes_script_close(self):
        html = '<p>x</p><script type="application/json" id="trace">{}</script>'
        doc = {"schema": "tsflow.v1", "note": "</script>"}
        out = embed_trace.embed(html, doc)
        self.assertEqual(out.count("</script>"), 1)
        self.assertEqual(embed_trace.extract(out), doc)

    def test_page_has_no_ip_addresses(self):
        with open(os.path.join(ROOT, "tailscale-flow.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIsNone(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", html))


if __name__ == "__main__":
    unittest.main()
