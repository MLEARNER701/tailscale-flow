#!/usr/bin/env python3
"""Embed a tsflow.v1 trace (from `flow_collector.py record` or tools/make_synthetic_trace.py) into the page.

Usage: python3 tools/embed_trace.py TRACE.json [--html tailscale-flow.html] [--out OUT.html]

The page replays the embedded trace when it is opened without ?src=. Keep your own recordings out of a
public copy: a real trace contains your machine names and DERP home regions.
"""
from __future__ import annotations

import argparse
import json
import re


def embed(html, doc):
    s = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    out, n = re.subn(r'(<script type="application/json" id="trace">).*?(</script>)',
                     lambda m: m.group(1) + s + m.group(2), html, count=1, flags=re.S)
    if n != 1:
        raise SystemExit("trace block not found in the page")
    return out


def extract(html):
    m = re.search(r'<script type="application/json" id="trace">(.*?)</script>', html, flags=re.S)
    if not m:
        raise ValueError("trace block not found")
    return json.loads(m.group(1).replace("<\\/", "</"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("trace")
    ap.add_argument("--html", default="tailscale-flow.html")
    ap.add_argument("--out", default=None, help="write here instead of overwriting --html")
    a = ap.parse_args(argv)
    with open(a.trace, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("schema") != "tsflow.v1":
        raise SystemExit("not a tsflow.v1 trace")
    with open(a.html, encoding="utf-8") as fh:
        html = fh.read()
    with open(a.out or a.html, "w", encoding="utf-8") as fh:
        fh.write(embed(html, doc))
    print("embedded %d samples into %s" % (len(doc.get("samples", [])), a.out or a.html))


if __name__ == "__main__":
    main()
