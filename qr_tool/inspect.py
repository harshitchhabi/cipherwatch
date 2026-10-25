#!/usr/bin/env python3
"""Inspect / break down a decoded QR payload.

Takes a payload string (from an argument, from --from-decode <image>, or on
stdin so it can be chained after decode.py) and reports a structured
breakdown:

  * If it looks like a URL/URI: scheme, domain (netloc / host / port / user),
    path, and query parameters -- parsed with urllib.parse -- plus flags for
    anything notable (non-standard scheme, known URL shortener, raw-IP host,
    userinfo in the authority, apparent open-redirect parameters, punycode).
  * Otherwise: report the detected type and the raw content.

This module only reads and parses. It does not modify the payload.

Usage:
    python qr_tool/inspect.py "<payload>"
    python qr_tool/inspect.py --from-decode sentinel_qr_0007.png
    python qr_tool/decode.py sentinel_qr_0007.png --raw | python qr_tool/inspect.py
"""

import argparse
import ipaddress
import json
import os
import sys
from urllib.parse import parse_qs, unquote, urlparse

# Path hygiene: this file is named inspect.py (as requested), which shadows the
# stdlib `inspect` that numpy/cv2 import when --from-decode pulls in decode.py.
# Drop this folder from sys.path and expose the repo root so the stdlib wins and
# `qr_tool.decode` still imports.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != _HERE]
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Common link shorteners / redirectors worth flagging in a QR context.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "t.ly", "rb.gy", "shorturl.at", "tiny.cc",
    "lnkd.in", "qr.ae", "s.id", "v.gd", "shorte.st", "adf.ly",
}

# Query-param names that often carry a redirect target (open-redirect smell).
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "next", "return",
    "returnurl", "return_url", "dest", "destination", "target", "continue",
    "goto", "r", "u", "link", "out",
}

STANDARD_SCHEMES = {"http", "https"}


def _looks_like_url(text):
    parsed = urlparse(text)
    return bool(parsed.scheme) and bool(parsed.netloc or parsed.path)


def inspect_payload(payload):
    """Return a dict describing the payload. Parsing only, no mutation."""
    text = payload.strip()
    report = {"raw": payload, "length": len(payload)}

    if not _looks_like_url(text):
        report["type"] = "text"
        report["note"] = "no URL/URI scheme detected; treating as plain content"
        return report

    parsed = urlparse(text)
    scheme = parsed.scheme.lower()
    host = parsed.hostname  # lowercased host without port/userinfo
    flags = []

    report["type"] = "url" if scheme in STANDARD_SCHEMES else "uri"
    report["scheme"] = parsed.scheme
    report["netloc"] = parsed.netloc
    report["host"] = host
    report["port"] = parsed.port
    report["username"] = parsed.username
    report["password"] = "***" if parsed.password else None
    report["path"] = parsed.path
    report["fragment"] = parsed.fragment or None

    # Query params (repeat keys preserved as lists).
    params = parse_qs(parsed.query, keep_blank_values=True)
    report["query_params"] = params

    # --- notable flags -------------------------------------------------
    if scheme not in STANDARD_SCHEMES:
        flags.append(f"non-standard scheme: {parsed.scheme!r}")

    if parsed.username or parsed.password:
        flags.append("authority contains userinfo (user[:pass]@host)")

    if host:
        host_l = host.lower()
        # Raw IP literal instead of a hostname.
        try:
            ipaddress.ip_address(host_l)
            flags.append(f"host is a raw IP address: {host_l}")
        except ValueError:
            pass
        # Registered-domain-level shortener match.
        labels = host_l.split(".")
        reg = ".".join(labels[-2:]) if len(labels) >= 2 else host_l
        if host_l in SHORTENERS or reg in SHORTENERS:
            flags.append(f"known URL shortener/redirector: {reg}")
        # Punycode / IDN homograph surface.
        if "xn--" in host_l:
            flags.append("punycode (IDN) label present -- check for homograph")

    # Redirect-looking params whose value is itself a URL.
    for key, values in params.items():
        if key.lower() in REDIRECT_PARAMS:
            for v in values:
                dv = unquote(v)
                if _looks_like_url(dv) or dv.startswith("//"):
                    flags.append(
                        f"possible redirect param {key!r} -> {dv!r}"
                    )
                    break

    report["flags"] = flags
    return report


def _print_human(report):
    print(f"type          : {report['type']}")
    print(f"length        : {report['length']} chars")
    if report["type"] == "text":
        print(f"note          : {report['note']}")
        print("raw content   :")
        print(report["raw"])
        return

    print(f"scheme        : {report['scheme']}")
    print(f"host (domain) : {report['host']}")
    if report.get("port"):
        print(f"port          : {report['port']}")
    print(f"netloc        : {report['netloc']}")
    if report.get("username"):
        print(f"userinfo      : {report['username']}"
              + (":***" if report.get('password') else ""))
    print(f"path          : {report['path'] or '(none)'}")
    if report.get("fragment"):
        print(f"fragment      : {report['fragment']}")

    params = report.get("query_params") or {}
    if params:
        print("query params  :")
        for k, v in params.items():
            shown = v[0] if len(v) == 1 else v
            print(f"    {k} = {shown}")
    else:
        print("query params  : (none)")

    flags = report.get("flags") or []
    if flags:
        print("flags         :")
        for f in flags:
            print(f"    [!] {f}")
    else:
        print("flags         : none notable")

    print("raw payload   :")
    print(report["raw"])


def _read_payloads(args):
    """Resolve the payload(s) to inspect from arg / --from-decode / stdin."""
    if args.payload is not None:
        return [args.payload]

    if args.from_decode:
        # Reuse the real decoder; no fabrication. Import works whether this
        # file is run as `python qr_tool/inspect.py` (sys.path[0] == qr_tool/)
        # or as part of the qr_tool package.
        try:
            from qr_tool.decode import decode_image
        except ImportError:
            from decode import decode_image  # same-directory fallback
        results = decode_image(args.from_decode)
        if not results:
            print(
                f"[inspect] no QR decoded in: {args.from_decode}",
                file=sys.stderr,
            )
            return []
        return [r["payload"] for r in results]

    # stdin (piped from decode.py --raw)
    data = sys.stdin.read()
    lines = [ln for ln in data.splitlines() if ln.strip()]
    return lines


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Break down a decoded QR payload (URL parsing + flags)."
    )
    parser.add_argument(
        "payload", nargs="?", default=None, help="payload string to inspect"
    )
    parser.add_argument(
        "--from-decode",
        metavar="IMAGE",
        help="decode this image first (via qr_tool.decode) then inspect it",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the report(s) as JSON"
    )
    args = parser.parse_args(argv)

    payloads = _read_payloads(args)
    if not payloads:
        if args.payload is None and not args.from_decode:
            print("[inspect] no payload provided on argument or stdin",
                  file=sys.stderr)
        return 2

    reports = [inspect_payload(p) for p in payloads]

    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0],
                         indent=2, ensure_ascii=False))
        return 0

    for i, report in enumerate(reports):
        if len(reports) > 1:
            print(f"--- payload {i + 1} of {len(reports)} ---")
        _print_human(report)
        if len(reports) > 1 and i != len(reports) - 1:
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
