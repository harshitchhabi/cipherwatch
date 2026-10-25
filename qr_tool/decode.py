#!/usr/bin/env python3
"""Decode QR code(s) from an image file.

Uses two independent real decoders and keeps whichever actually reads the
symbol:

  1. pyzbar (libzbar) -- robust, handles most real-world photos.
  2. OpenCV QRCodeDetector -- good fallback, locates a symbol embedded in a
     larger scene and copes with some cases zbar misses.

Nothing here fabricates or guesses a payload: if neither decoder reads a
symbol, that is reported honestly and the exit code is non-zero.

Usage:
    python qr_tool/decode.py <image_path> [--raw] [--json]

    --raw   print only the decoded payload text (nothing else), so the
            output can be piped straight into inspect.py.
    --json  print the full result (payload + detected type + which decoder
            read it) as JSON.
"""

import argparse
import json
import os
import sys
from urllib.parse import urlparse

# Path hygiene: when run as `python qr_tool/decode.py`, this folder lands first
# on sys.path and would shadow stdlib modules -- notably our sibling inspect.py
# vs the real `inspect`, which numpy (pulled in by cv2) imports. Drop this
# folder from sys.path and expose the repo root so `qr_tool.*` still imports.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != _HERE]
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _classify(payload):
    """Best-effort label for a decoded payload. Detection only -- no changes.

    Mirrors the common QR content conventions so the caller gets a quick
    hint; inspect.py does the detailed URL breakdown.
    """
    if payload is None:
        return "unknown"
    text = payload.strip()
    lower = text.lower()

    # Structured prefixes used by phones/scanners.
    prefix_types = {
        "http://": "url",
        "https://": "url",
        "mailto:": "email",
        "tel:": "phone",
        "smsto:": "sms",
        "sms:": "sms",
        "geo:": "geo",
        "wifi:": "wifi",
        "bitcoin:": "crypto",
        "upi://": "upi",
        "otpauth://": "otp",
    }
    for prefix, label in prefix_types.items():
        if lower.startswith(prefix):
            return label

    if lower.startswith("begin:vcard"):
        return "vcard"
    if lower.startswith("begin:vevent"):
        return "vevent"

    # A scheme-bearing string that urlparse understands but that did not match
    # the common prefixes above (e.g. ftp://, custom app schemes).
    parsed = urlparse(text)
    if parsed.scheme and (parsed.netloc or parsed.path):
        return "uri"

    return "text"


def _decode_pyzbar(image_path):
    """Return a list of result dicts from pyzbar, or [] if it read nothing."""
    try:
        from pyzbar import pyzbar
        from PIL import Image
    except ImportError as exc:
        print(f"[decode] pyzbar/PIL unavailable: {exc}", file=sys.stderr)
        return []

    try:
        img = Image.open(image_path)
    except Exception as exc:  # noqa: BLE001 -- surface any load error plainly
        print(f"[decode] could not open image: {exc}", file=sys.stderr)
        return []

    # Convert to a mode zbar is happy with; grayscale often improves reads.
    results = []
    for mode in ("L", "RGB"):
        try:
            candidate = img.convert(mode)
        except Exception:  # noqa: BLE001
            continue
        found = pyzbar.decode(candidate, symbols=[pyzbar.ZBarSymbol.QRCODE])
        if found:
            for sym in found:
                try:
                    payload = sym.data.decode("utf-8")
                    encoding = "utf-8"
                except UnicodeDecodeError:
                    payload = sym.data.decode("latin-1")
                    encoding = "latin-1 (non-utf8 bytes)"
                results.append(
                    {
                        "decoder": "pyzbar",
                        "payload": payload,
                        "encoding": encoding,
                        "symbol_type": sym.type,
                        "rect": list(sym.rect),
                    }
                )
            break  # first mode that reads the symbol is enough
    return results


def _decode_opencv(image_path):
    """Return a list of result dicts from OpenCV, or [] if it read nothing.

    detectAndDecodeMulti handles a symbol embedded in a larger image and the
    case of multiple symbols in one frame.
    """
    try:
        import cv2
    except ImportError as exc:
        print(f"[decode] opencv unavailable: {exc}", file=sys.stderr)
        return []

    img = cv2.imread(image_path)
    if img is None:
        print(f"[decode] opencv could not read image: {image_path}", file=sys.stderr)
        return []

    detector = cv2.QRCodeDetector()
    results = []
    try:
        ok, decoded, points, _ = detector.detectAndDecodeMulti(img)
    except cv2.error:
        ok, decoded, points = False, [], None

    if ok and decoded:
        for i, payload in enumerate(decoded):
            if not payload:
                continue  # located but not decoded -> don't fabricate
            rect = None
            if points is not None and i < len(points):
                xs = [int(p[0]) for p in points[i]]
                ys = [int(p[1]) for p in points[i]]
                rect = [min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys)]
            results.append(
                {
                    "decoder": "opencv",
                    "payload": payload,
                    "encoding": "opencv-utf8",
                    "symbol_type": "QRCODE",
                    "rect": rect,
                }
            )
    return results


def decode_image(image_path):
    """Decode all QR symbols in an image. Returns a list of result dicts.

    pyzbar is tried first; OpenCV supplies any payloads pyzbar missed
    (deduplicated on payload text).
    """
    results = _decode_pyzbar(image_path)
    seen = {r["payload"] for r in results}
    for r in _decode_opencv(image_path):
        if r["payload"] not in seen:
            results.append(r)
            seen.add(r["payload"])

    for r in results:
        r["detected_type"] = _classify(r["payload"])
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Decode QR code(s) from an image using real decoders."
    )
    parser.add_argument("image", help="path to the image file")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="print only the payload text (for piping into inspect.py)",
    )
    parser.add_argument(
        "--json", action="store_true", help="print full result(s) as JSON"
    )
    args = parser.parse_args(argv)

    results = decode_image(args.image)

    if not results:
        print(
            f"[decode] no QR code could be decoded in: {args.image}",
            file=sys.stderr,
        )
        return 2

    if args.raw:
        # Payload(s) only, one per line, nothing else -> clean for piping.
        for r in results:
            print(r["payload"])
        return 0

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0

    for i, r in enumerate(results):
        if len(results) > 1:
            print(f"--- symbol {i + 1} of {len(results)} ---")
        print(f"decoder       : {r['decoder']}")
        print(f"symbol type   : {r['symbol_type']}")
        print(f"detected type : {r['detected_type']}")
        print(f"encoding      : {r['encoding']}")
        if r.get("rect"):
            print(f"location      : x,y,w,h = {r['rect']}")
        print("raw payload   :")
        print(r["payload"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
