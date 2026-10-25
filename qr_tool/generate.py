#!/usr/bin/env python3
"""Generate a QR code whose payload is a Fernet-encrypted cipher URL.

Flow:
    plaintext --(Fernet encrypt with a runtime key)--> token
    token     --> https://96269.in/?cipher=<token>
    URL       --(qrcode)--> PNG, at a chosen error-correction level/size.

The Fernet key is NEVER hardcoded: supply it with --key or the FERNET_KEY
environment variable. Without a real key you can still build a
*structurally valid* token and QR with any key (e.g. a throwaway
Fernet.generate_key()), which is what --verify checks -- but only a token
made with the server's real key will be accepted by the real server.

--verify does a full local round trip with no server: encrypt, write the QR,
decode the QR back, parse the cipher, decrypt it with the same key, and
confirm it matches the input plaintext.

Match the original's error-correction level with --ec (default M, which is
what sentinel_qr_0007 uses) or auto-detect it from a reference image with
--match-image.

Usage:
    export FERNET_KEY="<urlsafe-base64 32-byte key>"
    python qr_tool/generate.py "Harshit Chhabi 24BCI0098" -o out.png --verify
    python qr_tool/generate.py "..." --match-image sentinel_qr_0007.png -o out.png
"""

import argparse
import os
import sys
from urllib.parse import quote, urlparse, parse_qs, urlunparse

# Path hygiene: this folder would otherwise shadow stdlib modules (notably our
# sibling inspect.py vs the real `inspect`, imported transitively by numpy/cv2).
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != _HERE]
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

DEFAULT_BASE_URL = "https://96269.in/"
DEFAULT_PARAM = "cipher"

# Map CLI letters to qrcode's constants, lazily (import inside to keep the
# module importable even if a dependency is missing until actually used).
_EC_LETTERS = ("L", "M", "Q", "H")


def _ec_constant(letter):
    from qrcode.constants import (
        ERROR_CORRECT_L,
        ERROR_CORRECT_M,
        ERROR_CORRECT_Q,
        ERROR_CORRECT_H,
    )
    return {
        "L": ERROR_CORRECT_L,
        "M": ERROR_CORRECT_M,
        "Q": ERROR_CORRECT_Q,
        "H": ERROR_CORRECT_H,
    }[letter.upper()]


def make_token(key, plaintext):
    """Encrypt plaintext into a Fernet token (str). Raises on a bad key."""
    from cryptography.fernet import Fernet

    if isinstance(key, str):
        key = key.encode()
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    return Fernet(key).encrypt(plaintext).decode("ascii")


def decrypt_token(key, token):
    """Decrypt a Fernet token back to plaintext (str). Raises if invalid."""
    from cryptography.fernet import Fernet

    if isinstance(key, str):
        key = key.encode()
    if isinstance(token, str):
        token = token.encode()
    return Fernet(key).decrypt(token).decode("utf-8")


def build_url(token, base_url=DEFAULT_BASE_URL, param=DEFAULT_PARAM):
    """Build base_url with ?<param>=<token>, preserving path and other params.

    A Fernet token uses the URL-safe base64 alphabet (A-Za-z0-9-_) plus '='
    padding, so it is emitted verbatim (matching the original's clean cipher
    value) rather than percent-encoded. Any other pre-existing query params
    are percent-encoded normally.
    """
    parts = urlparse(base_url)
    existing = parse_qs(parts.query, keep_blank_values=True)
    pieces = []
    for k, vals in existing.items():
        if k == param:
            continue
        for v in vals:
            pieces.append(f"{quote(k, safe='')}={quote(v, safe='')}")
    # Keep the token's own characters (including '=' padding) literal.
    pieces.append(f"{quote(param, safe='')}={quote(token, safe='-_=')}")
    new_query = "&".join(pieces)
    return urlunparse(
        (parts.scheme, parts.netloc, parts.path or "/", parts.params,
         new_query, parts.fragment)
    )


def generate_qr(data, ec_level="M", version=None, box_size=10, border=4):
    """Return a PIL image of a QR encoding `data` at the given EC level.

    version=None lets qrcode pick the smallest version that fits (fit=True).
    """
    import qrcode

    qr = qrcode.QRCode(
        version=version,
        error_correction=_ec_constant(ec_level),
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=(version is None))
    img = qr.make_image(fill_color="black", back_color="white")
    return img, qr.version


def detect_ec_level(image_path):
    """Detect a reference QR's EC level ('L'/'M'/'Q'/'H') or None.

    Uses zxing-cpp, which exposes ec_level directly. Best effort.
    """
    try:
        import zxingcpp
        import cv2
    except ImportError:
        return None
    img = cv2.imread(image_path)
    if img is None:
        return None
    for r in zxingcpp.read_barcodes(img):
        lvl = getattr(r, "ec_level", None)
        if lvl:
            lvl = str(lvl).strip().upper()
            # zxing may report like 'M' or 'Q'; take the first L/M/Q/H char.
            for ch in lvl:
                if ch in _EC_LETTERS:
                    return ch
    return None


def detect_version(image_path):
    """Best-effort detect a reference QR's version (1..40) from module count.

    Measures the top-left finder pattern (7 modules) against the symbol width.
    Returns an int or None if it can't be determined.
    """
    try:
        import cv2
        import numpy as np
    except ImportError:
        return None
    gray = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if gray is None:
        return None
    _, bw = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    det = cv2.QRCodeDetector()
    ok, pts = det.detect(gray)
    if not ok or pts is None:
        return None
    pts = pts.reshape(-1, 2)
    side = float(np.mean([
        np.linalg.norm(pts[0] - pts[1]),
        np.linalg.norm(pts[1] - pts[2]),
        np.linalg.norm(pts[2] - pts[3]),
        np.linalg.norm(pts[3] - pts[0]),
    ]))
    # Sample along the top edge; the leading dark run is the finder's 7 modules.
    x0, y0 = pts[0]
    x1, y1 = pts[1]
    N = 600
    run = 0
    started = False
    for i in range(N):
        x = int(round(x0 + (x1 - x0) * i / N))
        y = int(round(y0 + (y1 - y0) * i / N))
        if not (0 <= y < bw.shape[0] and 0 <= x < bw.shape[1]):
            continue
        dark = bw[y, x] < 128
        if dark:
            started = True
            run += 1
        elif started:
            break
    if run == 0:
        return None
    finder_frac = run / N
    modules = round(7 / finder_frac)
    if modules < 21 or (modules - 17) % 4 != 0:
        # Snap to the nearest valid module count (21 + 4k).
        version = max(1, round((modules - 17) / 4))
    else:
        version = (modules - 17) // 4
    if 1 <= version <= 40:
        return version
    return None


def _resolve_key(args):
    key = args.key or os.environ.get("FERNET_KEY")
    if not key:
        return None
    return key.strip()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate a Fernet-cipher QR (key supplied at runtime)."
    )
    parser.add_argument("plaintext", help="plaintext to encrypt into the cipher")
    parser.add_argument(
        "--key",
        help="Fernet key (urlsafe base64, 32 bytes). Overrides $FERNET_KEY. "
        "Never hardcode a key.",
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                        help=f"base URL (default {DEFAULT_BASE_URL})")
    parser.add_argument("--param", default=DEFAULT_PARAM,
                        help=f"query param name (default {DEFAULT_PARAM})")
    parser.add_argument("--ec", choices=list(_EC_LETTERS), default=None,
                        help="error-correction level (default M, or the "
                        "detected level with --match-image)")
    parser.add_argument("--version", type=int, default=None,
                        help="force QR version 1-40 (default: auto-fit)")
    parser.add_argument("--match-image", metavar="IMAGE",
                        help="auto-detect EC level and version from this "
                        "reference QR (e.g. the original)")
    parser.add_argument("--box-size", type=int, default=10)
    parser.add_argument("--border", type=int, default=4)
    parser.add_argument("-o", "--output", default="qr_out.png",
                        help="output PNG path (default qr_out.png)")
    parser.add_argument("--print-url", action="store_true",
                        help="print the full URL that was encoded")
    parser.add_argument("--verify", action="store_true",
                        help="round-trip check: decode the generated QR, "
                        "decrypt locally, confirm it matches the input")
    args = parser.parse_args(argv)

    key = _resolve_key(args)
    if not key:
        print("[generate] no Fernet key: pass --key or set $FERNET_KEY "
              "(never hardcode one)", file=sys.stderr)
        return 2

    # Resolve EC level and version, honoring explicit flags over detection.
    ec_level = args.ec
    version = args.version
    if args.match_image:
        det_ec = detect_ec_level(args.match_image)
        det_ver = detect_version(args.match_image)
        if ec_level is None and det_ec:
            ec_level = det_ec
        if version is None and det_ver:
            version = det_ver
        print(f"[generate] reference {args.match_image}: "
              f"EC={det_ec or '?'} version={det_ver or '?'}", file=sys.stderr)
    if ec_level is None:
        ec_level = "M"

    # Encrypt -> URL.
    try:
        token = make_token(key, args.plaintext)
    except Exception as exc:  # noqa: BLE001 -- surface an invalid key clearly
        print(f"[generate] could not encrypt (bad key?): {exc}", file=sys.stderr)
        return 2
    url = build_url(token, base_url=args.base_url, param=args.param)

    # Build the QR; if a forced version is too small for the data, auto-fit.
    try:
        img, used_version = generate_qr(url, ec_level=ec_level, version=version,
                                        box_size=args.box_size,
                                        border=args.border)
    except Exception as exc:  # e.g. DataOverflowError on a too-small --version
        print(f"[generate] forced version {version} too small for data; "
              f"auto-fitting instead ({exc})", file=sys.stderr)
        img, used_version = generate_qr(url, ec_level=ec_level, version=None,
                                        box_size=args.box_size,
                                        border=args.border)

    img.save(args.output)
    print(f"[generate] wrote {args.output}  (EC={ec_level}, "
          f"version={used_version}, modules={17 + 4 * used_version})")
    if args.print_url:
        print(url)

    if args.verify:
        ok = _round_trip_verify(args.output, key, args.plaintext, args.param)
        if not ok:
            print("[verify] FAIL", file=sys.stderr)
            return 1
        print("[verify] PASS: QR decodes and decrypts back to the input "
              "plaintext")
    return 0


def _round_trip_verify(image_path, key, plaintext, param):
    """Decode the generated QR, decrypt the cipher, compare to plaintext."""
    try:
        from qr_tool.decode import decode_image
    except ImportError:
        from decode import decode_image
    results = decode_image(image_path)
    if not results:
        print("[verify] generated QR did not decode", file=sys.stderr)
        return False
    decoded_url = results[0]["payload"]
    token = parse_qs(urlparse(decoded_url).query).get(param, [None])[0]
    if not token:
        print(f"[verify] no '{param}' param in decoded URL: {decoded_url}",
              file=sys.stderr)
        return False
    try:
        recovered = decrypt_token(key, token)
    except Exception as exc:  # noqa: BLE001
        print(f"[verify] decrypt failed: {exc}", file=sys.stderr)
        return False
    if recovered != plaintext:
        print(f"[verify] mismatch: {recovered!r} != {plaintext!r}",
              file=sys.stderr)
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
