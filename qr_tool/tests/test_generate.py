#!/usr/bin/env python3
"""Round-trip tests for qr_tool.generate using a DUMMY Fernet key.

These never use the real server key (we don't have it). A throwaway key from
Fernet.generate_key() is enough to prove the tool is correct: encrypt -> URL
-> QR -> decode -> decrypt returns the original plaintext, the URL keeps the
expected host, and the QR carries the requested error-correction level.

Run standalone:   python qr_tool/tests/test_generate.py
Or with pytest:   pytest qr_tool/tests/test_generate.py
"""

import os
import sys
import tempfile
from urllib.parse import urlparse, parse_qs

# Make the repo root importable regardless of how this file is invoked.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from cryptography.fernet import Fernet

from qr_tool.generate import (
    make_token,
    decrypt_token,
    build_url,
    generate_qr,
    _round_trip_verify,
    detect_ec_level,
)
from qr_tool.decode import decode_image

DUMMY_KEY = Fernet.generate_key()  # throwaway, NOT the real server key
SAMPLE = "Harshit Chhabi 24BCI0098"


def test_token_round_trip():
    token = make_token(DUMMY_KEY, SAMPLE)
    assert token.startswith("gAAAAA"), "not a Fernet token"
    assert decrypt_token(DUMMY_KEY, token) == SAMPLE


def test_build_url_structure():
    token = make_token(DUMMY_KEY, SAMPLE)
    url = build_url(token)
    parts = urlparse(url)
    assert parts.scheme == "https"
    assert parts.netloc == "96269.in"
    assert parts.path == "/"
    assert parse_qs(parts.query)["cipher"][0] == token


def test_qr_round_trip_and_ec_level():
    token = make_token(DUMMY_KEY, SAMPLE)
    url = build_url(token)
    img, version = generate_qr(url, ec_level="M")
    assert version >= 1
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "qr.png")
        img.save(path)

        # Decodes back to the exact URL.
        decoded = decode_image(path)
        assert decoded, "generated QR failed to decode"
        assert decoded[0]["payload"] == url

        # Decrypts back to the original plaintext.
        back_token = parse_qs(urlparse(decoded[0]["payload"]).query)["cipher"][0]
        assert decrypt_token(DUMMY_KEY, back_token) == SAMPLE

        # Error-correction level is M (best-effort; only assert if detectable).
        ec = detect_ec_level(path)
        if ec is not None:
            assert ec == "M", f"expected EC M, got {ec}"


def test_verify_helper():
    token = make_token(DUMMY_KEY, SAMPLE)
    url = build_url(token)
    img, _ = generate_qr(url, ec_level="M")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "qr.png")
        img.save(path)
        assert _round_trip_verify(path, DUMMY_KEY, SAMPLE, "cipher") is True
        # Wrong plaintext must fail the round trip.
        assert _round_trip_verify(path, DUMMY_KEY, "wrong", "cipher") is False


def test_wrong_key_cannot_decrypt():
    token = make_token(DUMMY_KEY, SAMPLE)
    other = Fernet.generate_key()
    try:
        decrypt_token(other, token)
    except Exception:
        pass
    else:
        raise AssertionError("decrypt with a different key should fail")


def _run_all():
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"FAIL  {name}: {exc!r}")
    if failures:
        print(f"\n{failures} test(s) failed")
        return 1
    print("\nall tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
