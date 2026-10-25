# qr_tool

QR code **decode + inspect** utilities for CipherWatch.

This stage is read-only: it decodes a QR symbol from an image and breaks the
payload down. It does **not** generate or modify QR codes.

## Install

```bash
pip install -r requirements.txt
```

`pyzbar` needs the native zbar shared library. On Debian/Ubuntu:

```bash
sudo apt-get install -y libzbar0t64   # or libzbar0 on older releases
```

## Usage

Decode an image and show the raw payload + detected type:

```bash
python qr_tool/decode.py sentinel_qr_0007.png
```

Decode only the payload text (for piping):

```bash
python qr_tool/decode.py sentinel_qr_0007.png --raw
```

Inspect a payload (URL breakdown: scheme / domain / path / params + flags):

```bash
python qr_tool/inspect.py "https://example.com/a?b=1"
```

Chain decode into inspect:

```bash
python qr_tool/decode.py sentinel_qr_0007.png --raw | python qr_tool/inspect.py
# or, in one step:
python qr_tool/inspect.py --from-decode sentinel_qr_0007.png
```

JSON output is available on both via `--json`.

## Notes

- Two real decoders are used: `pyzbar` (libzbar) first, OpenCV
  `QRCodeDetector` as a fallback that also handles a symbol embedded in a
  larger image. If neither reads a symbol, the tools say so and exit
  non-zero — no payload is ever fabricated or guessed.
- `inspect.py` flags notable URL traits: non-standard schemes, known
  shorteners/redirectors, raw-IP hosts, userinfo in the authority, punycode
  (IDN) labels, and redirect-looking query parameters.
