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

## Generate (`generate.py`)

Encrypt a plaintext into a Fernet token and emit a QR for
`https://96269.in/?cipher=<token>`. **The key is never hardcoded** — pass
`--key` or set `$FERNET_KEY` (a urlsafe-base64 32-byte key). Without the real
server key you can still build a structurally valid token/QR with any key
(e.g. a throwaway `Fernet.generate_key()`); only a token made with the
server's real key is accepted by the real server.

```bash
export FERNET_KEY="<urlsafe-base64 32-byte key>"

# Match the original's EC level + version automatically, verify the round trip:
python qr_tool/generate.py "Harshit Chhabi 24BCI0098" \
    --match-image sentinel_qr_0007.png -o out.png --print-url --verify

# Or set the EC level / version explicitly:
python qr_tool/generate.py "..." --ec M --version 9 -o out.png
```

- `--match-image <ref>` detects the reference QR's EC level (via zxing-cpp)
  and version (via module count) and reuses them. `sentinel_qr_0007` is
  **EC=M, version 9 (53×53)**.
- `--verify` does a no-server round trip: encrypt → write QR → decode it back
  → decrypt locally with the same key → confirm it matches the input.
- The Fernet token is emitted verbatim in the URL (its alphabet is already
  URL-safe), matching the original's clean `cipher` value.

### Tests

```bash
python qr_tool/tests/test_generate.py     # standalone
# or: pytest qr_tool/tests/test_generate.py
```

Tests use a throwaway dummy key (never the real server key).

## Notes

- Two real decoders are used: `pyzbar` (libzbar) first, OpenCV
  `QRCodeDetector` as a fallback that also handles a symbol embedded in a
  larger image. If neither reads a symbol, the tools say so and exit
  non-zero — no payload is ever fabricated or guessed.
- `inspect.py` flags notable URL traits: non-standard schemes, known
  shorteners/redirectors, raw-IP hosts, userinfo in the authority, punycode
  (IDN) labels, and redirect-looking query parameters.
