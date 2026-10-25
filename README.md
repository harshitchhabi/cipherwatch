# CipherWatch

Tooling for the VIT Dortress Cybersecurity Month 2026 hackathon.

## Modules

- **`qr_tool/`** — QR code decode + inspect utilities. Decodes a QR symbol
  from an image with real decoders (`pyzbar` + OpenCV) and breaks the payload
  down (URL scheme / domain / path / query params, with flags for notable
  traits). See [`qr_tool/README.md`](qr_tool/README.md).
- **`crypto_engine/`** — classical cryptanalysis, encoding, XOR, RSA, AES,
  hash, and ML-KEM/ML-DSA hybrid-envelope tooling.
- **`pass.txt.pqenc`** — the supplied hybrid PQC envelope target.
- **`solve.py` / `generate.py`** — inspect, solve, generate, and decrypt PQC
  envelopes when the KEM private key or AES key is available. See
  [`CRYPTO_SENTINEL_README.md`](CRYPTO_SENTINEL_README.md) for details.

## Setup

```bash
pip install -r requirements.txt
sudo apt-get install -y libzbar0t64   # native zbar library for pyzbar
```

Run the test suites with:

```bash
python3 -m unittest discover -s qr_tool/tests -v
python3 -m unittest discover -s tests -v
```
