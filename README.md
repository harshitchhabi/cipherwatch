# CipherWatch

Tooling for the VIT Dortress Cybersecurity Month 2026 hackathon.

## Modules

- **`qr_tool/`** — QR code decode + inspect utilities. Decodes a QR symbol
  from an image with real decoders (`pyzbar` + OpenCV) and breaks the payload
  down (URL scheme / domain / path / query params, with flags for notable
  traits). See [`qr_tool/README.md`](qr_tool/README.md).

## Setup

```bash
pip install -r requirements.txt
sudo apt-get install -y libzbar0t64   # native zbar library for pyzbar
```
