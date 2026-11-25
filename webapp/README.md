# BambooSense Keyforge 🐼🔑

A small **local web app** that mints a self-signed identity for your Bambu Lab
printer, writes everything onto a **USB key**, and then acts as the web client
that loads it back, installs the certificate, and drives the printer — all on
your LAN, no Bambu cloud.

It's the friendly front-end to the signing crack documented in
[`../docs/CRACK.md`](../docs/CRACK.md): the printer trusts any certificate it
installs itself, so we bring our own and sign `print.*` commands with it.

## The five steps (matching the UI)

1. **Mint your identity** — enter the printer serial. You get an RSA-2048 key,
   a self-signed certificate (`CN=<serial>.bambulab.com`), and a CRL. The cert
   and CRL are generated **together with the same issuer DN** — this is the
   detail that makes `app_cert_install` actually land instead of being silently
   dropped (`CRACK.md §7`). The private key is made here and only ever copied
   onto the USB key you pick.
2. **Point at your printer** — LAN IP, serial, and the 8-digit access code
   (printer screen → Settings → Network/WLAN). Optional `user_id`.
3. **The USB key** — "Write bundle to USB" drops a `BambooSense/` folder onto
   the stick: `identity-cert.pem`, `identity-key.pem`, `identity-crl.pem`,
   `connection.json`, and a `README.txt`. Carry it to wherever your web client
   runs and hit **Load from USB** — that's the "renseigner le client web" step.
4. **Install the cert on the printer** — sends `security.app_cert_install` over
   MQTT (port 8883, TLS, `bblp` + access code). The app confirms via
   `app_cert_list`.
5. **Drive the printer** — live status (state, progress, temps), chamber light,
   and signed `print.*` controls: pause / resume / stop / clear-error / speed,
   plus a raw command box.

## Run it

```bash
pip install -r webapp/requirements.txt
python3 webapp/server.py
# open http://127.0.0.1:8770
```

Environment overrides: `PORT` (default 8770), `HOST` (default 127.0.0.1 — keep
it loopback; this app holds a key that can command your printer).

## How the cert reaches the printer (honest note)

Bambu printers don't import a client identity from a USB stick natively — the
USB key here is the **carrier for the bundle** between machines, exactly as
asked. The certificate is actually installed over your LAN via the MQTT
`app_cert_install` path (the verified mechanism). If you'd rather the
BambooSense **dongle** install it instead, the bundle's PEMs are the same ones
its `POST /identity` endpoint expects.

## Files

| File | What |
|---|---|
| `server.py` | stdlib HTTP server: generate, USB export/import, install, control |
| `keyforge.py` | pure-crypto core — mint cert/key/CRL, sign `print.*` (no network) |
| `static/` | the single-page UI |

## Security

`identity-key.pem` can command your printer. Treat the USB key like a house
key. Nothing in the bundle is useful without your printer's IP **and** LAN
access code. The app binds to loopback by default and never writes the key into
the repo (`webapp/.workdir/` is gitignored).
