#!/usr/bin/env python3
"""BambooSense Keyforge — a small local web app.

What it does, in the order you'd use it:

  1. Mint a self-signed identity (cert + key + matching CRL) for your printer.
  2. Write the whole bundle to a USB key — cert, key, CRL, and a connection
     manifest with everything the web client needs.
  3. Read that USB key back in ("renseigner le client web"), install the cert
     onto the printer over your LAN, and then drive the printer locally:
     signed print.* commands (pause / resume / stop / speed / clear error),
     chamber light, and full live status.

Everything is local: the crypto never touches the network, and the only
outbound traffic is MQTT-over-TLS to the printer on your own LAN (port 8883).

Run:   python3 webapp/server.py            # then open http://127.0.0.1:8770
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keyforge  # noqa: E402

try:
    import paho.mqtt.client as mqtt  # noqa: E402
    HAVE_MQTT = True
except Exception:  # pragma: no cover
    HAVE_MQTT = False

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
WORKDIR = HERE / ".workdir"       # persists the session across restarts
WORKDIR.mkdir(exist_ok=True)
BUNDLE_DIRNAME = "BambooSense"    # folder name written to the USB key


# ===========================================================================
# session state  (identity + printer config, persisted to .workdir)
# ===========================================================================
class Session:
    def __init__(self):
        self.identity: keyforge.Identity | None = None
        self.printer = {"ip": "", "serial": "", "access_code": "", "user_id": "",
                        "cert_installed": False}
        self._seq = 100000 + int(time.time()) % 50000
        self._lock = threading.Lock()
        self.load()

    # ----- persistence -----
    def load(self):
        f = WORKDIR / "session.json"
        if f.exists():
            try:
                d = json.loads(f.read_text())
                if d.get("identity"):
                    self.identity = keyforge.load_identity(**d["identity"])
                self.printer.update(d.get("printer", {}))
            except Exception as e:
                print("session load failed:", e)

    def save(self):
        d = {"printer": self.printer}
        if self.identity:
            d["identity"] = self.identity.__dict__
        (WORKDIR / "session.json").write_text(json.dumps(d, indent=2))

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def state(self) -> dict:
        return {
            "have_mqtt": HAVE_MQTT,
            "identity": self.identity.public() if self.identity else None,
            "printer": {k: v for k, v in self.printer.items() if k != "access_code"}
            | {"has_access_code": bool(self.printer["access_code"])},
        }


SESSION = Session()


# ===========================================================================
# printer link  (one connect → act → collect cycle per call)
# ===========================================================================
class PrinterError(Exception):
    pass


def _mqtt_cycle(ip, serial, access_code, publishes, collect_secs=4.0):
    """Connect, subscribe to the report topic, run `publishes` (list of JSON
    strings), and collect everything that comes back for a few seconds.

    No client certificate is needed for the MQTT channel itself — auth is
    bblp + access code (docs/CRACK.md). Signing happens at the app layer.
    """
    if not HAVE_MQTT:
        raise PrinterError("paho-mqtt is not installed (pip install paho-mqtt)")
    if not ip or not serial:
        raise PrinterError("printer IP and serial must be set first")

    reports, secs, acks = [], [], []

    def on_connect(c, u, flags, rc, *a):
        c.subscribe(f"device/{serial}/report", 0)

    def on_message(c, u, m):
        try:
            d = json.loads(m.payload)
        except Exception:
            return
        if "security" in d:
            secs.append(d["security"])
        if "print" in d:
            reports.append(d["print"])
            p = d["print"]
            if "result" in p or str(p.get("sequence_id", "")).isdigit():
                acks.append({k: p.get(k) for k in
                             ("command", "result", "reason", "err_code", "sequence_id")
                             if k in p})

    try:
        c = mqtt.Client(client_id=f"keyforge-{int(time.time())}",
                        protocol=mqtt.MQTTv311)
    except Exception:  # paho 2.x
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                        client_id=f"keyforge-{int(time.time())}",
                        protocol=mqtt.MQTTv311)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c.tls_set_context(ctx)
    c.username_pw_set("bblp", access_code)
    c.on_connect = on_connect
    c.on_message = on_message

    try:
        c.connect(ip, 8883, keepalive=30)
    except Exception as e:
        raise PrinterError(f"could not connect to {ip}:8883 — {e}")
    c.loop_start()
    time.sleep(1.2)  # let subscribe settle
    for pub in publishes:
        c.publish(f"device/{serial}/request", pub)
        time.sleep(0.3)
    time.sleep(collect_secs)
    c.loop_stop()
    try:
        c.disconnect()
    except Exception:
        pass

    # merge all report fragments into one dict (printer pushes in pieces)
    merged = {}
    for r in reports:
        merged.update(r)
    return {"report": merged, "security": secs, "acks": acks,
            "report_count": len(reports)}


def install_cert():
    ident = SESSION.identity
    p = SESSION.printer
    if not ident:
        raise PrinterError("mint an identity first")
    env = keyforge.build_cert_install(ident, str(SESSION.next_seq()),
                                      int(time.time() * 1000))
    list_env = ('{"security":{"sequence_id":"' + str(SESSION.next_seq())
                + '","command":"app_cert_list","timestamp":'
                + str(int(time.time() * 1000)) + ',"type":"app"}}')
    out = _mqtt_cycle(p["ip"], p["serial"], p["access_code"],
                      [env, list_env], collect_secs=6.0)

    installed = False
    for s in out["security"]:
        blob = json.dumps(s)
        if s.get("command") == "app_cert_install" and s.get("result") == "SUCCESS":
            installed = True
        if ident.serial_hex in blob or ident.cn in blob:
            installed = True
    SESSION.printer["cert_installed"] = installed
    SESSION.save()
    return {"installed": installed, "security": out["security"]}


def send_print(print_obj: dict):
    """Sign and send a print.* command, return the ack."""
    ident = SESSION.identity
    p = SESSION.printer
    if not ident:
        raise PrinterError("mint an identity first")
    seq = SESSION.next_seq()
    print_obj = {"sequence_id": seq, **print_obj}  # sequence_id must be a NUMBER
    wire = keyforge.sign_print_command(ident, print_obj, p.get("user_id") or "0")
    out = _mqtt_cycle(p["ip"], p["serial"], p["access_code"], [wire],
                      collect_secs=5.0)
    ack = next((a for a in out["acks"] if str(a.get("sequence_id")) == str(seq)), None)
    return {"sent": print_obj, "ack": ack or (out["acks"][-1] if out["acks"] else None),
            "all_acks": out["acks"]}


def send_light(on: bool):
    p = SESSION.printer
    mode = "on" if on else "off"
    env = ('{"system":{"command":"ledctrl","led_node":"chamber_light","led_mode":"'
           + mode + '","led_on_time":500,"led_off_time":500,"loop_times":0,'
           '"interval_time":0}}')
    _mqtt_cycle(p["ip"], p["serial"], p["access_code"], [env], collect_secs=2.0)
    return {"light": mode}


def get_status():
    p = SESSION.printer
    pushall = '{"pushing":{"sequence_id":"0","command":"pushall"}}'
    out = _mqtt_cycle(p["ip"], p["serial"], p["access_code"], [pushall],
                      collect_secs=4.0)
    r = out["report"]
    # pull out the fields people actually want to see
    summary = {k: r.get(k) for k in
               ("gcode_state", "mc_percent", "mc_remaining_time", "layer_num",
                "total_layer_num", "nozzle_temper", "bed_temper",
                "chamber_temper", "spd_lvl", "lights_report", "subtask_name",
                "print_error", "wifi_signal") if k in r}
    return {"summary": summary, "raw_keys": sorted(r.keys()),
            "report_count": out["report_count"], "raw": r}


# ===========================================================================
# USB bundle  (write everything the client needs onto the key)
# ===========================================================================
def usb_candidates():
    """Best-effort list of mounted removable volumes across platforms."""
    out = []
    roots = ["/media", "/run/media", "/mnt", "/Volumes"]
    # /run/media/<user>/<label>
    for base in roots:
        b = Path(base)
        if not b.is_dir():
            continue
        try:
            for entry in b.iterdir():
                if entry.is_dir():
                    # one level deeper for /media/<user>/<label>
                    kids = [k for k in entry.iterdir() if k.is_dir()] \
                        if entry.is_dir() and base in ("/media", "/run/media") else []
                    targets = kids or [entry]
                    for t in targets:
                        if os.access(t, os.W_OK):
                            out.append(str(t))
        except PermissionError:
            continue
    # de-dup, keep order
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def _readme_text(ident: keyforge.Identity, printer: dict) -> str:
    return f"""BambooSense identity bundle
===========================
Created : {ident.created}
Printer : serial {printer.get('serial') or ident.serial}

This folder is the key to talking to your Bambu Lab printer locally.
Carry it on the USB stick, then in the BambooSense web client choose
"Load from USB" and point it at this folder.

Files
-----
  identity-cert.pem   self-signed certificate installed on the printer
  identity-key.pem    PRIVATE KEY — keep this secret; it signs commands
  identity-crl.pem    revocation list (issuer matches the cert — required)
  printer-cert.pem    the printer's own cert, saved after install (if any)
  connection.json     everything the web client reads back in

cert_id : {ident.cert_id}

Security note: identity-key.pem can command your printer. Treat this USB
stick like a house key. Nothing here is useful to anyone without your
printer's IP and LAN access code.
"""


def export_bundle(dest_path: str):
    ident = SESSION.identity
    if not ident:
        raise PrinterError("mint an identity first")
    dest = Path(dest_path).expanduser()
    if not dest.exists():
        raise PrinterError(f"path does not exist: {dest}")
    if not dest.is_dir():
        raise PrinterError(f"not a directory: {dest}")
    folder = dest / BUNDLE_DIRNAME
    folder.mkdir(exist_ok=True)

    (folder / "identity-cert.pem").write_text(ident.cert_pem)
    (folder / "identity-key.pem").write_text(ident.key_pem)
    os.chmod(folder / "identity-key.pem", 0o600)
    (folder / "identity-crl.pem").write_text(ident.crl_pem)

    manifest = {
        "bamboosense_bundle": 1,
        "identity": ident.__dict__,
        "printer": {k: SESSION.printer.get(k, "") for k in
                    ("ip", "serial", "access_code", "user_id")},
        "note": "Load this with the BambooSense web client. identity-key.pem is secret.",
    }
    (folder / "connection.json").write_text(json.dumps(manifest, indent=2))
    os.chmod(folder / "connection.json", 0o600)
    (folder / "README.txt").write_text(_readme_text(ident, SESSION.printer))

    files = sorted(p.name for p in folder.iterdir())
    return {"folder": str(folder), "files": files}


def import_bundle(src_path: str):
    src = Path(src_path).expanduser()
    # accept either the folder or its parent
    for cand in (src, src / BUNDLE_DIRNAME):
        f = cand / "connection.json"
        if f.exists():
            d = json.loads(f.read_text())
            SESSION.identity = keyforge.load_identity(**d["identity"])
            for k in ("ip", "serial", "access_code", "user_id"):
                if d.get("printer", {}).get(k):
                    SESSION.printer[k] = d["printer"][k]
            SESSION.printer["cert_installed"] = False
            SESSION.save()
            return {"loaded_from": str(cand)}
    raise PrinterError(f"no connection.json found at {src}")


# ===========================================================================
# HTTP
# ===========================================================================
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quieter console
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        return json.loads(self.rfile.read(n) or b"{}")

    # ---- static ----
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            path = "/index.html"
        if path == "/api/state":
            return self._send(200, SESSION.state())
        if path == "/api/usb/list":
            return self._send(200, {"candidates": usb_candidates()})
        if path == "/api/printer/status":
            return self._guard(lambda: get_status())
        # serve static files
        f = (STATIC / path.lstrip("/")).resolve()
        if STATIC in f.parents or f == STATIC:
            if f.is_file():
                ctype = {".html": "text/html", ".js": "text/javascript",
                         ".css": "text/css"}.get(f.suffix, "application/octet-stream")
                return self._send(200, f.read_bytes(), ctype)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._body()
        except Exception as e:
            return self._send(400, {"error": f"bad json: {e}"})

        if path == "/api/generate":
            ident = keyforge.mint_identity(
                body.get("serial", ""), body.get("prefix", ""),
                int(body.get("days", 3650)))
            SESSION.identity = ident
            if body.get("serial") and not SESSION.printer["serial"]:
                SESSION.printer["serial"] = body["serial"]
            SESSION.printer["cert_installed"] = False
            SESSION.save()
            return self._send(200, {"identity": ident.public()})

        if path == "/api/printer/config":
            for k in ("ip", "serial", "access_code", "user_id"):
                if k in body:
                    SESSION.printer[k] = str(body[k]).strip()
            SESSION.save()
            return self._send(200, SESSION.state())

        if path == "/api/usb/export":
            return self._guard(lambda: export_bundle(body["path"]))
        if path == "/api/usb/import":
            return self._guard(lambda: import_bundle(body["path"]))
        if path == "/api/printer/install":
            return self._guard(install_cert)
        if path == "/api/printer/light":
            return self._guard(lambda: send_light(bool(body.get("on"))))
        if path == "/api/printer/command":
            return self._guard(lambda: send_print(body["print"]))

        return self._send(404, {"error": "not found"})

    def _guard(self, fn):
        try:
            return self._send(200, fn())
        except PrinterError as e:
            return self._send(400, {"error": str(e)})
        except KeyError as e:
            return self._send(400, {"error": f"missing field: {e}"})
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})


def main():
    port = int(os.environ.get("PORT", "8770"))
    host = os.environ.get("HOST", "127.0.0.1")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"BambooSense Keyforge → http://{host}:{port}")
    print(f"  mqtt available: {HAVE_MQTT}   workdir: {WORKDIR}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
