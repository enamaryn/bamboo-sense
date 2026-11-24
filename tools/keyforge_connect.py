#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keyforge_connect.py — BambooSense : se connecter a la P2S et la piloter (sans serveur)

A utiliser APRES keyforge_usb.py (qui a cree la cle d'identite sur ta cle USB).

Ce script :
  1. charge l'identite (cert + cle privee) depuis la cle USB — detectee toute
     seule, ou indiquee avec --bundle
  2. te demande (ou prend en argument) l'IP LAN, le code d'acces et le numero
     de serie de l'imprimante
  3. installe le certificat sur l'imprimante par le reseau (app_cert_install)
  4. ouvre un petit menu pour envoyer les commandes signees :
     statut / lumiere / pause / reprise / stop / effacer erreur / vitesse

Dependances :  pip install cryptography paho-mqtt
(le fichier connect.bat fourni a cote les installe pour toi sous Windows.)

Exemples :
  python keyforge_connect.py
  python keyforge_connect.py --ip 192.168.1.50 --code 12345678 --serial 01P...  --install
  python keyforge_connect.py --command pause
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time

# ---- dependances, avec messages clairs ----
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:
    print("\n[!] Il manque 'cryptography'.  Tape :  pip install cryptography\n")
    sys.exit(1)
try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("\n[!] Il manque 'paho-mqtt'.  Tape :  pip install paho-mqtt\n")
    sys.exit(1)


# ===========================================================================
# trouver et charger la cle d'identite (connection.json)
# ===========================================================================
def find_bundle(explicit):
    """Retourne le chemin d'un connection.json, ou None."""
    def check(p):
        if not p:
            return None
        if os.path.isfile(p) and p.endswith(".json"):
            return p
        for cand in (os.path.join(p, "connection.json"),
                     os.path.join(p, "BambooSense", "connection.json")):
            if os.path.isfile(cand):
                return cand
        return None

    if explicit:
        c = check(explicit)
        if c:
            return c
        print(f"[!] Aucun connection.json trouve a : {explicit}")
        return None

    # detection auto sur les cles USB
    roots = []
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        bitmask = kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = f"{chr(65 + i)}:\\"
                if kernel32.GetDriveTypeW(letter) in (2, 3):  # amovible ou fixe
                    roots.append(letter)
    else:
        for base in ("/Volumes", "/media", "/run/media", "/mnt"):
            if os.path.isdir(base):
                for e in os.listdir(base):
                    roots.append(os.path.join(base, e))
                    sub = os.path.join(base, e)
                    if os.path.isdir(sub):
                        for e2 in os.listdir(sub):
                            roots.append(os.path.join(sub, e2))
    for r in roots:
        c = check(r)
        if c:
            return c
    return None


def load_identity(bundle_path):
    d = json.load(open(bundle_path, encoding="utf-8"))
    ident = d["identity"]
    printer = d.get("printer", {})
    return ident, printer


# ===========================================================================
# signature d'une commande print.*  (identique au firmware verifie)
# ===========================================================================
def sign_command(ident, top, obj, user_id):
    """Signe une commande `<top>.*` (print ou system) et renvoie le JSON complet.

    L'imprimante RECANONICALISE en CLES TRIEES avant de verifier la signature.
    Les commandes deja validees (pause/print_speed) avaient leurs cles deja dans
    l'ordre alphabetique, ce qui masquait le probleme : l'erreur 0x0502400A
    ("wrong canonical form") apparait des qu'une cle sort de cet ordre.
    """
    key = serialization.load_pem_private_key(ident["key_pem"].encode(), None)
    obj_json = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    inner = '{"' + top + '":' + obj_json + ',"user_id":"' + user_id + '"}'
    inner_bytes = inner.encode()
    sig = key.sign(inner_bytes, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode()
    header = (',"header":{"sign_ver":"v1.0","sign_alg":"RSA_SHA256","sign_string":"'
              + sig_b64 + '","cert_id":"' + ident["cert_id"]
              + '","payload_len":' + str(len(inner_bytes)) + "}")
    return inner[:-1] + header + "}"


def sign_print_command(ident, print_obj, user_id):
    return sign_command(ident, "print", print_obj, user_id)


def build_cert_install(ident, seq, ts_ms):
    def pem(p):
        return p.replace("\r", "").replace("\n", "\\n")
    return ('{"security":{"sequence_id":"' + str(seq) + '","command":"app_cert_install"'
            + ',"timestamp":' + str(ts_ms) + ',"type":"app"'
            + ',"app_cert":"' + pem(ident["cert_pem"]) + '"'
            + ',"crl":"' + pem(ident["crl_pem"]) + '"}}')


# ===========================================================================
# lien MQTT vers l'imprimante : connecter -> publier -> ecouter
# ===========================================================================
class Printer:
    def __init__(self, ip, serial, code):
        self.ip, self.serial, self.code = ip, serial, code
        self._seq = 100000 + int(time.time()) % 50000
        self.printer_cert = None   # la cle publique de l'imprimante (pour param_enc / homing)

    def next_seq(self):
        self._seq += 1
        return self._seq

    def _cycle(self, publishes, collect=4.0):
        reports, secs, acks = [], [], []

        def on_connect(c, u, flags, rc, *a):
            c.subscribe(f"device/{self.serial}/report", 0)

        def on_message(c, u, m):
            try:
                d = json.loads(m.payload)
            except Exception:
                return
            if "security" in d:
                secs.append(d["security"])
            if "print" in d:
                reports.append(d["print"])
            # un ACK peut arriver sous "print" OU "system" selon la commande
            for top in ("print", "system"):
                p = d.get(top)
                if isinstance(p, dict) and ("result" in p or str(p.get("sequence_id", "")).isdigit()):
                    acks.append({k: p.get(k) for k in
                                 ("command", "result", "reason", "err_code", "sequence_id")
                                 if k in p})

        # paho 2.x veut une version d'API explicite ; 1.x ne connait pas l'argument
        cid = f"kf-{int(time.time())}"
        if hasattr(mqtt, "CallbackAPIVersion"):
            c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=cid,
                            protocol=mqtt.MQTTv311)
        else:
            c = mqtt.Client(client_id=cid, protocol=mqtt.MQTTv311)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c.tls_set_context(ctx)
        c.username_pw_set("bblp", self.code)
        c.on_connect = on_connect
        c.on_message = on_message
        try:
            c.connect(self.ip, 8883, keepalive=30)
        except OSError as e:
            raise RuntimeError(
                f"connexion impossible a {self.ip}:8883 ({e}). "
                "Verifie l'IP, que l'imprimante est allumee et sur le meme reseau, "
                "et que le port 8883 n'est pas bloque.") from None
        c.loop_start()
        time.sleep(1.2)
        for pub in publishes:
            c.publish(f"device/{self.serial}/request", pub)
            time.sleep(0.3)
        time.sleep(collect)
        c.loop_stop()
        try:
            c.disconnect()
        except Exception:
            pass
        merged = {}
        for r in reports:
            merged.update(r)
        return {"report": merged, "security": secs, "acks": acks,
                "report_count": len(reports)}

    # ---- actions ----
    def install(self, ident):
        env = build_cert_install(ident, self.next_seq(), int(time.time() * 1000))
        lst = ('{"security":{"sequence_id":"' + str(self.next_seq())
               + '","command":"app_cert_list","timestamp":'
               + str(int(time.time() * 1000)) + ',"type":"app"}}')
        out = self._cycle([env, lst], collect=6.0)
        ok = False
        for s in out["security"]:
            blob = json.dumps(s)
            if s.get("command") == "app_cert_install" and s.get("result") == "SUCCESS":
                ok = True
            if ident["serial_hex"] in blob or ident["cn"] in blob:
                ok = True
            # l'imprimante renvoie sa propre cle publique -> indispensable pour le G-code (homing)
            for field in ("printer_cert", "cert", "dev_cert"):
                v = s.get(field)
                if isinstance(v, str) and "BEGIN CERTIFICATE" in v:
                    self.printer_cert = v.replace("\\n", "\n")
        return ok, out["security"]

    def _encrypt_to_printer(self, data: bytes):
        """Chiffre RSA les octets vers la cle publique de l'imprimante (param_enc)."""
        if not self.printer_cert:
            return None
        cert = x509.load_pem_x509_certificate(self.printer_cert.encode())
        ct = cert.public_key().encrypt(data, padding.PKCS1v15())
        return base64.b64encode(ct).decode()

    def gcode(self, ident, line, user_id):
        """Envoie une ligne de G-code signee. Si on a la cle de l'imprimante,
        le parametre est chiffre (param_enc) comme l'exige le firmware verrouille ;
        sinon on tente en clair (param)."""
        if not line.endswith("\n"):
            line += "\n"
        enc = self._encrypt_to_printer(line.encode())
        if enc:
            obj = {"command": "gcode_line", "param_enc": enc}
        else:
            obj = {"command": "gcode_line", "param": line}
        return self.send_print(ident, obj, user_id), bool(enc)

    def send_signed(self, ident, top, obj, user_id):
        seq = self.next_seq()
        o = {"sequence_id": seq, **obj}
        wire = sign_command(ident, top, o, user_id or "0")
        out = self._cycle([wire], collect=5.0)
        ack = next((a for a in out["acks"] if str(a.get("sequence_id")) == str(seq)), None)
        return ack or (out["acks"][-1] if out["acks"] else None)

    def send_print(self, ident, print_obj, user_id):
        return self.send_signed(ident, "print", print_obj, user_id)

    def light(self, ident, on, user_id):
        """Lumiere du caisson. Sur firmware verrouille, les commandes non signees
        sont ignorees : on envoie donc une system.ledctrl SIGNEE et on lit l'ACK."""
        mode = "on" if on else "off"
        obj = {"command": "ledctrl", "led_node": "chamber_light", "led_mode": mode,
               "led_on_time": 500, "led_off_time": 500, "loop_times": 0,
               "interval_time": 0}
        return self.send_signed(ident, "system", obj, user_id)

    def status(self):
        out = self._cycle(['{"pushing":{"sequence_id":"0","command":"pushall"}}'], collect=4.0)
        r = out["report"]
        keys = ("gcode_state", "mc_percent", "mc_remaining_time", "layer_num",
                "total_layer_num", "nozzle_temper", "bed_temper", "chamber_temper",
                "spd_lvl", "subtask_name", "print_error")
        return {k: r.get(k) for k in keys if k in r}, out["report_count"]


# ===========================================================================
# interface
# ===========================================================================
def ask(prompt, default=""):
    s = input(f"{prompt}" + (f" [{default}]" if default else "") + " : ").strip()
    return s or default


def menu(pr, ident, user_id):
    actions = {
        "1": ("Statut",         lambda: do_status(pr)),
        "2": ("Lumiere ON",     lambda: do_light(pr, ident, user_id, True)),
        "3": ("Lumiere OFF",    lambda: do_light(pr, ident, user_id, False)),
        "4": ("Pause",          lambda: do_cmd(pr, ident, user_id, {"command": "pause"})),
        "5": ("Reprise",        lambda: do_cmd(pr, ident, user_id, {"command": "resume"})),
        "6": ("Stop",           lambda: do_cmd(pr, ident, user_id, {"command": "stop"})),
        "7": ("Effacer erreur", lambda: do_cmd(pr, ident, user_id, {"command": "clean_print_error"})),
        "8": ("Vitesse",        lambda: do_speed(pr, ident, user_id)),
        "9": ("HOMING (G28) — test", lambda: do_home(pr, ident, user_id)),
        "0": ("G-code libre",   lambda: do_gcode(pr, ident, user_id)),
        "i": ("Reinstaller le certificat", lambda: do_install(pr, ident)),
    }
    while True:
        print("\n--- Commandes P2S ---")
        for k, (label, _) in actions.items():
            print(f"  {k}) {label}")
        print("  q) Quitter")
        choice = input("Choix : ").strip().lower()
        if choice == "q":
            print("A bientot.")
            return
        act = actions.get(choice)
        if not act:
            print("    choix invalide")
            continue
        try:
            act[1]()
        except Exception as e:
            print(f"    [!] erreur : {e}")


def do_status(pr):
    print("    ...interrogation...")
    s, n = pr.status()
    if not n:
        print("    [!] aucune reponse — verifie IP / code / serie, et que l'imprimante est allumee")
        return
    print(f"    etat        : {s.get('gcode_state','?')}")
    print(f"    progression : {s.get('mc_percent','?')} %   couche {s.get('layer_num','?')}/{s.get('total_layer_num','?')}")
    print(f"    buse {s.get('nozzle_temper','?')}°  plateau {s.get('bed_temper','?')}°  caisson {s.get('chamber_temper','?')}°")
    if s.get("subtask_name"):
        print(f"    tache       : {s['subtask_name']}")
    if s.get("print_error"):
        print(f"    print_error : {s['print_error']}")


def _show_ack(ack):
    if not ack:
        print("    [!] aucun accuse de reception (ACK) — commande probablement ignoree")
        return
    r = ack.get("result", "?")
    extra = f" ({ack.get('reason')})" if ack.get("reason") else ""
    ec = f"  err_code={ack.get('err_code')}" if ack.get("err_code") else ""
    print(f"    -> {r}{extra}{ec}")


def do_cmd(pr, ident, user_id, obj):
    print(f"    ...envoi {obj['command']}...")
    _show_ack(pr.send_print(ident, obj, user_id))


def do_light(pr, ident, user_id, on):
    print(f"    ...lumiere {'ON' if on else 'OFF'} (signee)...")
    _show_ack(pr.light(ident, on, user_id))


def do_speed(pr, ident, user_id):
    print("    vitesse : 1=Silencieux  2=Standard  3=Sport  4=Ludicrous")
    v = ask("    niveau", "2")
    do_cmd(pr, ident, user_id, {"command": "print_speed", "param": v})


def do_home(pr, ident, user_id):
    print("    ...envoi du HOMING (G28)...")
    if not pr.printer_cert:
        print("    [i] cle publique de l'imprimante inconnue -> installe d'abord le")
        print("        certificat (option i). Tentative en clair quand meme.")
    ack, enc = pr.gcode(ident, "G28", user_id)
    print(f"    mode : {'param_enc (chiffre)' if enc else 'param (clair)'}")
    if not ack:
        print("    [!] aucun ACK — commande probablement refusee.")
    else:
        r = ack.get("result", "?")
        extra = f" ({ack.get('reason')})" if ack.get("reason") else ""
        ec = f"  err_code={ack.get('err_code')}" if ack.get("err_code") else ""
        print(f"    -> {r}{extra}{ec}")
        if r == "SUCCESS":
            print("    L'imprimante devrait lancer son homing (les axes bougent).")


def do_gcode(pr, ident, user_id):
    line = ask("    ligne G-code (ex. G28 / G1 Z10 F600)")
    if not line:
        return
    ack, enc = pr.gcode(ident, line, user_id)
    print(f"    mode : {'param_enc' if enc else 'param'}")
    if ack:
        print(f"    -> {ack.get('result','?')}" + (f" ({ack['reason']})" if ack.get("reason") else ""))
    else:
        print("    [!] aucun ACK")


def do_install(pr, ident):
    print("    ...installation du certificat sur l'imprimante...")
    ok, sec = pr.install(ident)
    if ok:
        print("    -> certificat INSTALLE et confirme par l'imprimante.")
    else:
        print("    [!] pas de confirmation. Reponses securite :")
        print("        " + (json.dumps(sec)[:300] if sec else "(aucune — cert/CRL rejetes ?)"))


def main():
    ap = argparse.ArgumentParser(description="Connecte-toi a la P2S et pilote-la.")
    ap.add_argument("--bundle", help="chemin du connection.json / dossier / cle USB")
    ap.add_argument("--ip", help="IP LAN de l'imprimante")
    ap.add_argument("--code", help="code d'acces LAN")
    ap.add_argument("--serial", help="numero de serie de l'imprimante")
    ap.add_argument("--user-id", default="", help="user_id (optionnel)")
    ap.add_argument("--install", action="store_true", help="installer le cert puis ouvrir le menu")
    ap.add_argument("--command", help="une seule commande puis quitter "
                                       "(status|light-on|light-off|pause|resume|stop|clear|home)")
    args = ap.parse_args()

    print("=" * 58)
    print("  BambooSense — connexion a l'imprimante (P2S)")
    print("=" * 58)

    # 1. identite
    bundle = find_bundle(args.bundle)
    if not bundle:
        print("[!] Cle d'identite introuvable.")
        print("    Lance d'abord keyforge_usb.py, ou passe --bundle <chemin de la cle>.")
        sys.exit(1)
    ident, pconf = load_identity(bundle)
    print(f"[+] Identite chargee depuis : {bundle}")
    print(f"    cert_id = {ident['cert_id']}")

    # 2. champs de connexion (priorite : argument > bundle > saisie)
    ip = args.ip or pconf.get("ip") or ""
    code = args.code or pconf.get("access_code") or ""
    serial = args.serial or pconf.get("serial") or ident.get("serial") or ""
    user_id = args.user_id or pconf.get("user_id") or ""

    if not args.command:  # en mode interactif, on confirme/complete les champs
        print("\n--- Connexion a l'imprimante ---")
        ip = ask("IP LAN de l'imprimante", ip)
        code = ask("Code d'acces LAN", code)
        serial = ask("Numero de serie machine", serial)

    if not (ip and code and serial):
        print("[!] IP, code d'acces et numero de serie sont tous requis.")
        sys.exit(1)

    pr = Printer(ip, serial, code)

    # 3. commande unique ?
    if args.command:
        cmap = {"status": lambda: do_status(pr),
                "light-on": lambda: do_light(pr, ident, user_id, True),
                "light-off": lambda: do_light(pr, ident, user_id, False),
                "pause": lambda: do_cmd(pr, ident, user_id, {"command": "pause"}),
                "resume": lambda: do_cmd(pr, ident, user_id, {"command": "resume"}),
                "stop": lambda: do_cmd(pr, ident, user_id, {"command": "stop"}),
                "clear": lambda: do_cmd(pr, ident, user_id, {"command": "clean_print_error"}),
                "home": lambda: (do_install(pr, ident), do_home(pr, ident, user_id)),
                "install": lambda: do_install(pr, ident)}
        fn = cmap.get(args.command)
        if not fn:
            print(f"[!] commande inconnue : {args.command}")
            sys.exit(1)
        fn()
        return

    # 4. installation (auto si jamais faite) puis menu
    if args.install:
        do_install(pr, ident)
    else:
        print("\n[*] Installation du certificat (necessaire au moins une fois)...")
        do_install(pr, ident)

    menu(pr, ident, user_id)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnnule.")
    except Exception as e:
        print(f"\n[!] Erreur : {e}")
        sys.exit(1)
