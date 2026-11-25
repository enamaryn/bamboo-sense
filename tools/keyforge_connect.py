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
import datetime
import json
import os
import ssl
import sys
import time

# -------- journal de debug (ecrit tout : envois, receptions, ACK, erreurs) ----
LOG_PATH = None


def logln(msg: str):
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    line = f"{stamp}  {msg}"
    if LOG_PATH:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

# ---- dependances, avec messages clairs ----
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
    import datetime as _dt
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


# CRL GLOF codee en dur dans le firmware (issuer CN=GLOF3813734089.bambulab.com).
# Sert a (re)installer un leaf Studio reel : issuer(leaf)==issuer(crl)==GLOF... .
BAKED_GLOF_CRL = (
    "-----BEGIN X509 CRL-----\n"
    "MIIB6jCB0wIBATANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtHTE9GMzgxMzcz\n"
    "NDA4OS5iYW1idWxhYi5jb20XDTI0MTIyODAzNDkyMloXDTI1MDEyODA0NDkyMlow\n"
    "SDAiAhEAwKnG9y7waEObyjeMvq6AsRcNMjQxMjIwMDczODQ0WjAiAhEA8Nae8vkm\n"
    "xTtjKidwSnzKexcNMjQxMjE5MDgwMjQ1WqAvMC0wHwYDVR0jBBgwFoAUwsnRLS7p\n"
    "ktqZJwMZozos0xysCJswCgYDVR0UBAMCAXswDQYJKoZIhvcNAQELBQADggEBAIV+\n"
    "jSqHblK7ZEH6eb8T7zFsFBPTrr4DKmwcBarCq9OLUtN/FSCcGXnVP6dWU06+RhE0\n"
    "mSwh6ER6LDQEupYXpOerZPE0zQOa5q/CsfTAtpBndMsKM9jKFTh0+Gr7V46fkuM\n"
    "kJ7UeO17FddDtfCDqxIvheo/RPvZPoiNuCpUQuGAI59O3kFqNkv6VsZlk+7E/D1Q\n"
    "aSiKr+bk6+hWslSLtenA4rxZNcL8cq7AYijLPlE2HTN6ASCMx/bBZXzm28KHDyeR\n"
    "FtfnJsmWXBbeOqHmR9/JpSbJdXRD6jvXF2nQVgQcAqv3DZcOhov0ah+31foAe2/e\n"
    "aRANWl5wMJ5nUd5UFCk=\n"
    "-----END X509 CRL-----\n"
)


def cert_id_from_pem(cert_pem):
    """cert_id = serial(hex minuscule) + issuer(RFC4514), depuis le leaf (1er cert)."""
    c = x509.load_pem_x509_certificate(cert_pem.encode())
    return format(c.serial_number, "x") + c.issuer.rfc4514_string()


def _read_cert_flexible(path):
    """Lit un cert en PEM, ou en base64 de DER (slicer_base64.cer de Studio)."""
    from pathlib import Path as _P
    raw = _P(path).read_text(errors="ignore").strip()
    if "BEGIN CERTIFICATE" in raw:
        return raw if raw.endswith("\n") else raw + "\n"
    der = base64.b64decode("".join(raw.split()))
    c = x509.load_der_x509_certificate(der)
    return c.public_bytes(serialization.Encoding.PEM).decode()


def find_studio_material(studio_dir=None):
    """Cherche la cle Studio (slicer_key.pem) + le cert Studio produits par
    BambuSlicerKeySaver / livres avec Bambu Studio. Renvoie (key_path, cert_pem)."""
    home = os.path.expanduser("~")
    dirs = []
    if studio_dir:
        dirs.append(studio_dir)
    for env in ("APPDATA", "LOCALAPPDATA", "USERPROFILE", "PROGRAMFILES",
                "PROGRAMFILES(X86)"):
        v = os.environ.get(env)
        if v:
            dirs += [os.path.join(v, "BambuStudio"), v]
    dirs += [os.path.join(home, ".config", "BambuStudio"),
             os.path.join(home, "Library", "Application Support", "BambuStudio"),
             home, ".", os.path.dirname(os.path.abspath(__file__))]
    key_names = ["slicer_key.pem", "key.pem", "slicer_key.txt", "app_key.pem",
                 os.path.join("appcert_out", "app_key.pem"),
                 os.path.join("autocap", "out", "slicer_key.pem")]
    key_path = None
    for d in dirs:
        for kn in key_names:
            p = os.path.join(d, kn)
            if os.path.isfile(p):
                key_path = p
                break
        if key_path:
            break
    # CRL (BambuKeySaver: crl.pem ; frais depuis le cloud = indispensable)
    crl_path = None
    for d in dirs:
        for cn in ("crl.pem", "slicer_crl.pem"):
            p = os.path.join(d, cn)
            if os.path.isfile(p):
                crl_path = p
                break
        if crl_path:
            break
    cert_pem = None
    cert_names = ["chain.pem", "slicer_cert.pem", "cert_0.pem", "slicer.pem",
                  "app_cert.pem", os.path.join("appcert_out", "app_cert.pem"),
                  os.path.join("cert", "slicer_base64.cer"),
                  os.path.join("resources", "cert", "slicer_base64.cer"),
                  "slicer_base64.cer"]
    for d in dirs:
        for n in cert_names:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                try:
                    cert_pem = _read_cert_flexible(p)
                    break
                except Exception:
                    pass
        if cert_pem:
            break
    return key_path, cert_pem, crl_path


def load_studio_identity(key_path, cert_path=None, cert_id=None, crl_path=None,
                         cert_pem=None):
    """Construit une identite de signature a partir de la cle Studio partagee.
    Le leaf Studio etant reel (emis par GLOF3813734089), on peut le (re)installer
    avec la CRL GLOF du firmware pour garantir qu'il est de confiance, puis signer."""
    from pathlib import Path as _P
    key_pem = _P(key_path).read_text()
    if cert_pem is None:
        cert_pem = _read_cert_flexible(cert_path) if cert_path else ""
    if cert_id and os.path.isfile(cert_id):
        cert_id = _P(cert_id).read_text().strip()
    if not cert_id:
        if not cert_pem:
            raise RuntimeError("fournis --studio-cert ou --studio-cert-id avec --studio-key")
        cert_id = cert_id_from_pem(cert_pem)
    # verif : la cle correspond-elle bien au cert ? (meme modulus RSA)
    if cert_pem:
        try:
            kpub = serialization.load_pem_private_key(key_pem.encode(), None).public_key()
            cpub = x509.load_pem_x509_certificate(cert_pem.encode()).public_key()
            if kpub.public_numbers().n != cpub.public_numbers().n:
                print("    [!] ATTENTION : la cle Studio et le cert ne correspondent PAS")
                print("        (modulus different -> versions differentes de Studio ?).")
                print("        La signature sera refusee. Fournis un cert assorti a la cle.")
        except Exception:
            pass
    # CRL : fournie, sinon la CRL GLOF du firmware si le leaf est emis par GLOF...
    if crl_path:
        crl_pem = _P(crl_path).read_text()
    elif cert_pem and "GLOF3813734089" in cert_id:
        crl_pem = BAKED_GLOF_CRL
    else:
        crl_pem = ""
    return {"key_pem": key_pem, "cert_pem": cert_pem, "crl_pem": crl_pem,
            "cert_id": cert_id, "cn": "studio-app", "serial_hex": "",
            "serial": "studio", "created": "", "studio": True}


# ===========================================================================
# signature d'une commande print.*  (identique au firmware verifie)
# ===========================================================================
def _rsa_sign(key, data, pad="pkcs1", salt_len=32):
    if pad == "pss":
        sl = padding.PSS.MAX_LENGTH if salt_len is None else salt_len
        return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=sl), hashes.SHA256())
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def sign_command(ident, top, obj, pad="pkcs1", salt_len=32, sign_alg="RSA_SHA256",
                 **_ignore):
    """Signe une commande `<top>.*` selon le schema verifie sur materiel
    (ClusterM/open-bamboo-networking §10.4) :

      - on signe EXACTEMENT les octets   {"<top>":<valeur>}   (sans user_id,
        sans rien d'autre) ;
      - le `header` est place EN PREMIER dans l'enveloppe :
        {"header":{...},"<top>":<valeur>} ;
      - cert_id = serial(hex, minuscule) + issuer(RFC4514, p.ex. CN=...) ;
      - la valeur serialisee signee doit etre OCTET-POUR-OCTET identique a
        celle emise sur le fil (on reutilise la meme chaine).

    Le firmware reconstruit les octets signes en retirant le prefixe
    {"header":{...}, puis en reprefixant {. D'ou l'obligation du header EN TETE."""
    key = serialization.load_pem_private_key(ident["key_pem"].encode(), None)
    value = json.dumps(obj, separators=(",", ":"))          # serialise UNE fois
    signed = '{"' + top + '":' + value + '}'                 # exactement ce qui est signe
    sig = _rsa_sign(key, signed.encode(), pad=pad, salt_len=salt_len)
    header = ('{"sign_ver":"v1.0","sign_alg":"' + sign_alg
              + '","sign_string":"' + base64.b64encode(sig).decode()
              + '","cert_id":"' + ident["cert_id"]
              + '","payload_len":' + str(len(signed.encode())) + "}")
    # header EN PREMIER, puis la MEME chaine `value` qu'on a signee
    return '{"header":' + header + ',"' + top + '":' + value + '}'


def sign_print_command(ident, print_obj, user_id=""):
    return sign_command(ident, "print", print_obj)


# quand la signature est encore refusee : essai pkcs1 puis pss (padding RSA).
PROBE_MATRIX = [
    ("pkcs1", dict(pad="pkcs1"), False),
    ("pss32", dict(pad="pss", salt_len=32), False),
    ("pssMAX", dict(pad="pss", salt_len=None), False),
]


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
            logln(f"CONNECT rc={rc}  SUB device/{self.serial}/report")

        def on_message(c, u, m):
            raw = m.payload.decode("utf-8", "replace")
            logln(f"RX  {raw[:4000]}")
            try:
                d = json.loads(m.payload)
            except Exception as e:
                logln(f"RX  (json non parse: {e})")
                return
            if "security" in d:
                secs.append(d["security"])
            if "print" in d:
                reports.append(d["print"])
            # un ACK peut arriver sous "print" OU "system" selon la commande
            for top in ("print", "system"):
                p = d.get(top)
                if isinstance(p, dict) and ("result" in p or str(p.get("sequence_id", "")).isdigit()):
                    a = {k: p.get(k) for k in
                         ("command", "result", "reason", "err_code", "sequence_id") if k in p}
                    acks.append(a)
                    logln(f"ACK {json.dumps(a)}")

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
        logln(f"-- cycle: connect {self.ip}:8883  serial={self.serial}  "
              f"publishes={len(publishes)}  collect={collect}s")
        try:
            c.connect(self.ip, 8883, keepalive=30)
        except OSError as e:
            logln(f"ERR connect {self.ip}:8883 -> {e}")
            raise RuntimeError(
                f"connexion impossible a {self.ip}:8883 ({e}). "
                "Verifie l'IP, que l'imprimante est allumee et sur le meme reseau, "
                "et que le port 8883 n'est pas bloque.") from None
        c.loop_start()
        time.sleep(1.2)
        for pub in publishes:
            info = c.publish(f"device/{self.serial}/request", pub)
            logln(f"TX  rc={getattr(info, 'rc', '?')}  {pub[:4000]}")
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
        logln(f"-- cycle fin: reports={len(reports)}  security={len(secs)}  acks={len(acks)}")
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
                    logln(f"printer_cert capture (champ '{field}', {len(v)} car.)")
        logln(f"INSTALL ok={ok}  printer_cert={'oui' if self.printer_cert else 'NON'}")
        return ok, out["security"]

    def _encrypt_to_printer(self, data: bytes):
        """Chiffre RSA les octets vers la cle publique de l'imprimante (param_enc)."""
        if not self.printer_cert:
            return None
        cert = x509.load_pem_x509_certificate(self.printer_cert.encode())
        ct = cert.public_key().encrypt(data, padding.PKCS1v15())
        return base64.b64encode(ct).decode()

    def gcode(self, ident, line, encrypt=False, **sign_kw):
        """Envoie une ligne de G-code signee.
        encrypt=False : param en CLAIR (project_file accepte bien une url en clair).
        encrypt=True  : param_enc, chiffre vers la cle publique de l'imprimante.
        sign_kw : options de signature (user_id, include_uid, pad, salt_len...)."""
        if not line.endswith("\n"):
            line += "\n"
        if encrypt:
            enc = self._encrypt_to_printer(line.encode())
            if not enc:
                obj = {"command": "gcode_line", "param": line}
                mode = "param(clair, faute de cle)"
            else:
                obj = {"command": "gcode_line", "param_enc": enc}
                mode = "param_enc(chiffre)"
        else:
            obj = {"command": "gcode_line", "param": line}
            mode = "param(clair)"
        logln(f"GCODE {line!r}  mode={mode}  sign_kw={sign_kw}")
        return self.send_signed(ident, "print", obj, **sign_kw), mode

    def send_signed(self, ident, top, obj, **kw):
        seq = self.next_seq()
        o = {"sequence_id": seq, **obj}
        wire = sign_command(ident, top, o, **kw)
        out = self._cycle([wire], collect=5.0)
        ack = next((a for a in out["acks"] if str(a.get("sequence_id")) == str(seq)), None)
        return ack or (out["acks"][-1] if out["acks"] else None)

    def send_print(self, ident, print_obj, user_id="", include_uid=True):
        return self.send_signed(ident, "print", print_obj,
                                user_id=user_id, include_uid=include_uid)

    def send_unsigned(self, top, obj):
        """Publie une commande SANS header (fonctionne si le Mode Developpeur
        est actif sur l'imprimante : la verif de signature est alors ignoree)."""
        seq = self.next_seq()
        o = {"sequence_id": seq, **obj}
        wire = '{"' + top + '":' + json.dumps(o, separators=(",", ":")) + "}"
        logln(f"UNSIGNED {wire[:120]}")
        out = self._cycle([wire], collect=5.0)
        return next((a for a in out["acks"] if str(a.get("sequence_id")) == str(seq)), None) \
            or (out["acks"][-1] if out["acks"] else None)

    def probe_signature(self, ident):
        """Essaie la matrice (padding x forme x timestamp) avec clean_print_error
        (inoffensif). Renvoie [(libelle, kwargs, ack), ...]."""
        results = []
        for label, kw, add_ts in PROBE_MATRIX:
            obj = {"command": "clean_print_error"}
            if add_ts:
                obj["timestamp"] = int(time.time() * 1000)
            ack = self.send_signed(ident, "print", obj, **kw)
            logln(f"PROBE {label} -> {json.dumps(ack)}")
            results.append((label, kw, ack))
        return results

    def light(self, ident, on, user_id):
        """Lumiere du caisson (system.ledctrl). Contrairement a print.*, cette
        commande n'est PAS signee et ne prend PAS de sequence_id : signee, la
        P2S repond 'json wrong format'. On envoie la forme exacte du firmware
        et on lit la reponse de l'imprimante (elle echo la commande avec result)."""
        mode = "on" if on else "off"
        seq = str(self.next_seq())  # system.* veut un sequence_id en CHAINE
        env = ('{"system":{"sequence_id":"' + seq + '","command":"ledctrl",'
               '"led_node":"chamber_light","led_mode":"' + mode + '",'
               '"led_on_time":500,"led_off_time":500,"loop_times":0,"interval_time":0}}')
        acks = self._cycle([env], collect=3.0)["acks"]
        return next((a for a in acks if a.get("command") == "ledctrl"), None)

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
    print(f"    ...lumiere {'ON' if on else 'OFF'}...")
    ack = pr.light(ident, on, user_id)
    if ack is None:
        print("    -> pas de reponse ledctrl (regarde si la lumiere a change ; voir le journal)")
    else:
        _show_ack(ack)


def do_speed(pr, ident, user_id):
    print("    vitesse : 1=Silencieux  2=Standard  3=Sport  4=Ludicrous")
    v = ask("    niveau", "2")
    do_cmd(pr, ident, user_id, {"command": "print_speed", "param": v})


def _ack_ok(ack):
    """True si l'ACK n'est pas un echec de signature."""
    if not ack:
        return False
    r = str(ack.get("result", "")).lower()
    return r in ("success", "ok") or (r not in ("failed", "fail")
                                      and ack.get("err_code") != 84033546)


def _fmt(ack):
    if not ack:
        return "aucun ACK"
    r = ack.get("result") or "?"
    extra = f" ({ack.get('reason')})" if ack.get("reason") else ""
    ec = f"  err_code={ack.get('err_code')}" if ack.get("err_code") else ""
    return f"{r}{extra}{ec}"


def _home_try(pr, ident, sign_kw, encrypt=False):
    ack, mode = pr.gcode(ident, "G28", encrypt=encrypt, **sign_kw)
    print(f"    [{mode}] -> {_fmt(ack)}")
    return ack


def do_home(pr, ident, user_id):
    print("    ...HOMING (G28)...")
    # 1) MODE DEVELOPPEUR : commande NON signee (le firmware ignore la signature)
    print("    1) essai NON signe (= Mode Developpeur) ...")
    ack = pr.send_unsigned("print", {"command": "gcode_line", "param": "G28\n"})
    print(f"       -> {_fmt(ack)}")
    if _ack_ok(ack):
        print("       OK ! Mode Developpeur actif : aucune signature necessaire. Axes en mouvement.")
        return
    ec = ack.get("err_code") if ack else None
    if ec == 84033543:
        print("       (84033543 = 'non signe refuse' -> imprimante en mode SECURISE)")

    # 2) SIGNE avec l'identite courante (cert auto-signe, ou cle Studio si chargee)
    print("    2) essai SIGNE avec l'identite courante ...")
    ack2, _ = pr.gcode(ident, "G28", encrypt=False)
    print(f"       -> {_fmt(ack2)}")
    if _ack_ok(ack2):
        print("       OK signe : axes en mouvement.")
        return

    ec2 = ack2.get("err_code") if ack2 else None
    print()
    if ec2 == 84033546:   # 0x0502400A bad signature
        print("    [DIAGNOSTIC] 0x0502400A 'bad signature' : ce certificat n'est pas")
        print("    de confiance pour SIGNER sur ce firmware securise (il ne chaine pas")
        print("    jusqu'a la racine Bambu). Deux solutions :")
        print("      a) activer le MODE DEVELOPPEUR sur l'imprimante -> l'essai 1 marchera ;")
        print("      b) fournir la vraie cle Studio partagee : relance avec")
        print("         --studio-key slicer_key.pem --studio-cert-id slicer_cert_id.txt")
        print("         (extraite de Bambu Studio, p.ex. via BambuSlicerKeySaver).")
    elif ec2 == 84033545:
        print("    [DIAGNOSTIC] 84033545 : signature valide mais cert_id absent du trust")
        print("    store (reboot l'a vide). Reinstalle le cert (option i) puis reessaie.")
    else:
        print("    [i] echec. Envoie le journal (keyforge_connect.log).")


def do_gcode(pr, ident, user_id):
    line = ask("    ligne G-code (ex. G28 / G1 Z10 F600)")
    if not line:
        return
    enc = ask("    chiffrer param_enc ? (o/N)", "n").lower().startswith("o")
    ack, mode = pr.gcode(ident, line, encrypt=enc, user_id=user_id)
    print(f"    mode : {mode}")
    if ack:
        print(f"    -> {ack.get('result','?')}" + (f" ({ack['reason']})" if ack.get("reason") else "")
              + (f"  err_code={ack['err_code']}" if ack.get("err_code") else ""))
    else:
        print("    [!] aucun ACK")


def do_install(pr, ident):
    # En mode Studio sans chaine+CRL fournies, rien a installer : le leaf Studio
    # est deja de confiance sur l'imprimante (ne pas pousser un cert auto-signe).
    if ident.get("studio") and not (ident.get("cert_pem") and ident.get("crl_pem")):
        print("    [i] cle Studio : installation ignoree (le leaf Studio est deja")
        print("        de confiance ; fournis --studio-cert + --studio-crl pour reinstaller).")
        return
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
    ap.add_argument("--log", help="fichier journal (defaut : keyforge_connect.log a cote du script)")
    ap.add_argument("--install", action="store_true", help="installer le cert puis ouvrir le menu")
    ap.add_argument("--studio-key", help="cle privee Studio partagee (slicer_key.pem) "
                                         "pour signer sur firmware securise")
    ap.add_argument("--studio-cert", help="cert/chaine Studio (slicer_cert.pem) — sert a "
                                          "deriver le cert_id et, avec --studio-crl, a (re)installer")
    ap.add_argument("--studio-cert-id", help="cert_id Studio (slicer_cert_id.txt ou la chaine) "
                                             "si on ne passe pas --studio-cert")
    ap.add_argument("--studio-crl", help="CRL Studio (slicer_crl.pem) pour reinstaller la chaine")
    ap.add_argument("--studio-dir", help="dossier ou chercher slicer_key.pem + cert Studio")
    ap.add_argument("--no-auto-studio", action="store_true",
                    help="ne pas auto-detecter la cle Studio (slicer_key.pem)")
    ap.add_argument("--command", help="une seule commande puis quitter "
                                       "(status|light-on|light-off|pause|resume|stop|clear|home)")
    args = ap.parse_args()

    print("=" * 58)
    print("  BambooSense — connexion a l'imprimante (P2S)")
    print("=" * 58)

    # 0. journal de debug
    global LOG_PATH
    LOG_PATH = args.log or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "keyforge_connect.log")
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 70 + "\n")
        safe_argv = list(sys.argv[1:])
        for i, a in enumerate(safe_argv):  # ne pas ecrire le code d'acces en clair
            if a in ("--code", "--user-id") and i + 1 < len(safe_argv):
                safe_argv[i + 1] = "***"
        logln(f"SESSION  argv={safe_argv}")
        print(f"[i] Journal : {LOG_PATH}")
        print("    (envoie-moi ce fichier pour debugger)")
    except Exception as e:
        LOG_PATH = None
        print(f"[!] impossible d'ecrire le journal : {e}")

    # 1. identite
    bundle = find_bundle(args.bundle)
    if not bundle:
        print("[!] Cle d'identite introuvable.")
        print("    Lance d'abord keyforge_usb.py, ou passe --bundle <chemin de la cle>.")
        sys.exit(1)
    ident, pconf = load_identity(bundle)
    print(f"[+] Identite chargee depuis : {bundle}")
    print(f"    cert_id = {ident['cert_id']}")

    # identite Studio partagee (firmware securise) : remplace le cert auto-signe.
    # 1) flags explicites ; 2) sinon auto-detection de slicer_key.pem (BambuSlicerKeySaver).
    studio_key = args.studio_key
    studio_cert_pem = None
    studio_crl = args.studio_crl
    if not studio_key and not args.no_auto_studio:
        k, cpem, crl = find_studio_material(args.studio_dir)
        if k:
            studio_key = k
            studio_cert_pem = cpem
            if crl and not studio_crl:
                studio_crl = crl
                print(f"[+] CRL Studio auto-detectee : {crl}")
            print(f"[+] Cle Studio auto-detectee : {k}")
            if not cpem and not args.studio_cert and not args.studio_cert_id:
                print("    [!] cert Studio introuvable -> passe --studio-cert chain.pem")
    if studio_key:
        try:
            ident = load_studio_identity(studio_key, args.studio_cert,
                                         args.studio_cert_id, studio_crl,
                                         cert_pem=studio_cert_pem)
            print(f"[+] Signature via cle Studio partagee. cert_id = {ident['cert_id']}")
        except Exception as e:
            print(f"[!] cle Studio : {e}")
            sys.exit(1)

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
