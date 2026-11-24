#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keyforge_usb.py — BambooSense, version script autonome (Windows 11 / macOS / Linux)

Ce que fait ce script, tout seul, sans serveur :
  1. trouve ta clé USB (lecteurs amovibles sous Windows, /media /Volumes ailleurs)
  2. crée un certificat AUTO-SIGNÉ + sa CRL (même émetteur = "auto-validé" :
     c'est ce qui fait que l'imprimante accepte l'installation sans l'ignorer)
  3. écrit tous les fichiers sur la clé USB :
       identity-cert.pem   le certificat
       identity-key.pem    la clé privée (SECRÈTE — elle signe les commandes)
       identity-crl.pem    la liste de révocation (émetteur = celui du cert)
       connection.json     toutes les infos (cert_id, serial, IP, code...)
       LISEZMOI.txt        rappel de ce que contient la clé

Utilisation simple :
    python keyforge_usb.py
(il te pose les questions). Ou tout d'un coup :
    python keyforge_usb.py --serial 01P00A000000000 --ip 192.168.1.50 --code 12345678

Seule dépendance : la bibliothèque "cryptography".
    pip install cryptography
(le fichier keyforge.bat fourni à côté le fait pour toi sous Windows.)
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys

# ----- vérif de la dépendance, avec message clair -----
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("\n[!] Il manque la bibliotheque 'cryptography'.")
    print("    Ouvre une invite de commande et tape :\n")
    print("        pip install cryptography\n")
    print("    puis relance ce script. (Ou double-clique sur keyforge.bat)")
    sys.exit(1)


# ===========================================================================
# 1. détection de la clé USB
# ===========================================================================
def find_usb_drives():
    """Renvoie une liste de chemins de lecteurs amovibles."""
    drives = []
    if os.name == "nt":  # Windows
        import ctypes
        DRIVE_REMOVABLE = 2
        kernel32 = ctypes.windll.kernel32
        bitmask = kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = f"{chr(65 + i)}:\\"
                if kernel32.GetDriveTypeW(letter) == DRIVE_REMOVABLE:
                    drives.append(letter)
    else:  # macOS / Linux
        for base in ("/Volumes", "/media", "/run/media", "/mnt"):
            if not os.path.isdir(base):
                continue
            for entry in os.listdir(base):
                p = os.path.join(base, entry)
                # un niveau plus bas pour /media/<user>/<label>
                if os.path.isdir(p) and base in ("/media", "/run/media"):
                    for sub in os.listdir(p):
                        sp = os.path.join(p, sub)
                        if os.path.isdir(sp) and os.access(sp, os.W_OK):
                            drives.append(sp)
                elif os.path.isdir(p) and os.access(p, os.W_OK):
                    drives.append(p)
    # dédoublonne en gardant l'ordre
    seen, out = set(), []
    for d in drives:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def choose_usb(explicit):
    if explicit:
        return explicit
    drives = find_usb_drives()
    if not drives:
        print("[!] Aucune cle USB detectee automatiquement.")
        manual = input("    Tape le chemin de la cle (ex. E:\\ ) : ").strip()
        return manual
    if len(drives) == 1:
        print(f"[+] Cle USB trouvee : {drives[0]}")
        return drives[0]
    print("[?] Plusieurs lecteurs amovibles trouves :")
    for i, d in enumerate(drives, 1):
        print(f"      {i}) {d}")
    sel = input("    Lequel ? (numero) : ").strip()
    try:
        return drives[int(sel) - 1]
    except Exception:
        print("[!] Choix invalide.")
        sys.exit(1)


# ===========================================================================
# 2. fabrication du certificat auto-signé + CRL (même émetteur)
# ===========================================================================
def mint(serial: str, prefix: str = "", days: int = 3650):
    serial = serial.strip()
    if not serial:
        raise ValueError("le numero de serie de l'imprimante est obligatoire")
    cn = f"{prefix}{serial}.bambulab.com"
    now = dt.datetime.now(dt.timezone.utc)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert_serial = int.from_bytes(b"\x5a" * 16, "big")  # marqueur 0x5a5a...

    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)          # auto-signe
        .public_key(key.public_key())
        .serial_number(cert_serial)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    # CRL emise par le MEME nom/cle -> emetteur(cert) == emetteur(crl)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - dt.timedelta(days=1))
        .next_update(now + dt.timedelta(days=days))
        .add_extension(x509.CRLNumber(123), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )

    serial_hex = format(cert_serial, "x").zfill(32)
    cert_id = serial_hex + "CN=" + cn
    return {
        "serial": serial, "cn": cn, "cert_id": cert_id, "serial_hex": serial_hex,
        "created": now.isoformat(),
        "key_pem": key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption()).decode(),
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "crl_pem": crl.public_bytes(serialization.Encoding.PEM).decode(),
    }


# ===========================================================================
# 3. écriture du bundle sur la clé
# ===========================================================================
LISEZMOI = """BambooSense — cle d'identite pour imprimante Bambu Lab
======================================================
Cree le : {created}
Imprimante : serie {serial}{ip}

Cette cle USB contient tout ce qu'il faut pour piloter l'imprimante en local.

Fichiers :
  identity-cert.pem   le certificat auto-signe a installer sur l'imprimante
  identity-key.pem    la CLE PRIVEE -- GARDE-LA SECRETE, elle signe les commandes
  identity-crl.pem    la liste de revocation (meme emetteur que le cert : requis)
  connection.json     toutes les infos (cert_id, serie, IP, code d'acces)

cert_id : {cert_id}

ATTENTION : identity-key.pem permet de commander ton imprimante. Traite cette
cle USB comme une cle de maison. Rien ici n'est utilisable sans l'IP ET le code
d'acces LAN de ton imprimante.
"""


def write_bundle(usb_path: str, ident: dict, printer: dict):
    folder = os.path.join(usb_path, "BambooSense")
    os.makedirs(folder, exist_ok=True)

    def w(name, data):
        with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(data)

    w("identity-cert.pem", ident["cert_pem"])
    w("identity-key.pem", ident["key_pem"])
    w("identity-crl.pem", ident["crl_pem"])
    w("connection.json", json.dumps({
        "bamboosense_bundle": 1,
        "identity": ident,
        "printer": printer,
        "note": "identity-key.pem est secret.",
    }, indent=2))
    ipline = f"\nIP : {printer['ip']}" if printer.get("ip") else ""
    w("LISEZMOI.txt", LISEZMOI.format(created=ident["created"], serial=ident["serial"],
                                      ip=ipline, cert_id=ident["cert_id"]))
    return folder


# ===========================================================================
# (bonus) petite auto-verification de la signature, pour te rassurer
# ===========================================================================
def selfcheck(ident: dict, user_id: str = "0"):
    key = serialization.load_pem_private_key(ident["key_pem"].encode(), None)
    print_obj = {"sequence_id": 100001, "command": "pause"}
    inner = ('{"print":' + json.dumps(print_obj, separators=(",", ":"))
             + ',"user_id":"' + user_id + '"}').encode()
    sig = key.sign(inner, padding.PKCS1v15(), hashes.SHA256())
    cert = x509.load_pem_x509_certificate(ident["cert_pem"].encode())
    cert.public_key().verify(sig, inner, padding.PKCS1v15(), hashes.SHA256())
    crl = x509.load_pem_x509_crl(ident["crl_pem"].encode())
    assert cert.issuer == crl.issuer == cert.subject
    return True


# ===========================================================================
# main
# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description="Cree la cle d'identite BambooSense sur une cle USB.")
    ap.add_argument("--serial", help="numero de serie de l'imprimante")
    ap.add_argument("--ip", default="", help="adresse IP LAN de l'imprimante (optionnel)")
    ap.add_argument("--code", default="", help="code d'acces LAN (optionnel)")
    ap.add_argument("--user-id", default="", help="user_id pour signer (optionnel)")
    ap.add_argument("--prefix", default="", help="prefixe de CN (optionnel)")
    ap.add_argument("--days", type=int, default=3650, help="validite en jours")
    ap.add_argument("--out", help="chemin de sortie (cle USB). Sinon : detection auto")
    args = ap.parse_args()

    print("=" * 58)
    print("  BambooSense Keyforge — generateur de cle USB")
    print("=" * 58)

    serial = args.serial or input("Numero de serie de l'imprimante : ").strip()
    ip = args.ip or input("IP LAN de l'imprimante (Entree pour passer) : ").strip()
    code = args.code or input("Code d'acces LAN (Entree pour passer)   : ").strip()

    print("\n[*] Generation du certificat auto-signe + CRL...")
    ident = mint(serial, prefix=args.prefix, days=args.days)
    selfcheck(ident, args.user_id or "0")
    print(f"    OK. cert_id = {ident['cert_id']}")

    usb = choose_usb(args.out)
    if not usb or not os.path.isdir(usb):
        print(f"[!] Chemin introuvable : {usb!r}")
        sys.exit(1)

    printer = {"ip": ip, "serial": serial, "access_code": code, "user_id": args.user_id}
    folder = write_bundle(usb, ident, printer)

    print("\n[+] Termine ! Fichiers ecrits dans :")
    print(f"    {folder}")
    for n in sorted(os.listdir(folder)):
        print(f"      - {n}")
    print("\n    Ejecte la cle proprement, puis insere-la / charge-la sur ton client.")
    print("    (identity-key.pem est SECRET : ne le partage pas.)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnnule.")
    except Exception as e:
        print(f"\n[!] Erreur : {e}")
        sys.exit(1)
