#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# extract_studio_key.py — récupère la clé de signature Studio partagée de Bambu
# depuis une instance de Bambu Studio EN COURS d'exécution, sans rien compiler.
#
# Il lit la mémoire du process Bambu Studio (ctypes / ReadProcessMemory sous
# Windows, /proc/<pid>/mem sous Linux), y trouve le « blob » chiffré de la clé
# (résident au repos dans le plugin réseau), le déchiffre avec le chiffre
# AES-256-CTR à S-box personnalisée, reconstruit la clé RSA (CRT) et écrit :
#     slicer_key.pem        la clé privée (PKCS#8)
#     slicer_cert.pem       le leaf + la chaîne (si trouvés en mémoire)
#     slicer_cert_id.txt     le cert_id MQTT (serial + issuer)
#
# keyforge_connect.py / connect.bat détectent ensuite ces fichiers et signent
# avec, sur firmware sécurisé.
#
# ---------------------------------------------------------------------------
# LICENCE : AGPL-3.0-or-later.
# Ce fichier est un travail dérivé de la recherche open-bamboo-networking
# (© 2026 Alexey Cluster et contributors, AGPL-3.0) — chiffre S-box, cadrage du
# blob et reconstruction RSA : voir research/10.02-secrets.md et
# tools/fetch_slicer_credentials.py / extract_key_from_dump.py, et des travaux de
# danielwoz (BambuSlicerKeySaver). Il est distribué SANS AUCUNE GARANTIE.
# À n'utiliser que pour interopérer avec VOTRE propre imprimante / installation
# Bambu Studio. Le code source complet : https://github.com/ClusterM/open-bamboo-networking
# ---------------------------------------------------------------------------
from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    print("[!] Il manque 'cryptography'. Tape :  pip install cryptography")
    sys.exit(1)


# ===========================================================================
# Chiffre AES-256 à S-box personnalisée  (dérivé de open-bamboo-networking, AGPL)
# ===========================================================================
SBOX = bytes([
    0xC5, 0x57, 0x4D, 0x6C, 0x3A, 0x95, 0x05, 0xE0, 0xA3, 0xBA, 0x36, 0x1F, 0xEA, 0x51, 0x53, 0x3B,
    0x0E, 0x07, 0x4E, 0x64, 0x50, 0x04, 0x40, 0xE8, 0x62, 0x6E, 0x9F, 0x2D, 0x70, 0x8B, 0x28, 0x49,
    0xD5, 0xF9, 0x65, 0x8D, 0x74, 0x68, 0x7C, 0x6F, 0x0A, 0x6A, 0xB3, 0xAF, 0x38, 0xFE, 0x7E, 0x8A,
    0x47, 0x7F, 0xB0, 0x16, 0x00, 0xD4, 0x0F, 0x13, 0xC9, 0x80, 0x4A, 0xAC, 0x8C, 0x4F, 0xA7, 0x98,
    0x83, 0x94, 0x5D, 0x48, 0xB4, 0xE9, 0x30, 0x19, 0x03, 0x99, 0x25, 0xBF, 0x8E, 0x41, 0xA0, 0xE4,
    0xC3, 0xCF, 0x2C, 0xAB, 0xD2, 0x32, 0x1A, 0x0C, 0x11, 0xB5, 0x56, 0x63, 0x15, 0xA6, 0x69, 0x0B,
    0x88, 0xBB, 0x4C, 0x10, 0xCB, 0x75, 0xFA, 0x81, 0xF8, 0xCD, 0xA1, 0xD6, 0x97, 0xB7, 0x26, 0xC6,
    0x9E, 0xF1, 0x5F, 0xE5, 0xA9, 0x87, 0xC7, 0xDC, 0x8F, 0x7A, 0x86, 0x20, 0x9A, 0xD1, 0x08, 0xC2,
    0x84, 0x09, 0x33, 0x1B, 0xDD, 0x1E, 0xFD, 0x01, 0x71, 0xDA, 0x77, 0x0D, 0xD7, 0xDE, 0x93, 0xCA,
    0xA5, 0xD0, 0xE6, 0x60, 0x89, 0x37, 0xC8, 0x21, 0x59, 0x79, 0x96, 0xAD, 0x24, 0x34, 0xB9, 0x44,
    0xFC, 0xC1, 0xAE, 0xF3, 0x82, 0x46, 0x43, 0x31, 0xE3, 0x2E, 0x4B, 0xFB, 0x92, 0x55, 0xED, 0x45,
    0x76, 0x6D, 0xAA, 0x3F, 0xF5, 0x5A, 0x91, 0x78, 0x22, 0x06, 0xFF, 0xD9, 0x35, 0x7D, 0x7B, 0xDB,
    0x54, 0x12, 0x9C, 0xD8, 0xD3, 0xEE, 0x17, 0x42, 0x52, 0x3E, 0xA4, 0xE7, 0xDF, 0x9D, 0xF2, 0xF4,
    0xEF, 0x73, 0xF6, 0x5E, 0xB1, 0x5B, 0x18, 0xE2, 0x9B, 0x58, 0xA8, 0x2A, 0xE1, 0x3D, 0x90, 0xB6,
    0x1C, 0xBD, 0x61, 0xEB, 0x23, 0xA2, 0x67, 0x39, 0xF0, 0xBC, 0xB2, 0xF7, 0x85, 0x27, 0x72, 0xCC,
    0x29, 0xB8, 0x1D, 0xBE, 0x66, 0xC4, 0x2F, 0xCE, 0x14, 0x3C, 0x6B, 0xEC, 0x5C, 0x2B, 0xC0, 0x02,
])
APPCERT_KEY = bytes(range(32))
RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D])

NONCE_LEN = 12
CT_LEN_OFFSET = 28
BLOB_HEADER_LEN = 32
FIRST_CT_BLOCK_COUNTER = 2
SKEY = b"\x59\x45\x4b\x53"
SKEY_LEN = 4
PT_HEADER_LEN = 32
CRT_LIMB_COUNT = 5


def _xtime(a):
    return ((a << 1) ^ (0x1B if (a & 0x80) else 0)) & 0xFF


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def key_expand(key):
    w = [[0, 0, 0, 0] for _ in range(60)]
    for i in range(8):
        for j in range(4):
            w[i][j] = key[4 * i + j]
    for i in range(8, 60):
        t = w[i - 1][:]
        if i % 8 == 0:
            tmp = t[0]
            t[0] = SBOX[t[1]] ^ RCON[i // 8 - 1]
            t[1] = SBOX[t[2]]
            t[2] = SBOX[t[3]]
            t[3] = SBOX[tmp]
        elif i % 8 == 4:
            t = [SBOX[x] for x in t]
        for j in range(4):
            w[i][j] = w[i - 8][j] ^ t[j]
    rk = []
    for r in range(15):
        block = bytearray(16)
        for c in range(4):
            for j in range(4):
                block[4 * c + j] = w[4 * r + c][j]
        rk.append(bytes(block))
    return rk


def aes_encrypt_block(block, rk):
    s = bytearray(block[i] ^ rk[0][i] for i in range(16))
    for rnd in range(1, 15):
        s = bytearray(SBOX[x] for x in s)
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = s[4 * ((c + r) % 4) + r]
        s = t
        if rnd < 14:
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c: 4 * c + 4]
                s[4 * c + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
                s[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
                s[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
                s[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
        for i in range(16):
            s[i] ^= rk[rnd][i]
    return bytes(s)


def ctr_xor(key, nonce, data):
    rk = key_expand(key)
    out = bytearray(len(data))
    for i in range((len(data) + 15) // 16):
        ctr = bytearray(nonce) + struct.pack(">I", FIRST_CT_BLOCK_COUNTER + i)
        ks = aes_encrypt_block(bytes(ctr), rk)
        base = i * 16
        n = min(16, len(data) - base)
        for j in range(n):
            out[base + j] = data[base + j] ^ ks[j]
    return bytes(out)


# ===========================================================================
# Blob -> clé RSA
# ===========================================================================
def ct_len_for(bits):
    return PT_HEADER_LEN + CRT_LIMB_COUNT * (bits // 16)


def try_decode_blob(blob):
    """Déchiffre un blob candidat -> objet clé privée RSA, ou None."""
    if len(blob) < BLOB_HEADER_LEN + PT_HEADER_LEN + CRT_LIMB_COUNT:
        return None
    nonce = blob[:NONCE_LEN]
    ct_len = struct.unpack_from("<I", blob, CT_LEN_OFFSET)[0]
    if BLOB_HEADER_LEN + ct_len > len(blob):
        return None
    pt = ctr_xor(APPCERT_KEY, nonce, blob[BLOB_HEADER_LEN:BLOB_HEADER_LEN + ct_len])
    if pt[:SKEY_LEN] != SKEY:
        return None
    body = len(pt) - PT_HEADER_LEN
    if body <= 0 or body % CRT_LIMB_COUNT != 0:
        return None
    limb = body // CRT_LIMB_COUNT
    parts = [pt[PT_HEADER_LEN + i * limb: PT_HEADER_LEN + (i + 1) * limb] for i in range(CRT_LIMB_COUNT)]
    p = int.from_bytes(parts[0], "big")
    q = int.from_bytes(parts[1], "big")
    if p <= 1 or q <= 1:
        return None
    try:
        n = p * q
        e = 65537
        from math import gcd
        lam = (p - 1) // gcd(p - 1, q - 1) * (q - 1)
        d = pow(e, -1, lam)
        pub = rsa.RSAPublicNumbers(e, n)
        priv = rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p),
                                     rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q), pub)
        key = priv.private_key()
    except Exception:
        return None
    # preuve : sign/verify
    try:
        msg = b"bamboosense-keyforge"
        sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        key.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        return None
    return key


def scan_bytes_for_blob(buf, key_sizes=(2048, 3072, 4096)):
    """Cherche un blob de clé dans `buf`. Renvoie l'objet clé RSA, ou None."""
    rk = key_expand(APPCERT_KEY)
    counter = struct.pack(">I", FIRST_CT_BLOCK_COUNTER)
    for bits in key_sizes:
        ct_len = ct_len_for(bits)
        blob_len = BLOB_HEADER_LEN + ct_len
        marker = struct.pack("<I", ct_len)
        pos = 0
        while True:
            k = buf.find(marker, pos)
            if k < 0:
                break
            pos = k + 1
            start = k - CT_LEN_OFFSET
            if start < 0 or start + blob_len > len(buf):
                continue
            nonce = buf[start:start + NONCE_LEN]
            ct0 = buf[start + BLOB_HEADER_LEN:start + BLOB_HEADER_LEN + SKEY_LEN]
            ks0 = aes_encrypt_block(nonce + counter, rk)
            if bytes(a ^ b for a, b in zip(ct0, ks0[:SKEY_LEN])) != SKEY:
                continue
            key = try_decode_blob(bytes(buf[start:start + blob_len]))
            if key:
                return key
    return None


def scan_bytes_for_certs(buf, acc, seen):
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    pos = 0
    while True:
        a = buf.find(begin, pos)
        if a < 0:
            break
        pos = a + 1
        b = buf.find(end, a)
        if b < 0 or b - a > 8000:
            continue
        try:
            cert = x509.load_pem_x509_certificate(bytes(buf[a:b + len(end)]))
            der = cert.public_bytes(serialization.Encoding.DER)
        except Exception:
            continue
        if der not in seen:
            seen.add(der)
            acc.append(cert)


# ===========================================================================
# Lecture mémoire process (Windows + Linux)
# ===========================================================================
def _k32():
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.VirtualQueryEx.restype = ctypes.c_size_t
    k.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    k.ReadProcessMemory.restype = wintypes.BOOL
    k.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_char_p,
                                    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    return k, ctypes, wintypes


def iter_process_regions_windows(pid):
    k32, ctypes, wintypes = _k32()
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError(f"OpenProcess({pid}) a echoue (essaie en Administrateur) "
                      f"err={ctypes.get_last_error()}")

    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD), ("__a1", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD), ("__a2", wintypes.DWORD)]
    MEM_COMMIT = 0x1000
    READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
    PAGE_GUARD = 0x100
    addr = 0
    mbi = MBI()
    max_addr = 0x7FFFFFFF0000
    total = [0]
    try:
        while addr < max_addr:
            if k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            if size == 0:
                break
            if (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE
                    and not (mbi.Protect & PAGE_GUARD)):
                for chunk in _read_region_windows(k32, ctypes, h, base, size):
                    total[0] += len(chunk)
                    yield chunk
            addr = base + size
    finally:
        k32.CloseHandle(h)
    print(f"    ({total[0] // (1024*1024)} Mo lus)")


def _read_region_windows(k32, ctypes, h, base, size, chunk=64 * 1024 * 1024, overlap=4096):
    off = 0
    prev_tail = b""
    while off < size:
        n = min(chunk, size - off)
        buf = ctypes.create_string_buffer(n)
        read = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(read))
        if not ok or read.value == 0:
            return
        data = buf.raw[:read.value]
        yield prev_tail + data
        prev_tail = data[-overlap:] if len(data) >= overlap else data
        off += read.value
        if read.value < n:
            return


def iter_process_regions_linux(pid):
    maps = Path(f"/proc/{pid}/maps").read_text()
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for line in maps.splitlines():
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            a, b = parts[0].split("-")
            start, end = int(a, 16), int(b, 16)
            try:
                mem.seek(start)
                data = mem.read(end - start)
            except Exception:
                continue
            if data:
                yield data


# ===========================================================================
# Recherche du process Bambu Studio
# ===========================================================================
PROC_HINTS = ("bambu-studio", "bambustudio", "bambu_studio", "bambu-network",
              "bambu_network", "bambunetwork", "bambusource", "bambu-connect")


def find_bambu_pids():
    pids = []
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        psapi = ctypes.WinDLL("psapi")
        k32, _c, _w = _k32()
        k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                   wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        arr = (wintypes.DWORD * 8192)()
        got = wintypes.DWORD()
        if not psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(got)):
            return pids
        count = got.value // ctypes.sizeof(wintypes.DWORD)
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        for i in range(count):
            pid = arr[i]
            if not pid:
                continue
            h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                continue
            try:
                buf = ctypes.create_unicode_buffer(32768)
                size = wintypes.DWORD(len(buf))
                if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    name = os.path.basename(buf.value.lower())
                    if any(hint in name for hint in PROC_HINTS):
                        pids.append((pid, buf.value))
            finally:
                k32.CloseHandle(h)
    else:
        for d in Path("/proc").iterdir():
            if not d.name.isdigit():
                continue
            try:
                comm = (d / "comm").read_text().strip().lower()
                cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "ignore").lower()
            except Exception:
                continue
            if any(hint in comm or hint in cmd for hint in PROC_HINTS):
                pids.append((int(d.name), comm))
    return pids


# ===========================================================================
# Chaîne de certificats
# ===========================================================================
def build_chain(leaf, certs):
    chain = [leaf]
    cur = leaf
    for _ in range(4):
        parent = None
        for c in certs:
            if c.subject == cur.issuer and c.subject != c.issuer:
                parent = c
                break
        if not parent:
            # racine auto-signee de meme issuer
            for c in certs:
                if c.subject == cur.issuer and c is not cur and c not in chain:
                    parent = c
                    break
        if not parent or parent in chain:
            break
        chain.append(parent)
        cur = parent
        if parent.subject == parent.issuer:
            break
    return chain


def cert_id_of(leaf):
    return format(leaf.serial_number, "x") + leaf.issuer.rfc4514_string()


# ===========================================================================
# main
# ===========================================================================
def find_plugin_files():
    """Fichiers plugin reseau sur disque a scanner (le blob y est parfois au repos)."""
    out = []
    home = os.path.expanduser("~")
    roots = []
    for env in ("APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"):
        v = os.environ.get(env)
        if v:
            roots += [os.path.join(v, "BambuStudio"), os.path.join(v, "Bambu Studio")]
    roots += [os.path.join(home, ".config", "BambuStudio"),
              os.path.join(home, "Library", "Application Support", "BambuStudio")]
    for r in roots:
        for sub in ("", "plugins", os.path.join("plugins", "nightly")):
            d = os.path.join(r, sub) if sub else r
            if not os.path.isdir(d):
                continue
            try:
                for f in os.listdir(d):
                    fl = f.lower()
                    if any(h in fl for h in ("bambu_networking", "bambusource", "bambu_source",
                                             "networking", "bambu-net")) \
                            and fl.endswith((".dll", ".so", ".dylib")):
                        out.append(os.path.join(d, f))
            except Exception:
                pass
    return out


def process_source(args):
    if args.dump:
        print(f"[*] Lecture du dump : {args.dump}")
        yield Path(args.dump).read_bytes()
        return

    # 1) fichiers plugin sur disque (rapide, sans Studio lance)
    for f in find_plugin_files():
        try:
            print(f"[*] Scan du plugin sur disque : {f}")
            yield Path(f).read_bytes()
        except Exception as e:
            print(f"    (lecture impossible: {e})")

    # 2) memoire des process Bambu en cours (TOUS)
    pids = [(args.pid, "(--pid)")] if args.pid else find_bambu_pids()
    if not pids:
        print("[i] Aucun process Bambu en cours (on s'est limite au disque).")
        return
    for pid, name in pids:
        print(f"[*] Process Bambu : PID {pid}  {name}")
        print("    Lecture de la memoire (10-60 s)...")
        try:
            if os.name == "nt":
                yield from iter_process_regions_windows(pid)
            else:
                yield from iter_process_regions_linux(pid)
        except Exception as e:
            print(f"    (lecture memoire PID {pid} impossible: {e})")


def main():
    ap = argparse.ArgumentParser(
        description="Extrait la cle de signature Studio partagee depuis Bambu Studio en cours.")
    ap.add_argument("--out-dir", default=".", help="dossier de sortie (defaut: dossier courant)")
    ap.add_argument("--pid", type=int, help="PID du process a lire")
    ap.add_argument("--dump", help="lire un dump memoire (.dmp procdump -ma / core) au lieu du process")
    args = ap.parse_args()

    print("=" * 60)
    print("  Extracteur de cle Studio partagee (BambooSense)")
    print("=" * 60)

    key = None
    certs = []
    seen = set()
    for chunk in process_source(args):
        if key is None:
            key = scan_bytes_for_blob(chunk)
            if key:
                print("[+] Cle RSA trouvee et reconstruite (sign/verify OK).")
        scan_bytes_for_certs(chunk, certs, seen)

    print(f"[i] Diagnostic : {len(certs)} certificat(s) vus en memoire/plugin.")
    if certs:
        lines = []
        for c in certs:
            try:
                cn = c.subject.rfc4514_string()
                iss = c.issuer.rfc4514_string()
                cid = format(c.serial_number, "x") + iss
                lines.append(f"  - subject={cn}  issuer={iss}\n    cert_id={cid}")
            except Exception:
                pass
        print("[i] Certificats vus :")
        print("\n".join(lines))
        try:
            Path(args.out_dir).mkdir(parents=True, exist_ok=True)
            (Path(args.out_dir) / "studio_certs_seen.txt").write_text(
                "\n".join(lines), newline="\n")
        except Exception:
            pass

    if not key:
        print("\n[!] Blob de cle introuvable.")
        if certs:
            print("    (La lecture memoire FONCTIONNE — des certs ont ete vus — mais le")
            print("     blob de cle n'etait pas present. Il n'est materialise qu'apres")
            print("     une operation reseau.)")
            print("    -> Dans Bambu Studio : CONNECTE-toi, ouvre l'onglet 'Appareil'")
            print("       (Device) de ton imprimante, voire lance une PREPARATION de")
            print("       print, PUIS relance getkey.bat SANS fermer Studio.")
        else:
            print("    La lecture n'a rien ramene. Sous Windows : lance en Administrateur.")
        print("    Repli fiable : procdump -accepteula -ma bambu-studio.exe studio.dmp")
        print("    puis   python extract_studio_key.py --dump studio.dmp")
        sys.exit(2)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    (out / "slicer_key.pem").write_text(key_pem, newline="\n")
    os.chmod(out / "slicer_key.pem", 0o600)
    print(f"[+] Ecrit : {out / 'slicer_key.pem'}")

    # leaf = cert dont le modulus == n de la cle
    n = key.public_key().public_numbers().n
    leaf = None
    for c in certs:
        pk = c.public_key()
        if isinstance(pk, rsa.RSAPublicKey) and pk.public_numbers().n == n:
            leaf = c
            break
    if leaf:
        chain = build_chain(leaf, certs)
        chain_pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)
        (out / "slicer_cert.pem").write_text(chain_pem, newline="\n")
        cid = cert_id_of(leaf)
        (out / "slicer_cert_id.txt").write_text(cid, newline="\n")
        print(f"[+] Ecrit : {out / 'slicer_cert.pem'}  ({len(chain)} cert(s))")
        print(f"[+] cert_id : {cid}")
    else:
        print("[!] Leaf assorti a la cle non trouve en memoire.")
        print("    slicer_key.pem suffit si connect.bat trouve le cert Studio")
        print("    (slicer_base64.cer) ; sinon passe --studio-cert.")

    print("\n[OK] Termine. Lance connect.bat : il detectera slicer_key.pem et signera.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnnule.")
