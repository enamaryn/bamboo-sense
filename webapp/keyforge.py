"""keyforge — mint the self-signed Bambu identity and sign print.* commands.

The whole point: a Bambu Lab printer (2025+ firmware) accepts command signatures
from any certificate it has *installed itself* via the unsigned
`security.app_cert_install` MQTT command. There is no chain validation — a
self-signed cert works — with ONE catch learned the hard way (docs/CRACK.md §7):

    issuer(app_cert) MUST equal issuer(crl)  -- else the printer SILENTLY drops
                                                 the install (no reply at all).

So we always generate the cert and the CRL *together*, signed by the same key
with the same issuer DN. That makes the pair self-consistent for any CN.

Nothing here depends on the network — it is pure crypto, so it can run anywhere
(including offline, which is the point of writing it all to a USB key).
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# minting
# ---------------------------------------------------------------------------

def _common_name(serial: str, prefix: str = "") -> str:
    """The subject/issuer CN. Bambu's own device certs are <serial>.bambulab.com;
    we mimic that shape. A prefix (e.g. 'GLOF') is optional and harmless."""
    serial = serial.strip()
    return f"{prefix}{serial}.bambulab.com"


@dataclass
class Identity:
    """A minted identity: the key never has to leave the box it was made on,
    except onto the USB key the user carries."""
    serial: str
    cn: str
    cert_id: str
    serial_hex: str
    key_pem: str
    cert_pem: str
    crl_pem: str
    created: str

    def public(self) -> dict:
        """Safe-to-display subset (no private key)."""
        return {
            "serial": self.serial,
            "cn": self.cn,
            "cert_id": self.cert_id,
            "serial_hex": self.serial_hex,
            "cert_pem": self.cert_pem,
            "crl_pem": self.crl_pem,
            "created": self.created,
        }


def mint_identity(serial: str, prefix: str = "", days: int = 3650) -> Identity:
    """Create RSA-2048 key + self-signed cert + matching (empty) CRL.

    `cert_id` is built exactly the way the verified on-chip signer derives it
    (firmware deriveCertId): lowercase hex of the cert serial, zero-padded to
    32 chars, then "CN=" + the subject common name.
    """
    serial = serial.strip()
    if not serial:
        raise ValueError("printer serial is required")

    cn = _common_name(serial, prefix)
    now = _dt.datetime.now(_dt.timezone.utc)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    # A fixed, recognisable 16-byte serial (0x5a5a... — same marker the project
    # has used from the start). Any positive integer works; the printer does
    # not care about the value, only that cert_id is consistent with it.
    cert_serial = int.from_bytes(b"\x5a" * 16, "big")

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: subject == issuer
        .public_key(key.public_key())
        .serial_number(cert_serial)
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=days))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # CRL issued by the SAME name/key as the cert — empty revocation list.
    # This is the piece that makes app_cert_install actually land (§7).
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - _dt.timedelta(days=1))
        .next_update(now + _dt.timedelta(days=days))
        .add_extension(x509.CRLNumber(123), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    serial_hex = format(cert_serial, "x").zfill(32)
    cert_id = serial_hex + "CN=" + cn

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()

    return Identity(
        serial=serial,
        cn=cn,
        cert_id=cert_id,
        serial_hex=serial_hex,
        key_pem=key_pem,
        cert_pem=cert_pem,
        crl_pem=crl_pem,
        created=now.isoformat(),
    )


def load_identity(serial: str, cn: str, cert_id: str, serial_hex: str,
                  key_pem: str, cert_pem: str, crl_pem: str, created: str = "",
                  **_ignore) -> Identity:
    """Rebuild an Identity from a bundle read back off the USB key."""
    return Identity(
        serial=serial, cn=cn, cert_id=cert_id, serial_hex=serial_hex,
        key_pem=key_pem, cert_pem=cert_pem, crl_pem=crl_pem,
        created=created or _dt.datetime.now(_dt.timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# signing  (mirrors firmware signPrintCommand exactly — verified: SUCCESS)
# ---------------------------------------------------------------------------

def sign_print_command(identity: Identity, print_obj: dict, user_id: str) -> str:
    """Return the full wire JSON for a signed `print.*` command.

    The bytes that get signed are, byte-for-byte:
        {"print":<compact-json-of-print_obj>,"user_id":"<user_id>"}
    with `sequence_id` a NUMBER (not a string). The header is then spliced in
    before the final '}'. This is the canonical form the 2026 firmware wants
    (insertion order, trailing user_id — docs/CRACK.md).
    """
    key = serialization.load_pem_private_key(identity.key_pem.encode(), None)

    # compact, insertion-order json for just the print object
    print_json = json.dumps(print_obj, separators=(",", ":"))
    inner = '{"print":' + print_json + ',"user_id":"' + user_id + '"}'
    inner_bytes = inner.encode()

    sig = key.sign(inner_bytes, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode()

    header = (
        ',"header":{"sign_ver":"v1.0","sign_alg":"RSA_SHA256","sign_string":"'
        + sig_b64
        + '","cert_id":"' + identity.cert_id
        + '","payload_len":' + str(len(inner_bytes)) + "}"
    )
    # splice the header in before the closing brace of `inner`
    return inner[:-1] + header + "}"


def build_cert_install(identity: Identity, sequence_id: str, timestamp_ms: int) -> str:
    """The unsigned security.app_cert_install envelope (cert + matching CRL)."""
    def pem_to_json(pem: str) -> str:
        # embed a PEM as a JSON string value (escaped newlines)
        return pem.replace("\r", "").replace("\n", "\\n")

    return (
        '{"security":{"sequence_id":"' + sequence_id + '","command":"app_cert_install"'
        + ',"timestamp":' + str(timestamp_ms) + ',"type":"app"'
        + ',"app_cert":"' + pem_to_json(identity.cert_pem) + '"'
        + ',"crl":"' + pem_to_json(identity.crl_pem) + '"}}'
    )


if __name__ == "__main__":  # quick self-test
    ident = mint_identity("01P00A000000000")
    print("CN      :", ident.cn)
    print("cert_id :", ident.cert_id)
    print("len key :", len(ident.key_pem), "len cert:", len(ident.cert_pem),
          "len crl :", len(ident.crl_pem))
    wire = sign_print_command(ident, {"sequence_id": 100001, "command": "print_speed",
                                      "param": "2"}, user_id="1234567890")
    print("signed wire bytes:", len(wire))
    assert '"header"' in wire and wire.endswith("}")
    # verify issuer(cert) == issuer(crl)
    c = x509.load_pem_x509_certificate(ident.cert_pem.encode())
    r = x509.load_pem_x509_crl(ident.crl_pem.encode())
    assert c.issuer == r.issuer == c.subject, "issuer mismatch!"
    print("OK: issuer(cert) == issuer(crl) == subject")
