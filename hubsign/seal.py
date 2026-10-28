"""Cryptographic sealing: every completed PDF gets a PAdES (ETSI EN 319 142) certification signature.

Any later change to the file, even one byte, breaks the signature, and Adobe Acrobat and other validators flag it.
Bring your own document-signing certificate (HUBSIGN_SEAL_CERT_FILE / _KEY_FILE) from a CA on Adobe's trust list so
readers show a green tick without extra steps. With none configured a self-signed certificate is generated: the seal
still proves the file is unchanged since HubSign sealed it, but readers will say the signer's identity is unknown
until the certificate is added as a trust anchor (it is downloadable at /.well-known/hubsign-seal.pem).
"""

from __future__ import annotations

import io
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from asn1crypto import pem, x509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from .config import Settings

FIELD = "HubSignSeal"


def _generate(cert_path: Path, key_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = cx509.Name(
        [
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "HubSign"),
            cx509.NameAttribute(NameOID.COMMON_NAME, "HubSign Document Seal (self-signed)"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(cx509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            cx509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )  # fmt: skip
        .sign(key, hashes.SHA256())
    )
    key_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class Sealer:
    def __init__(self, s: Settings, timestamper=None):
        self.s = s
        if s.seal_cert_file and s.seal_key_file:
            self.cert_path, self.key_path, self.generated = Path(s.seal_cert_file), Path(s.seal_key_file), False
        else:
            d = s.data_dir / "seal"
            self.cert_path, self.key_path, self.generated = d / "seal.pem", d / "seal-key.pem", True
            if not self.cert_path.exists() or not self.key_path.exists():
                _generate(self.cert_path, self.key_path)
        chain = [s.seal_chain_file] if s.seal_chain_file else []
        pw = s.seal_key_password.encode() if s.seal_key_password else None
        self.signer = signers.SimpleSigner.load(
            str(self.key_path), str(self.cert_path), ca_chain_files=chain, key_passphrase=pw
        )
        self.timestamper = timestamper
        if timestamper is None and s.tsa_url:
            from pyhanko.sign.timestamps import HTTPTimeStamper

            self.timestamper = HTTPTimeStamper(s.tsa_url)
        # trust anchors for verification: the configured chain's roots if given, else the seal certificate itself
        roots = [self.signer.signing_cert]
        if chain:
            for _, _, der in pem.unarmor(Path(chain[0]).read_bytes(), multiple=True):
                roots.append(x509.Certificate.load(der))
        self.roots = roots

    @property
    def cert_pem(self) -> bytes:
        return self.cert_path.read_bytes()

    @property
    def fingerprint(self) -> str:
        return self.signer.signing_cert.sha256.hex()

    def seal(self, pdf: bytes, *, reason: str) -> bytes:
        meta = signers.PdfSignatureMetadata(
            field_name=FIELD,
            reason=reason,
            location="HubSign",
            certify=True,
            docmdp_permissions=fields.MDPPerm.NO_CHANGES,
            subfilter=fields.SigSeedSubFilter.PADES,
            md_algorithm="sha256",
        )
        w = IncrementalPdfFileWriter(io.BytesIO(pdf))
        out = signers.sign_pdf(w, meta, signer=self.signer, timestamper=self.timestamper)
        return out.getvalue()

    def verify(self, pdf: bytes) -> dict:
        """Report on every embedded signature. `intact` False means the file changed after it was sealed."""
        try:
            r = PdfFileReader(io.BytesIO(pdf))
            sigs = r.embedded_signatures
        except Exception:
            return {"signed": False, "error": "not a readable PDF", "signatures": []}
        vc = ValidationContext(trust_roots=self.roots, allow_fetching=False, revocation_mode="soft-fail")
        out = []
        for sig in sigs:
            try:
                st = validate_pdf_signature(sig, signer_validation_context=vc)
                cert = st.signing_cert
                out.append(
                    {
                        "field": sig.field_name,
                        "intact": bool(st.intact),
                        "valid": bool(st.valid),
                        "trusted_by_this_server": bool(st.trusted),
                        "covers_entire_file": st.coverage.name == "ENTIRE_FILE",
                        "unmodified_since_signing": bool(st.docmdp_ok) and st.coverage.name == "ENTIRE_FILE",
                        "signer": cert.subject.human_friendly if cert else None,
                        "signed_at": (st.timestamp_validity.timestamp.isoformat() if st.timestamp_validity else
                                      (st.signer_reported_dt.isoformat() if st.signer_reported_dt else None)),
                        "trusted_timestamp": bool(st.timestamp_validity and st.timestamp_validity.valid),
                        "reason": sig.sig_object.get("/Reason"),
                    }
                )  # fmt: skip
            except Exception as e:
                out.append(
                    {
                        "field": sig.field_name,
                        "intact": False,
                        "valid": False,
                        "error": f"{type(e).__name__}: {e}"[:200],
                    }
                )
        ok = bool(out) and all(x.get("intact") and x.get("valid") and x.get("unmodified_since_signing") for x in out)
        return {"signed": bool(out), "ok": ok, "signatures": out}
