"""
GhostPrompt — Compliance Signing Engine

Single shared HMAC-SHA256 signing utility for all compliance and analytics exports.
Reuses the existing HMAC key infrastructure from compliance/__init__.py.

Supports:
- JSON payload signing with canonical serialization
- CSV export signing with signature footer block
- PDF signature embedding metadata
- Verification of any uploaded export against stored signature
"""

import hmac
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Union

from app.compliance.framework_base import ComplianceSnapshot


class ComplianceSigningEngine:
    """
    Single shared signing utility. Reuses the SAME HMAC key as the audit log
    signing infrastructure — do not introduce a second key.
    """

    def __init__(self, hmac_key: bytes = b"ghostprompt-compliance-report-integrity-v1"):
        self.hmac_key = hmac_key

    def _canonical_json(self, data: dict) -> bytes:
        """Deterministic JSON serialization with sorted keys for consistent hashing."""
        return json.dumps(data, sort_keys=True, default=str, ensure_ascii=True).encode("utf-8")

    def sign_snapshot(self, snapshot: ComplianceSnapshot) -> str:
        """Sign a ComplianceSnapshot and return the HMAC-SHA256 hex digest."""
        snap_dict = snapshot.to_dict()
        # Remove signature field before signing
        snap_dict.pop("hmac_signature", None)
        snap_dict.pop("_signature", None)
        payload = self._canonical_json(snap_dict)
        return hmac.new(self.hmac_key, payload, hashlib.sha256).hexdigest()

    def sign_json_payload(self, snapshot: ComplianceSnapshot) -> dict:
        """Sign and return the full JSON payload with embedded signature block."""
        signature = self.sign_snapshot(snapshot)
        result = snapshot.to_dict()
        result["hmac_signature"] = signature
        result["_signature"] = {
            "algorithm": "HMAC-SHA256",
            "signature": signature,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_id": snapshot.snapshot_id,
            "verification_note": (
                "To verify: recompute HMAC-SHA256 over this payload minus the "
                "_signature and hmac_signature fields, using canonical JSON encoding "
                "with sorted keys, and compare."
            ),
        }
        return result

    def sign_csv_export(self, csv_body: str, snapshot: ComplianceSnapshot) -> str:
        """Sign CSV content and append a clearly-delimited signature footer."""
        # Normalize line endings for consistent hashing
        csv_body = csv_body.replace("\r\n", "\n")
        signature = hmac.new(
            self.hmac_key, csv_body.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        footer = (
            f"\n# ---SIGNATURE-BLOCK---\n"
            f"# snapshot_id,{snapshot.snapshot_id}\n"
            f"# framework,{snapshot.framework_name}\n"
            f"# generated_at,{snapshot.generated_at}\n"
            f"# signed_at,{datetime.now(timezone.utc).isoformat()}\n"
            f"# algorithm,HMAC-SHA256\n"
            f"# signature,{signature}\n"
            f"# verify,Recompute HMAC-SHA256 over all bytes above this block\n"
        )
        return csv_body + footer

    def get_pdf_signature_metadata(self, pdf_content_bytes: bytes, snapshot: ComplianceSnapshot) -> dict:
        """Compute signature metadata to embed in PDF footer/header."""
        signature = hmac.new(
            self.hmac_key, pdf_content_bytes, hashlib.sha256
        ).hexdigest()
        return {
            "signature": signature,
            "snapshot_id": snapshot.snapshot_id,
            "footer_text": (
                f"Report ID: {snapshot.snapshot_id} | "
                f"HMAC-SHA256: {signature[:16]}...{signature[-8:]}"
            ),
        }

    def verify_payload(self, payload_dict: dict) -> bool:
        """
        Verify a JSON payload's integrity by recomputing its HMAC signature.
        Returns True if the signature matches.
        """
        claimed_sig = payload_dict.get("hmac_signature", "")
        if not claimed_sig:
            return False

        # Remove signature fields before recomputing
        clean = {k: v for k, v in payload_dict.items()
                 if k not in ("hmac_signature", "_signature")}
        expected = hmac.new(
            self.hmac_key, self._canonical_json(clean), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, claimed_sig)

    def verify_csv(self, csv_content: str) -> bool:
        """
        Verify a signed CSV export by extracting the signature block
        and recomputing the HMAC over the body.
        """
        # Normalize line endings
        csv_content = csv_content.replace("\r\n", "\n")
        marker = "\n# ---SIGNATURE-BLOCK---"
        if marker not in csv_content:
            return False

        body, sig_block = csv_content.split(marker, 1)
        # Extract claimed signature
        claimed_sig = ""
        for line in sig_block.strip().split("\n"):
            if line.startswith("# signature,"):
                claimed_sig = line.split(",", 1)[1].strip()
                break

        if not claimed_sig:
            return False

        expected = hmac.new(
            self.hmac_key, body.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, claimed_sig)


# Singleton
signing_engine = ComplianceSigningEngine()
