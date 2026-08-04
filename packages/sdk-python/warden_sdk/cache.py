import json
import os
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from warden_sdk.exceptions import WardenError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _canonicalize_json(value) -> str:
    """Match the API's deterministic JSON representation before checking a signature."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class CertificateCache:
    def __init__(self, cache_dir: Optional[str] = None, ttl_seconds: int = 86400):
        self.cache_dir = Path(cache_dir or Path.home() / ".warden" / "cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds

    def _cache_path(self, tool_url: str) -> Path:
        digest = hashlib.sha256(tool_url.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def get(self, tool_url: str) -> Optional[dict]:
        path = self._cache_path(tool_url)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(entry["cached_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - cached_at).total_seconds()
            if age > self.ttl_seconds:
                return None
            cert = entry.get("certificate", {})
            if cert.get("status") == "revoked":
                return None
            expires_at = datetime.fromisoformat(cert["expires_at"].replace("Z", "+00:00"))
            if expires_at < datetime.now(timezone.utc):
                return None
            return entry
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    def set(self, tool_url: str, certificate: dict) -> None:
        entry = {
            "certificate": certificate,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "tool_url": tool_url,
        }
        self._cache_path(tool_url).write_text(json.dumps(entry, indent=2), encoding="utf-8")

    def invalidate(self, tool_url: str) -> None:
        path = self._cache_path(tool_url)
        if path.exists():
            path.unlink()

    def invalidate_by_certificate_id(self, certificate_id: str) -> None:
        for file in self.cache_dir.glob("*.json"):
            try:
                entry = json.loads(file.read_text(encoding="utf-8"))
                if entry.get("certificate", {}).get("certificate_id") == certificate_id:
                    file.unlink()
            except (json.JSONDecodeError, KeyError):
                continue

    def verify_offline(self, entry: dict, current_hash: Optional[str] = None) -> Optional[dict]:
        cert = entry["certificate"]
        if cert.get("status") != "active":
            return None

        try:
            body = {key: value for key, value in cert.items() if key not in ("signature", "status")}
            public_key = cert["issuer"]["public_key"].removeprefix("ed25519:")
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
                base64.b64decode(cert["signature"]),
                _canonicalize_json(body).encode("utf-8"),
            )
        except (KeyError, TypeError, ValueError, UnicodeError):
            return None
        except Exception:
            # InvalidSignature intentionally fails closed without exposing crypto internals.
            return None

        if current_hash and current_hash != cert.get("tool", {}).get("hash"):
            return {
                "decision": "block",
                "reason": "Tool code or manifest has changed since certification.",
                "certificate_id": cert.get("certificate_id"),
                "risk_score": cert.get("risk_summary", {}).get("findings_count", 0),
            }

        decision = cert.get("decision", {})
        return {
            "decision": decision.get("outcome", "block"),
            "reason": f"Cached certificate verified offline. {decision.get('reason', '')}",
            "certificate_id": cert.get("certificate_id"),
            "risk_score": cert.get("risk_summary", {}).get("findings_count", 0),
            "approved_capabilities": cert.get("approved_capabilities", []),
        }
