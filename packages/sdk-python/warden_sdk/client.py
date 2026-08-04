import os
import hashlib
import httpx
from typing import Optional, List, Dict, Any
from .exceptions import AuthError, APIError, ToolNotTrustedError
from .cache import CertificateCache

class WardenResponse:
    def __init__(self, data: Dict[str, Any]):
        self.decision: str = data.get("decision", "block")
        self.reason: str = data.get("reason", "Unknown verification response.")
        self.certificate_id: Optional[str] = data.get("certificate_id")
        self.risk_score: int = data.get("risk_score", 0)
        self.approved_capabilities: List[str] = data.get("approved_capabilities", [])

    def __repr__(self) -> str:
        return f"WardenResponse(decision='{self.decision}', reason='{self.reason}', certificate_id='{self.certificate_id}')"

class Warden:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        cache_dir: Optional[str] = None,
        cache_ttl_seconds: int = 86400,
    ):
        self.api_key = api_key or os.getenv("WARDEN_API_KEY", "")
        self.base_url = (base_url or os.getenv("WARDEN_API_URL", "http://localhost:3000")).rstrip("/")
        self.cache = CertificateCache(cache_dir=cache_dir, ttl_seconds=cache_ttl_seconds)
        
    def _get_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _compute_manifest_hash(self, tool_url: str) -> Optional[str]:
        if os.path.exists(tool_url):
            try:
                with open(tool_url, "r", encoding="utf-8") as f:
                    content = f.read()
                return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
            except OSError:
                return None
        return None

    def verify(self, tool_url: str) -> WardenResponse:
        """Asks Warden whether a tool is trusted."""
        manifest_hash = self._compute_manifest_hash(tool_url)
        cached = self.cache.get(tool_url)

        if cached:
            offline = self.cache.verify_offline(cached, manifest_hash)
            if offline and offline.get("decision") == "allow":
                return WardenResponse(offline)

        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.post(
                    f"{self.base_url}/v1/certificates/verify",
                    headers=self._get_headers(),
                    json={"tool_url": tool_url},
                )
                if res.status_code == 401:
                    raise AuthError("Invalid or missing API Key")
                if res.status_code != 200:
                    raise APIError(f"Warden API returned status {res.status_code}: {res.text}")
                
                result = WardenResponse(res.json())

                if result.decision == "allow" and result.certificate_id:
                    try:
                        cert = self.get_certificate(result.certificate_id)
                        self.cache.set(tool_url, cert)
                    except APIError:
                        pass
                elif result.decision == "block":
                    self.cache.invalidate(tool_url)

                return result
        except httpx.RequestError as e:
            raise APIError(f"Failed to connect to Warden API at {self.base_url}: {str(e)}")

    def scan(self, tool_url: str) -> dict:
        """Triggers a scan for a tool manifest."""
        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.post(
                    f"{self.base_url}/v1/scans",
                    headers=self._get_headers(),
                    json=self._build_scan_payload(tool_url),
                )
                if res.status_code == 401:
                    raise AuthError("Invalid or missing API Key")
                if res.status_code not in (200, 201):
                    raise APIError(f"Warden API returned status {res.status_code}: {res.text}")
                return res.json()
        except httpx.RequestError as e:
            raise APIError(f"Failed to connect to Warden API at {self.base_url}: {str(e)}")

    def _build_scan_payload(self, tool_url: str) -> dict:
        import json as json_lib
        if os.path.exists(tool_url):
            with open(tool_url, "r", encoding="utf-8") as f:
                manifest = json_lib.load(f)
        else:
            with httpx.Client(timeout=15.0) as client:
                response = client.get(tool_url)
                if response.status_code != 200:
                    raise APIError(f"Failed to fetch manifest: HTTP {response.status_code}")
                manifest = response.json()

        return {
            "tool_name": manifest.get("name", "mcp-tool"),
            "source_url": tool_url,
            "manifest": manifest,
            "actor": "sdk:python",
        }

    def get_certificate(self, certificate_id: str) -> dict:
        """Retrieves a trust certificate by its ID."""
        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.get(
                    f"{self.base_url}/v1/certificates/{certificate_id}",
                    headers=self._get_headers(),
                )
                if res.status_code == 401:
                    raise AuthError("Invalid or missing API Key")
                if res.status_code != 200:
                    raise APIError(f"Warden API returned status {res.status_code}: {res.text}")
                return res.json()
        except httpx.RequestError as e:
            raise APIError(f"Failed to connect to Warden API at {self.base_url}: {str(e)}")

    def verify_certificate(self, certificate_id: str, current_hash: Optional[str] = None) -> dict:
        """Verify a certificate's signature, status, and optional live tool hash."""
        payload = {"current_hash": current_hash} if current_hash else {}
        return self._request("POST", f"/v1/certificates/{certificate_id}/verify", payload)

    def revoke_certificate(self, certificate_id: str, reason: Optional[str] = None) -> dict:
        return self._request("POST", f"/v1/certificates/{certificate_id}/revoke", {"reason": reason} if reason else {})

    def health(self) -> dict:
        return self._request("GET", "/v1/health")

    def register_webhook(self, url: str, events: Optional[List[str]] = None) -> dict:
        """Register a webhook to receive revocation events."""
        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.post(
                    f"{self.base_url}/v1/webhooks",
                    headers=self._get_headers(),
                    json={"url": url, "events": events or ["cert_revoked"]},
                )
                if res.status_code == 401:
                    raise AuthError("Invalid or missing API Key")
                if res.status_code not in (200, 201):
                    raise APIError(f"Warden API returned status {res.status_code}: {res.text}")
                return res.json()
        except httpx.RequestError as e:
            raise APIError(f"Failed to connect to Warden API at {self.base_url}: {str(e)}")

    def list_webhooks(self) -> List[dict]:
        return self._request("GET", "/v1/webhooks")

    def delete_webhook(self, webhook_id: str) -> dict:
        return self._request("DELETE", f"/v1/webhooks/{webhook_id}")

    def list_webhook_deliveries(self, webhook_id: str) -> List[dict]:
        return self._request("GET", f"/v1/webhooks/{webhook_id}/deliveries")

    def list_api_keys(self) -> List[dict]:
        return self._request("GET", "/v1/api-keys")

    def create_api_key(self, name: str, scopes: Optional[List[str]] = None) -> dict:
        """Create a scoped API key. Its plaintext value is returned only once."""
        return self._request("POST", "/v1/api-keys", {"name": name, "scopes": scopes or ["verify:read"]})

    def revoke_api_key(self, key_id: str) -> dict:
        return self._request("POST", f"/v1/api-keys/{key_id}/revoke")

    def verify_or_raise(self, tool_url: str) -> WardenResponse:
        result = self.verify(tool_url)
        if result.decision != "allow":
            raise ToolNotTrustedError(result.reason)
        return result

    def _request(self, method: str, path: str, payload: Optional[dict] = None) -> Any:
        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.request(method, f"{self.base_url}{path}", headers=self._get_headers(), json=payload)
                if response.status_code == 401:
                    raise AuthError("Invalid or missing API Key")
                if not 200 <= response.status_code < 300:
                    raise APIError(f"Warden API returned status {response.status_code}: {response.text}")
                return response.json()
        except httpx.RequestError as error:
            raise APIError(f"Failed to connect to Warden API at {self.base_url}: {str(error)}")

    def handle_revocation_event(self, certificate_id: str) -> None:
        """Invalidate cached certificates when a revocation webhook is received."""
        self.cache.invalidate_by_certificate_id(certificate_id)
