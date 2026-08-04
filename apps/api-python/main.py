import os
import httpx
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="Warden REST API (Legacy Proxy)",
    description="Thin proxy to the Warden Core API — prefer calling Core API directly or using the SDK.",
    version="1.0.0",
)

security = HTTPBearer()

WARDEN_CORE_API_URL = os.getenv("WARDEN_CORE_API_URL", "http://localhost:3000")
WARDEN_API_KEY = os.getenv("WARDEN_API_KEY", "warden-test-key-123")

def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    if credentials.credentials != WARDEN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key"
        )
    return credentials.credentials

class VerifyRequest(BaseModel):
    tool_url: str

class VerifyResponse(BaseModel):
    decision: str
    reason: str
    certificate_id: Optional[str] = None
    risk_score: int = 0
    approved_capabilities: Optional[List[str]] = None

class ScanRequest(BaseModel):
    tool_url: str

def _core_headers() -> dict:
    return {
        "Authorization": f"Bearer {WARDEN_API_KEY}",
        "Content-Type": "application/json",
    }

@app.get("/v1/health")
async def health():
    return {"status": "ok", "proxy": True, "core_api": WARDEN_CORE_API_URL}

@app.post("/verify", response_model=VerifyResponse, dependencies=[Depends(verify_api_key)])
async def verify_tool(body: VerifyRequest):
    """Legacy endpoint — proxies to POST /v1/certificates/verify on Core API."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            res = await client.post(
                f"{WARDEN_CORE_API_URL}/v1/certificates/verify",
                headers=_core_headers(),
                json={"tool_url": body.tool_url},
            )
            if res.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid or missing API Key")
            if res.status_code != 200:
                raise HTTPException(status_code=res.status_code, detail=res.text)
            return res.json()
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Failed to contact Core API: {str(e)}")

@app.post("/v1/certificates/verify", response_model=VerifyResponse, dependencies=[Depends(verify_api_key)])
async def verify_tool_v1(body: VerifyRequest):
    return await verify_tool(body)

@app.post("/scan", dependencies=[Depends(verify_api_key)])
async def scan_tool(body: ScanRequest):
    async with httpx.AsyncClient(timeout=15.0) as client:
        if os.path.exists(body.tool_url):
            import json
            with open(body.tool_url, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        else:
            fetch = await client.get(body.tool_url)
            if fetch.status_code != 200:
                raise HTTPException(status_code=400, detail=f"Failed to fetch manifest: HTTP {fetch.status_code}")
            manifest = fetch.json()

        scan_res = await client.post(
            f"{WARDEN_CORE_API_URL}/v1/scans",
            headers=_core_headers(),
            json={
                "tool_name": manifest.get("name", "mcp-tool"),
                "source_url": body.tool_url,
                "manifest": manifest,
                "actor": "rest-api:scan",
            },
        )
        if scan_res.status_code not in (200, 201):
            raise HTTPException(status_code=500, detail=f"Core API scan failed: {scan_res.text}")
        return scan_res.json()

@app.get("/certificate/{id}", dependencies=[Depends(verify_api_key)])
async def get_certificate(id: str):
    async with httpx.AsyncClient(timeout=15.0) as client:
        cert_res = await client.get(
            f"{WARDEN_CORE_API_URL}/v1/certificates/{id}",
            headers=_core_headers(),
        )
        if cert_res.status_code != 200:
            raise HTTPException(status_code=cert_res.status_code, detail=cert_res.text)
        return cert_res.json()

@app.get("/v1/certificates/{id}", dependencies=[Depends(verify_api_key)])
async def get_certificate_v1(id: str):
    return await get_certificate(id)
