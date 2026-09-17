"""Stdlib-only Firestore REST client using the ambient Cloud Run
service-account token.

No google-cloud-firestore package: this service deploys via Cloud Run's
no-build source path (deploy_service_from_file_contents), which skips the
pip/build step entirely, so only the standard library is available. Same
trick aegis-redteam's llm.py already uses for Vertex AI: fetch a
short-lived access token from the GCE/Cloud Run metadata server, attach it
as a Bearer token, talk to the REST API directly.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

_METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token"
)

_token_cache = {"token": None, "expires_at": 0.0}


def gcp_metadata_token() -> str:
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 30:
        return _token_cache["token"]
    req = urllib.request.Request(_METADATA_TOKEN_URL, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read())
    _token_cache["token"] = data["access_token"]
    _token_cache["expires_at"] = now + int(data.get("expires_in", 3000))
    return _token_cache["token"]


def project_id() -> str:
    return os.environ["GCP_PROJECT"]


def _base_url() -> str:
    return (
        f"https://firestore.googleapis.com/v1/projects/{project_id()}"
        "/databases/(default)/documents"
    )


def _to_value(v):
    if v is None:
        return {"nullValue": None}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, str):
        return {"stringValue": v}
    if isinstance(v, list):
        return {"arrayValue": {"values": [_to_value(x) for x in v]}}
    if isinstance(v, dict):
        return {"mapValue": {"fields": to_fields(v)}}
    return {"stringValue": str(v)}


def _from_value(fv):
    if "stringValue" in fv:
        return fv["stringValue"]
    if "integerValue" in fv:
        return int(fv["integerValue"])
    if "doubleValue" in fv:
        return fv["doubleValue"]
    if "booleanValue" in fv:
        return fv["booleanValue"]
    if "nullValue" in fv:
        return None
    if "timestampValue" in fv:
        return fv["timestampValue"]
    if "mapValue" in fv:
        return from_fields(fv["mapValue"].get("fields", {}))
    if "arrayValue" in fv:
        return [_from_value(x) for x in fv["arrayValue"].get("values", [])]
    return None


def to_fields(d: dict) -> dict:
    return {k: _to_value(v) for k, v in d.items()}


def from_fields(fields: dict) -> dict:
    return {k: _from_value(v) for k, v in (fields or {}).items()}


def _call(method: str, url: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {gcp_metadata_token()}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise RuntimeError(
            f"Firestore {method} {url} -> {e.code}: {e.read().decode(errors='replace')}"
        )


def get_doc(collection: str, doc_id: str):
    doc = _call("GET", f"{_base_url()}/{collection}/{doc_id}")
    if doc is None:
        return None
    return from_fields(doc.get("fields", {}))


def set_doc(collection: str, doc_id: str, data: dict) -> None:
    _call("PATCH", f"{_base_url()}/{collection}/{doc_id}", {"fields": to_fields(data)})


def create_doc(collection: str, data: dict) -> str:
    """Auto-generated document ID -- used for audit_log / proposals."""
    doc = _call("POST", f"{_base_url()}/{collection}", {"fields": to_fields(data)})
    return doc["name"].rsplit("/", 1)[-1]


def delete_doc(collection: str, doc_id: str) -> None:
    _call("DELETE", f"{_base_url()}/{collection}/{doc_id}")


def list_docs(collection: str) -> list:
    """Simple unfiltered listing -- fine for this service's small collections."""
    result = _call("GET", f"{_base_url()}/{collection}") or {}
    out = []
    for doc in result.get("documents", []):
        row = from_fields(doc.get("fields", {}))
        row["_id"] = doc["name"].rsplit("/", 1)[-1]
        out.append(row)
    return out
