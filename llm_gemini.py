"""Vertex AI Gemini backend (native generateContent API), stdlib-only.

Same call shape confirmed working live on the aegis-redteam side: ambient
Cloud Run service-account token via the metadata server (ADC-free), the
"global" Vertex location (some new Gemini releases are global-only before
regional rollout completes), and function-calling for tool use.

NOTE: this file was written from the design doc's recorded specs, not
copied from the live aegis-redteam llm.py (that repo's zip predates the
Gemini pivot and only had AnthropicBackend). The generateContent request
shape and role/part conventions below match Google's documented Gemini
function-calling API; the model+location combination has NOT been
independently re-verified from this session (no network path to
googleapis.com from this sandbox) -- if the first live /chat call errors,
check Cloud Logging for the raw error body first.
"""
from __future__ import annotations

import json
import os
import urllib.request

from firestore_rest import gcp_metadata_token, project_id


def _endpoint(model: str, location: str) -> str:
    return (
        f"https://aiplatform.googleapis.com/v1/projects/{project_id()}"
        f"/locations/{location}/publishers/google/models/{model}:generateContent"
    )


def chat_with_tools(contents: list, system_prompt: str, tools: list,
                     model: str = None, location: str = None, max_tokens: int = 1024) -> dict:
    """One generateContent call. Returns the raw candidate `content` dict
    (caller inspects `parts` for text vs. `functionCall`)."""
    model = model or os.environ.get("VERTEX_MODEL", "gemini-3.6-flash")
    location = location or os.environ.get("VERTEX_LOCATION", "global")
    body = {
        "contents": contents,
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": {"maxOutputTokens": max_tokens},
    }
    if tools:
        body["tools"] = [{"functionDeclarations": tools}]
    req = urllib.request.Request(
        _endpoint(model, location),
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {gcp_metadata_token()}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read())
    candidates = result.get("candidates", [])
    if not candidates:
        return {"role": "model", "parts": [{"text": "(no response from model)"}]}
    return candidates[0]["content"]
