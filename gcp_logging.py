"""Structured logging for Cloud Logging (stdlib-only).

Cloud Run captures container stdout as log entries; a JSON line with
top-level "severity"/"message" keys is ingested as a *structured* entry,
filterable in Logs Explorer (e.g. jsonPayload.event="secret_leaked").
Same mechanism aegis-redteam already uses -- no client library, no extra
IAM role, no network call.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
        }
        if os.environ.get("CLOUD_RUN_EXECUTION"):
            payload["cloud_run_execution"] = os.environ["CLOUD_RUN_EXECUTION"]
        fields = getattr(record, "json_fields", None)
        if fields:
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_configured = False


def get_logger(name: str = "aegis_blueteam") -> logging.Logger:
    global _configured
    if not _configured:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())
        root = logging.getLogger()
        root.handlers = [handler]
        root.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
        _configured = True
    return logging.getLogger(name)


def log(logger: logging.Logger, severity: str, message: str, **fields: Any) -> None:
    logger.log(logging.getLevelName(severity), message, extra={"json_fields": fields})
