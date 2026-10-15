"""Structured status events: the ONLY thing the workload may log.

The schema is closed. Fields are job metadata and stage outcomes; there is deliberately no free-text field,
so payload-derived content (file names, code, findings) cannot be logged by accident. Adding a field is a
trust-boundary change (see CONTRIBUTING.md).
"""

from __future__ import annotations

import json
import sys
import time
from enum import Enum


class Stage(str, Enum):
    START = "start"
    ATTESTED = "attested"
    KEY_RELEASED = "key_released"
    DECRYPTED = "decrypted"
    SCANNED = "scanned"
    ANALYZED = "analyzed"
    SEALED = "sealed"
    SIGNED = "signed"
    PUBLISHED = "published"
    ZEROIZED = "zeroized"
    FAILED = "failed"


class ErrorCode(str, Enum):
    NONE = "none"
    ATTESTATION = "attestation"
    KEY_RELEASE = "key_release"
    INTEGRITY = "integrity"
    SCANNER = "scanner"
    MODEL = "model"
    OUTPUT = "output"
    INTERNAL = "internal"


_ALLOWED_COUNTERS = {"findings_total", "duration_ms", "bundle_bytes"}


def emit(job_id: str, stage: Stage, error: ErrorCode = ErrorCode.NONE, **counters: int) -> None:
    """Write one JSON event to stdout. Only integer counters from an allow list are accepted."""
    unknown = set(counters) - _ALLOWED_COUNTERS
    if unknown:
        raise ValueError(f"event fields not in schema: {sorted(unknown)}")
    if not all(isinstance(v, int) for v in counters.values()):
        raise TypeError("event counters must be integers")
    record = {"ts": int(time.time()), "job_id": job_id, "stage": stage.value, "error": error.value, **counters}
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
    sys.stdout.flush()
