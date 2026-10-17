"""Cloud Run entrypoint. Authentication is enforced by Cloud Run IAM (roles/run.invoker), not in this code."""

from __future__ import annotations

import json
import logging
import os

from flask import Flask, request

from . import logic
from .gcp import Launcher

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("caf.launcher")

app = Flask(__name__)
_launcher: Launcher | None = None


def launcher() -> Launcher:
    global _launcher
    if _launcher is None:
        _launcher = Launcher(logic.Settings.from_env(dict(os.environ)))
    return _launcher


@app.post("/events")
def events():
    """Pub/Sub push endpoint. 2xx acknowledges; 5xx asks Pub/Sub to redeliver (then dead-letter)."""
    try:
        job = logic.parse_push(request.get_json(force=True, silent=True) or {}, launcher().s)
        name = launcher().launch(job)
        log.info(json.dumps({"event": "launched", "job_id": job.job_id, "instance": name}))
        return "", 204
    except logic.Ignore as e:
        log.info(json.dumps({"event": "ignored", "reason": str(e)}))
        return "", 204
    except logic.Retry as e:
        log.warning(json.dumps({"event": "retry", "reason": str(e)}))
        return "", 503


@app.post("/sweep")
def sweep():
    deleted = launcher().sweep()
    log.info(json.dumps({"event": "swept", "deleted": deleted}))
    return {"deleted": deleted}, 200
