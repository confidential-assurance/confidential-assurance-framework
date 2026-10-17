"""Thin Google Cloud adapters around logic.py."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from google.api_core import exceptions as gexc
from google.cloud import compute_v1, storage

from . import logic

log = logging.getLogger("caf.launcher")


class Launcher:
    def __init__(self, settings: logic.Settings):
        self.s = settings
        self.instances = compute_v1.InstancesClient()
        self.templates = compute_v1.InstanceTemplatesClient()
        self.storage = storage.Client(project=settings.project_id)

    def payload_size(self, job: logic.Job) -> int | None:
        blob = self.storage.bucket(self.s.ingest_bucket).get_blob(f"{job.job_id}/payload.bin")
        return None if blob is None else blob.size

    def template_metadata(self) -> list[tuple[str, str]]:
        tpl = self.templates.get(project=self.s.project_id, instance_template=self.s.scan_template)
        return [(i.key, i.value) for i in tpl.properties.metadata.items]

    def launch(self, job: logic.Job) -> str:
        logic.check_payload(self.payload_size(job), self.s)
        name = logic.instance_name(job)
        items = logic.instance_metadata(self.template_metadata(), job, self.s)
        instance = compute_v1.Instance(
            name=name,
            labels=logic.instance_labels(job),
            metadata=compute_v1.Metadata(items=[compute_v1.Items(key=k, value=v) for k, v in items]),
        )
        try:
            # source_instance_template is a request field, not a flattened argument, so build the request.
            self.instances.insert(request=compute_v1.InsertInstanceRequest(
                project=self.s.project_id,
                zone=self.s.zone,
                instance_resource=instance,
                source_instance_template=f"projects/{self.s.project_id}/global/instanceTemplates/{self.s.scan_template}",
            ))
        except gexc.Conflict:
            log.info("scan VM already exists", extra={"job_id": job.job_id, "instance": name})
            return name
        except (gexc.ServiceUnavailable, gexc.TooManyRequests, gexc.InternalServerError) as e:
            raise logic.Retry(type(e).__name__) from e
        log.info("scan VM requested", extra={"job_id": job.job_id, "instance": name})
        return name

    def sweep(self) -> list[str]:
        now = datetime.now(UTC)
        deleted = []
        req = compute_v1.ListInstancesRequest(project=self.s.project_id, zone=self.s.zone,
                                              filter="labels.caf-role = scan")
        for inst in self.instances.list(request=req):
            if logic.should_sweep(inst.status, inst.creation_timestamp, now, self.s.max_scan_seconds):
                try:
                    self.instances.delete(project=self.s.project_id, zone=self.s.zone, instance=inst.name)
                    deleted.append(inst.name)
                except gexc.NotFound:
                    pass
        return deleted
