# CAF workload image. Everything in this file is measured: its digest is what KMS conditions pin.
#
# Build context is the repository root:  docker build -f workload/Dockerfile .
#
# Reproducibility rules:
#   - every base image and binary is pinned by digest or checksum (see config/components.lock.json)
#   - SOURCE_DATE_EPOCH is fixed per release; build with `make reproduce` (BuildKit, rewrite-timestamp=true)
#   - no network access after the fetch stage; no package index lookups at build time beyond pinned hashes

ARG CUDA_BASE=nvcr.io/nvidia/cuda@sha256:REPLACE_WITH_PINNED_DIGEST

# ---- fetch stage: download and checksum-verify scanner binaries -------------------------------------------
FROM ${CUDA_BASE} AS fetch
COPY workload/config/components.lock.json /tmp/components.lock.json
COPY workload/tools/fetch_components.py /tmp/fetch_components.py
RUN python3 /tmp/fetch_components.py /tmp/components.lock.json /opt/scanners

# ---- runtime stage ---------------------------------------------------------------------------------------
FROM ${CUDA_BASE}

# Confidential Space launch policy. These labels are enforced by the launcher and appear in attestation claims.
LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.log_redirect"="never"
LABEL "tee.launch_policy.monitoring_memory_allow"="never"
# Only these two variables may be set at launch; their values appear in the attestation claims.
LABEL "tee.launch_policy.allow_env_override"="CAF_JOB_ID,CAF_DEPLOYMENT"

# Offline scanner databases and project rules are part of the measured image (no runtime updates).
COPY --from=fetch /opt/scanners /opt/scanners
COPY rules/ /opt/caf/rules/
COPY templates/ /opt/caf/templates/
COPY workload/config/ /opt/caf/config/
COPY schemas/ /opt/caf/schemas/

COPY workload/requirements.txt /opt/caf/requirements.txt
RUN pip install --no-deps --require-hashes -r /opt/caf/requirements.txt

COPY workload/caf/ /opt/caf/caf/

ENV PATH="/opt/scanners/bin:${PATH}" \
    PYTHONPATH="/opt/caf" \
    PYTHONDONTWRITEBYTECODE=1 \
    CAF_WORKDIR=/dev/shm/caf

USER 65532:65532
ENTRYPOINT ["python3", "-m", "caf.main"]
