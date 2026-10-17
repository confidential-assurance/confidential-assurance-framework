# Control-plane launcher for Cloud Run. Not measured and not part of the trust boundary.
FROM python:3.12-slim
WORKDIR /app
COPY control-plane/launcher/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY control-plane/launcher/caf_launcher/ caf_launcher/
USER 65532:65532
CMD ["sh", "-c", "exec gunicorn --bind :${PORT:-8080} --workers 2 --threads 8 caf_launcher.app:app"]
