.PHONY: lint test reproduce licenses tf-validate

lint:
	ruff check workload cli
	terraform -chdir=infra/terraform fmt -check -recursive
	python3 -c "import json,glob,jsonschema; [jsonschema.Draft202012Validator.check_schema(json.load(open(f))) for f in glob.glob('schemas/*.json')]"

test:
	pytest -q tests

licenses:
	cd workload/tools && python3 check_licenses.py ../config/components.lock.json

tf-validate:
	terraform -chdir=infra/terraform init -backend=false && terraform -chdir=infra/terraform validate

# Rebuild the workload image from source and print its digest. Must match the signed release.
reproduce:
	SOURCE_DATE_EPOCH=$$(git log -1 --format=%ct) docker buildx build -f workload/Dockerfile . \
	  --output "type=oci,dest=/tmp/caf.tar,rewrite-timestamp=true" \
	  --provenance=false --sbom=false --metadata-file /tmp/caf-meta.json
	@python3 -c "import json; print(json.load(open('/tmp/caf-meta.json'))['containerimage.digest'])"
