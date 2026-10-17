"""CAF control-plane launcher: turns ingest-bucket upload events into single-use Confidential Space scan VMs.

Control plane only. It sees object names and sizes, never plaintext, and holds no KMS rights. Nothing here is part
of the measured trust boundary: a compromised launcher can refuse or delay scans, but cannot read vendor data or
forge signed artifacts.
"""
