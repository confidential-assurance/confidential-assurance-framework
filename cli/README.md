# caf-cli

Command-line tool for the [Confidential Assurance Framework](https://github.com/confidential-assurance/confidential-assurance-framework).

```bash
pip install ./cli

caf keygen --out ~/.caf                     # X25519 key pair that receives your detailed report
caf bundle ./my-repo --out ./upload ...     # encrypt a source tree on your machine before upload
caf verify --results results/ ...           # check signatures, provenance and attestation
caf decrypt --results results/ ...          # open your HPKE-encrypted detailed report
```

See `docs/verification.md` in the repository for the full procedure.
