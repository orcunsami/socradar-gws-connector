# Supply-chain hardening runbook (release-time)

The customer pulls + runs our container, so the image must be trustworthy. These are the exact steps for a
hardened release. They run in CI / at release time (not in this dev session — shipped as the runbook).

## 1. Pin + hash dependencies (reproducible, tamper-evident installs)
```bash
cd development/app
pip install pip-tools
pip-compile --generate-hashes --output-file=requirements.lock requirements.txt
# Dockerfile then installs with hash enforcement:
#   RUN pip install --require-hashes -r requirements.lock
```
A changed/typosquatted dep fails the hash check.

## 2. SBOM (software bill of materials)
```bash
syft packages dir:development/app -o cyclonedx-json > sbom.cdx.json   # or: trivy sbom
# publish sbom.cdx.json alongside the image so customers can audit what's inside
```

## 3. No secrets in the image
- Dockerfile: use BuildKit `--secret` mounts, never `ARG`/`ENV` for secrets; `.dockerignore` must exclude
  `.env`, `*.sqlite3`, `*.local.md`, keys.
```bash
trivy image --scanners secret  REGION-docker.pkg.dev/PROJECT/REPO/gws-connector:TAG   # must be clean
docker history --no-trunc IMAGE | grep -iE 'SECRET|KEY|PASSWORD|FEED_API'              # must be empty
```

## 4. Vulnerability gate before customers pull
```bash
trivy image --severity HIGH,CRITICAL --exit-code 1 \
  REGION-docker.pkg.dev/PROJECT/REPO/gws-connector:TAG     # fail the release on HIGH/CRITICAL
# or enable Artifact Analysis (automatic scan on push) on the Artifact Registry repo.
```

## 5. Minimize the base image
Multi-stage build → distroless / slim, run as non-root (`USER nonroot`). Smaller CVE + post-exploitation surface
on a binary that holds Workspace-remediation power.

## 6. Sign the release + provenance (customers verify it's genuinely SOCRadar's)
```bash
cosign sign --yes REGION-docker.pkg.dev/PROJECT/REPO/gws-connector@sha256:DIGEST   # keyless / Sigstore
cosign verify ... --certificate-identity=... --certificate-oidc-issuer=https://accounts.google.com
# Generate SLSA build provenance in CI; customers pull BY DIGEST (immutable), not by tag.
```
Optional enforcement: Binary Authorization so Cloud Run only runs signed/attested images by digest.

## 7. Pull-by-digest in the customer deploy
Document that customers deploy `...@sha256:DIGEST` (immutable) rather than `:latest`, and verify the cosign
signature first. This closes "deploy access alone can ship a backdoored image inheriting the DWD SA".
