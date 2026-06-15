# Multi-stage, non-root, no-secrets build (supply-chain hardening — see deploy/supply-chain.md for the
# CI-side hash-pinning / SBOM / trivy scan / cosign signing that complete this).
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
# Install into an isolated prefix we copy into the runtime (keeps build tools out of the final image).
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim AS runtime
# Run as an unprivileged user — a container RCE does not get root inside the sandbox.
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --from=builder /install /usr/local
COPY app ./app
# On Cloud Run this runs as the DWD service account (ambient metadata token; no gcloud, no key).
# .dockerignore keeps .env / *.sqlite3 / keys / *.local.md OUT of the image layers.
ENV PORT=8080 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER appuser
EXPOSE 8080
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
