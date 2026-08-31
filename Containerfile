# Merkleye dnstwist sidecar.
#
# Stateless by design: no volumes, no database, no published ports. It takes a
# domain and returns strings, so a crash here cannot corrupt state.
#
# Consumed by merkleye/merkleye's deploy/docker-compose.yml as
# ghcr.io/merkleye/merkleye-dnstwist — this repo owns the source and CI/CD for
# that image; merkleye/merkleye only references the published tag.
FROM python:3.12-slim

ARG OCI_VERSION=0.0.0
ARG OCI_REVISION=unknown
ARG OCI_CREATED=unknown
ARG OCI_REF_NAME=dev
ARG OCI_SOURCE=https://github.com/merkleye/dnstwist

LABEL org.opencontainers.image.title="Merkleye dnstwist sidecar" \
      org.opencontainers.image.description="Domain permutation / lookalike generator" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.url="${OCI_SOURCE}" \
      org.opencontainers.image.version="${OCI_VERSION}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.ref.name="${OCI_REF_NAME}"

# Non-root: this service makes outbound DNS queries to attacker-controlled
# infrastructure and should hold no more privilege than that needs.
RUN useradd --system --create-home --uid 10001 dnstwist

WORKDIR /app

COPY requirements.txt .
# dnstwist[full] pulls in py-tlsh, which has no prebuilt wheel and compiles a
# C++ extension — g++ is build-time only, removed once the wheel is built.
RUN apt-get update && \
    apt-get install -y --no-install-recommends g++ && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove g++ && \
    rm -rf /var/lib/apt/lists/*

COPY app.py .

USER dnstwist

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status==200 else 1)"

# uvicorn has no env-var-driven log level of its own, so LOG_LEVEL (see
# merkleye/merkleye's docker-compose.local.yml) is threaded through as
# --log-level via a shell wrapper. Unset defaults to uvicorn's own "info".
# Vocabulary differs from merkleye's internal/logging on the Go side for one
# value: uvicorn wants "warning", not "warn" — only "debug"/"info"/"error"
# are spelled the same on both sides.
CMD ["sh", "-c", "exec uvicorn app:app --host 0.0.0.0 --port 8000 --log-level \"${LOG_LEVEL:-info}\""]
