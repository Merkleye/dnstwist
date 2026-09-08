#!/usr/bin/env bash
# Runs the local equivalent of CI's "OpenAPI contract" job: a real uvicorn
# serving app.py, and schemathesis replaying every declared operation against
# it with response-schema validation on.
#
# This is the check that catches the class of bug a unit test cannot: the
# document and the server disagreeing. tests/test_app.py asserts what the
# handlers return, and scripts/validate-spec.py reads the document, but only
# this pass puts a live response next to the schema that claims to describe it
# — an undocumented status code, a field the document says is required and the
# handler omits, a content type that changed when a response class did.
#
# Requires: python matching mise.toml, the dependencies in requirements.txt,
# and schemathesis. mise.toml pins the exact version CI uses under
# "pipx:schemathesis", so `mise run contract` installs the same one and a pass
# here means what a pass in CI means.
#
# Override DNSTWIST_CONTRACT_PORT if 8000 is already bound locally.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${DNSTWIST_CONTRACT_HOST:-127.0.0.1}"
PORT="${DNSTWIST_CONTRACT_PORT:-8000}"
PIDFILE=uvicorn.contract.pid
LOGFILE=uvicorn.contract.log

# Force-succeeded, and the pidfile is checked rather than assumed: under
# `set -e` a bare `[ -f x ] && kill ...` aborts the trap when the file is
# absent, which is precisely the case where the server never started.
cleanup() {
  if [ -f "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
  fi
  rm -f "$PIDFILE"
}
trap cleanup EXIT

echo "==> starting uvicorn on ${HOST}:${PORT}"
# OTEL_SDK_DISABLED: a contract run has no collector to export to, and app.py
# reads this the same way the Go backend does — no exporter thread, no
# per-request context propagation. LOG_LEVEL warning keeps the fuzzer's few
# thousand request lines out of the output.
OTEL_SDK_DISABLED=true LOG_LEVEL=warning \
  python -m uvicorn app:app --host "$HOST" --port "$PORT" --log-level warning \
  > "$LOGFILE" 2>&1 &
echo $! > "$PIDFILE"

for i in $(seq 1 30); do
  if curl -sf "http://${HOST}:${PORT}/health" >/dev/null; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "uvicorn did not become healthy in time"
    cat "$LOGFILE"
    exit 1
  fi
  sleep 1
done

echo "==> schemathesis"
# Flags must stay identical to .github/workflows/ci.yml's api-contract job —
# the point of this script is that a laptop runs what CI runs.
#
# `--checks all` is kept explicit even though v4 defaults to it, because the
# flag is what says nothing here is switched off. Note that v4's `all` includes
# positive_data_acceptance and negative_data_rejection, and its default
# generation mode covers negative inputs as well as positive; that is
# deliberately not narrowed, since this pass exists to find routes the document
# lies about. A check that starts failing here is a bug in the route or in the
# document, not a flag to remove. The one operation that needs a wider set of
# acceptable answers says so in schemathesis.toml, per operation and per check.
#
# POST /enrich is excluded from the whole run. It resolves whatever name it is
# given, so replaying it would point the resolver at every string the fuzzer
# invents, at DNS latency per example and with a result that depends on what
# the world answers today — the one operation here whose behaviour is not a
# function of its input. tests/test_app.py covers its contract with resolution
# mocked instead.
schemathesis run api/openapi.yaml \
  --url "http://${HOST}:${PORT}" \
  --checks all \
  --exclude-path /enrich \
  --max-examples 25
