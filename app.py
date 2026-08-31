"""dnstwist sidecar for Merkleye.

Two endpoints, deliberately split by when they run:

  POST /generate  — batch, one domain at a time, run when a domain is added
                    or a set is regenerated. Produces lookalike permutations
                    and resolves registered/mx for each of them in bulk — a
                    one-time, few-second pass rather than continuous traffic.
  POST /enrich    — at hit time, one domain. Full resolution (A/MX/NS) for a
                    single lookalike, called only after a certificate for it
                    has actually appeared in CT.

Batch-resolving registered/mx during /generate is a deliberate, narrow
exception to dnstwist's normal mode of resolving every permutation to see
which exist: doing that continuously answers "does this domain exist?" when
the question is "is someone standing infrastructure up on it?", and a
certificate showing up in CT is a far better continuous trigger than a DNS
sweep. Registered/mx at generation time is acceptable because it only runs
once per generation/regeneration, not on a poll loop — see DESIGN §08 for the
full offline-generate / hit-time-enrich rationale this narrows.

This service never touches Postgres. It takes a domain and returns strings, so
it is trivially testable and a crash here cannot corrupt state.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import sys
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import dnstwist
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# socket.gethostbyname_ex has no per-call timeout. That was fine for /enrich
# (one call per hit), but the bulk generation-time pass below fans it out
# across a thread pool over potentially thousands of variants — a single
# slow-to-answer resolver could otherwise stall a worker indefinitely and
# blow past the "a few seconds" this is supposed to take. Bound it the same
# way dns.resolver's MX/NS lookups already are (lifetime=5.0).
socket.setdefaulttimeout(5.0)

app = FastAPI(
    title="Merkleye dnstwist sidecar",
    description="Lookalike domain generation and hit-time enrichment.",
    version="0.1.0",
)

# OTEL_SDK_DISABLED mirrors the Go backend's kill switch (internal/telemetry,
# https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).
# Checked explicitly, rather than relying on the Python SDK's own internal
# check (TracerProvider.get_tracer() returns a no-op tracer when this is set),
# so a disabled sidecar never even opens the OTLP exporter's background export
# thread or pays FastAPIInstrumentor's per-request context-propagation cost.
_otel_sdk_disabled = os.getenv("OTEL_SDK_DISABLED", "").strip().lower() == "true"

if not _otel_sdk_disabled:
    # OTEL_EXPORTER_OTLP_ENDPOINT/_INSECURE/OTEL_SERVICE_NAME are the real
    # OTEL env vars; the exporter's own endpoint arg only falls back to the
    # narrower *_TRACES_* variants, not this one, so it is read by hand here.
    # An unreachable/missing collector never fails a request either way:
    # BatchSpanProcessor exports on a background thread and swallows export
    # errors internally (SDK-logged, not raised) — same failure mode as the
    # Go backend's OTLP exporter.
    _otel_insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").strip().lower() == "true"
    tracer_provider = TracerProvider(resource=Resource.create({
        "service.name": os.getenv("OTEL_SERVICE_NAME", "merkleye-dnstwist"),
        "service.version": "0.1.0",
    }))
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector:4317"),
        insecure=_otel_insecure,
    )))
    trace.set_tracer_provider(tracer_provider)
    FastAPIInstrumentor.instrument_app(app)


def _configure_logging() -> logging.Logger:
    """Single-line JSON stdout logger, correlated to the active OTEL span.

    Mirrors internal/logging on the Go backend so promtail's JSON pipeline
    stage (see promtail.local.yml, which already extracts level/trace_id/
    span_id for the backend) does the same for dnstwist, and Loki/Tempo stay
    cross-linked for both services. LOG_LEVEL here is this logger's own
    threshold — separate from the same env var's other job of setting
    uvicorn's --log-level (Containerfile CMD), since uvicorn's own framework
    logs are a different logger tree this does not touch.
    """
    level = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }.get(os.getenv("LOG_LEVEL", "info").strip().lower(), logging.INFO)

    class _JSONFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload: dict[str, Any] = {
                "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "level": record.levelname,
                "msg": record.getMessage(),
            }
            ctx = trace.get_current_span().get_span_context()
            if ctx.is_valid:
                payload["trace_id"] = f"{ctx.trace_id:032x}"
                payload["span_id"] = f"{ctx.span_id:016x}"
            payload.update(getattr(record, "extra_fields", {}))
            return json.dumps(payload)

    logger = logging.getLogger("merkleye.dnstwist")
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JSONFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


log = _configure_logging()


class _RequestLoggingMiddleware(BaseHTTPMiddleware):
    """The dnstwist analogue of router.go's requestLogger: one JSON line per
    request, at debug level, carrying whatever trace/span is active — which
    is FastAPIInstrumentor's request span when OTEL is enabled, absent
    entirely when OTEL_SDK_DISABLED is set.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        log.debug(
            "http",
            extra={"extra_fields": {
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.monotonic() - start) * 1000, 3),
            }},
        )
        return response


app.add_middleware(_RequestLoggingMiddleware)

# Mirrors variants.DefaultAlgorithms in the Go backend.
# The full dnstwist fuzzer set as of 20250130, verified against the installed
# package rather than assumed. "cyrillic" matters especially here: Cyrillic
# homoglyph substitution is the canonical lookalike attack, and omitting it
# would silently drop exactly the permutations most worth watching.
# dnstwist labels the input domain itself "*original", which is filtered out.
DEFAULT_ALGORITHMS = [
    "addition", "bitsquatting", "cyrillic", "dictionary", "homoglyph",
    "hyphenation", "insertion", "omission", "plural", "repetition",
    "replacement", "subdomain", "tld-swap", "transposition", "various",
    "vowel-swap",
]

# A curated high-abuse list, not all ~1,500 TLDs. Unbounded TLD expansion
# multiplies every permutation and adds far more false positives than true
# ones — the binding constraint is alert quality, not storage. See DESIGN G-17.
DEFAULT_TLDS = [
    "com", "net", "org", "co", "io", "xyz", "top", "online",
    "site", "live", "shop", "app", "cc", "info", "biz",
]


class GenerateRequest(BaseModel):
    domain: str
    algorithms: list[str] = Field(default_factory=lambda: list(DEFAULT_ALGORITHMS))
    tlds: list[str] = Field(default_factory=lambda: list(DEFAULT_TLDS))
    dictionary: list[str] = Field(default_factory=list)
    max_variants: int = 25_000


class Variant(BaseModel):
    fqdn: str
    algorithm: str
    unicode: str | None = None
    tld: str = ""
    registered: bool = False
    mx: list[str] = Field(default_factory=list)


class GenerateResponse(BaseModel):
    generator: str = "dnstwist"
    generator_version: str
    config_hash: str
    truncated: bool
    variants: list[Variant]


class EnrichRequest(BaseModel):
    domain: str


class EnrichResponse(BaseModel):
    resolves: bool
    a: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    registered_at: datetime | None = None
    geo: str | None = None


def _generator_version() -> str:
    return getattr(dnstwist, "__version__", "unknown")


def _config_hash(req: GenerateRequest) -> str:
    """Hash the generation inputs.

    Two runs with the same hash produce the same set, which is what lets the
    backend skip a pointless regeneration and lets an analyst confirm months
    later that a stored set matches the config that claims to have produced it.
    See DESIGN G-10.
    """
    payload = json.dumps(
        {
            "domain": req.domain,
            "algorithms": sorted(req.algorithms),
            "tlds": sorted(req.tlds),
            "dictionary": sorted(req.dictionary),
            "generator_version": _generator_version(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def _normalize(name: str) -> tuple[str, str | None]:
    """Return (a_label, u_label_or_None) for a generated permutation.

    dnstwist already emits A-labels — a cyrillic permutation comes back as
    "xn--80ajb1au1a38g.com", not the Cyrillic string — so the work here is
    mostly the *other* direction: decoding back to a U-label for display.

    Both forms matter, for different reasons. The A-label is the match key,
    because certificate SANs carry IDNs punycode-encoded on the wire; comparing
    Unicode against those would match nothing, a silent no-op that looks like a
    working feature (DESIGN G-08). The U-label is what a human needs to see —
    "xn--80ajb1au1a38g.com" conveys nothing, while "ехамрӏе.com" shows the
    attack at a glance.
    """
    if not name:
        return "", None
    if name.isascii():
        if not name.startswith("xn--") and ".xn--" not in name:
            return name, None
        try:
            return name, name.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            # An A-label we cannot decode is still a valid match key.
            return name, None
    try:
        return name.encode("idna").decode("ascii"), name
    except (UnicodeError, UnicodeDecodeError):
        # Not encodable as IDNA, so it cannot appear in a certificate either.
        return "", None


def _effective_tld(fqdn: str, original_domain: str, candidate_tlds: list[str]) -> str:
    """Return the effective TLD of a generated permutation.

    `original_domain` is always the registrable domain (eTLD+1, DESIGN G-06),
    so its own suffix is exactly everything after the first label — no
    public-suffix-list lookup needed, and correct even for multi-label
    suffixes like "co.uk". The only *other* possible suffix in a run's output
    is one of the tld-swap candidates passed in the request, since dnstwist
    only swaps to entries in its tld_dictionary. Matching the longer of those
    two closed candidates against fqdn is therefore exact.
    """
    candidates = {t.lower().lstrip(".") for t in candidate_tlds}
    if "." in original_domain:
        candidates.add(original_domain.split(".", 1)[1].lower())

    matched = ""
    for tld in candidates:
        if (fqdn == tld or fqdn.endswith("." + tld)) and len(tld) > len(matched):
            matched = tld
    return matched


def _resolve(domain: str) -> tuple[list[str], list[str], list[str]]:
    """Resolve one domain's A, MX, and NS records.

    Shared by /enrich (hit-time, single domain) and the bulk generation-time
    pass below, which only needs a subset (registered = bool(a), mx) of what
    /enrich exposes — one resolution implementation so the two can never
    silently diverge on what "registered" means.
    """
    a_records: list[str] = []
    try:
        _, _, addrs = socket.gethostbyname_ex(domain)
        a_records = addrs
    except (socket.gaierror, UnicodeError):
        pass

    mx_records: list[str] = []
    ns_records: list[str] = []
    try:
        import dns.resolver  # optional; ships with dnstwist's extras

        for rtype, sink in (("MX", mx_records), ("NS", ns_records)):
            try:
                for rdata in dns.resolver.resolve(domain, rtype, lifetime=5.0):
                    sink.append(str(rdata).strip())
            except Exception:
                continue
    except ImportError:
        pass

    return a_records, mx_records, ns_records


# Matches dnstwist's own CLI default (-t, --threads 18). Sequential resolution
# across thousands of generated variants would not finish in the few seconds
# this is expected to take.
_RESOLVE_WORKERS = 18


def _resolve_stream(variants: list[Variant]) -> Iterator[Variant]:
    """Resolve registered + mx for every variant, concurrently, yielding each
    as its resolution completes rather than in submission order.
    """
    if not variants:
        return
    with ThreadPoolExecutor(max_workers=_RESOLVE_WORKERS) as pool:
        futures = {pool.submit(_resolve, v.fqdn): v for v in variants}
        for future in as_completed(futures):
            variant = futures[future]
            a_records, mx_records, _ns_records = future.result()
            variant.registered = bool(a_records)
            variant.mx = mx_records
            yield variant


def _resolve_all(variants: list[Variant]) -> None:
    for _ in _resolve_stream(variants):
        pass


def _run_fuzzer(req: GenerateRequest) -> list[dict[str, str]]:
    if not req.domain:
        raise HTTPException(status_code=400, detail="domain is required")
    if req.max_variants <= 0:
        raise HTTPException(status_code=400, detail="max_variants must be positive")

    try:
        fuzzer = dnstwist.Fuzzer(req.domain, dictionary=req.dictionary, tld_dictionary=req.tlds)
        fuzzer.generate()
        return fuzzer.permutations()
    except HTTPException:
        raise
    except Exception as exc:  # dnstwist raises bare exceptions on bad input
        raise HTTPException(status_code=400, detail=f"dnstwist: {exc}") from exc


def _filtered_variants(req: GenerateRequest, permutations: list[dict[str, str]]) -> Iterator[tuple[Variant, bool]]:
    """Yield (variant, truncated) pairs — the shared filter/dedup/cap logic
    behind both /generate and /generate/stream, so the two endpoints can never
    silently diverge on which permutations they return.
    """
    wanted = {a.lower() for a in req.algorithms}
    seen: set[str] = set()
    count = 0

    for perm in permutations:
        algorithm = perm.get("fuzzer", "unknown")
        # dnstwist labels the input itself "*original"; it is not a lookalike.
        if algorithm.startswith("*") or algorithm.lower() not in wanted:
            continue

        name = perm.get("domain", "")
        if not name:
            continue

        ascii_name, unicode_name = _normalize(name)
        if not ascii_name or ascii_name in seen:
            continue
        seen.add(ascii_name)

        tld = _effective_tld(ascii_name, req.domain, req.tlds)

        if count >= req.max_variants:
            yield Variant(fqdn=ascii_name, algorithm=algorithm, unicode=unicode_name, tld=tld), True
            return

        count += 1
        yield Variant(fqdn=ascii_name, algorithm=algorithm, unicode=unicode_name, tld=tld), False


@app.post("/generate", response_model=GenerateResponse)
def generate(req: GenerateRequest) -> GenerateResponse:
    permutations = _run_fuzzer(req)

    variants: list[Variant] = []
    truncated = False
    for variant, would_truncate in _filtered_variants(req, permutations):
        if would_truncate:
            truncated = True
            break
        variants.append(variant)

    _resolve_all(variants)

    return GenerateResponse(
        generator_version=_generator_version(),
        config_hash=_config_hash(req),
        truncated=truncated,
        variants=variants,
    )


@app.post("/generate/stream")
def generate_stream(req: GenerateRequest) -> StreamingResponse:
    """Same generation as /generate, emitted as newline-delimited JSON.

    One line per variant, followed by exactly one closing line —
    {"type":"done",...} on success or {"type":"error",...} on failure.
    Fuzzing/filtering itself is near-instant, so variant lines are emitted as
    each one's registered/mx resolution completes rather than as it clears
    the filter/dedup pipeline — resolving thousands of candidates is the part
    of this that actually takes a few seconds, and that's what a caller
    watching this feed is waiting on.
    """
    permutations = _run_fuzzer(req)

    def body() -> Iterator[str]:
        variants: list[Variant] = []
        truncated = False
        try:
            for variant, would_truncate in _filtered_variants(req, permutations):
                if would_truncate:
                    truncated = True
                    break
                variants.append(variant)
        except Exception as exc:  # keep a mid-stream failure visible to the caller
            yield json.dumps({"type": "error", "detail": str(exc)}) + "\n"
            return

        try:
            for variant in _resolve_stream(variants):
                yield json.dumps({"type": "variant", **variant.model_dump()}) + "\n"
        except Exception as exc:
            yield json.dumps({"type": "error", "detail": str(exc)}) + "\n"
            return

        yield json.dumps({
            "type": "done",
            "generator": "dnstwist",
            "generator_version": _generator_version(),
            "config_hash": _config_hash(req),
            "truncated": truncated,
            "variant_count": len(variants),
        }) + "\n"

    return StreamingResponse(body(), media_type="application/x-ndjson")


@app.post("/enrich", response_model=EnrichResponse)
def enrich(req: EnrichRequest) -> EnrichResponse:
    """Resolve one lookalike, at hit time.

    NOTE: this is outbound traffic aimed at attacker-controlled infrastructure
    and signals that you are watching. Some SOCs want it proxied or disabled —
    the backend gates it behind config. See DESIGN §18, open decision 4.
    """
    if not req.domain:
        raise HTTPException(status_code=400, detail="domain is required")

    # MX presence is the signal that matters most here: it means the lookalike
    # can receive mail, i.e. it is capable of credential harvesting or BEC.
    a_records, mx_records, ns_records = _resolve(req.domain)

    # TODO(phase-3): registration age is the single strongest phishing signal
    # (+25 in the risk model). It needs a WHOIS/RDAP lookup, which is a separate
    # egress decision from DNS — wire it with its own config gate.
    return EnrichResponse(
        resolves=bool(a_records),
        a=a_records,
        mx=mx_records,
        ns=ns_records,
        registered_at=None,
    )


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "generator": "dnstwist",
        "generator_version": _generator_version(),
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
