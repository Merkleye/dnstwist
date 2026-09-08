"""dnstwist sidecar for Merkleye.

Two endpoints, deliberately split by when they run:

  POST /generate  — batch, one domain at a time, run when a domain is added
                    or a set is regenerated. Produces lookalike permutation
                    *names* and nothing else.
  POST /enrich    — at hit time, one domain. Full resolution (A/MX/NS) for a
                    single lookalike, called only after a certificate for it
                    has actually appeared in CT.

/generate used to resolve registered/mx for every permutation it produced.
That state now belongs to internal/variantscan, which refreshes it on a
schedule against the active set — because the answer moving is the signal, and
a value frozen at generation time is wrong within weeks of being written. It
also made a run slow enough to need a progress stream, which is why the
/generate/stream endpoint that used to live here is gone: with resolution out,
generation is permutation math. See docs/VARIANT-TRACKING.md and DESIGN §08.

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
from datetime import datetime, timezone
from typing import Any

import dnstwist
import yaml
from fastapi import FastAPI, HTTPException
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

# socket.gethostbyname_ex has no per-call timeout, and /enrich runs it against
# attacker-controlled infrastructure, which has every reason to answer slowly.
# Bound it the same way dns.resolver's MX/NS lookups already are
# (lifetime=5.0).
socket.setdefaulttimeout(5.0)

SERVICE_VERSION = "0.1.0"

# Generation cost is quadratic in the length of the name being permuted.
# Measured against dnstwist 20250130 with the default TLD list: a 10-character
# domain yields 29k permutations in ~1s, a 50-character one 923k in ~68s and
# roughly a gigabyte of RSS, and a 243-character one exhausts memory and takes
# the process down with it — which, in a container, means the sidecar dies and
# every other caller's request dies with it.
#
# Nothing upstream bounds this: merkleye's watchlist accepts whatever IDNA
# accepts (internal/match.Normalize), so a single absurd-but-legal watched
# domain was enough to kill this service. The bound therefore lives here, in
# the published contract, where a caller learns about it from a 422 naming the
# field. 64 characters is past any registrable domain anyone actually watches
# and already costs ~100s to permute at the top of the range.
MAX_DOMAIN_LENGTH = 64

# Enrichment resolves, it does not permute, so the only limit that applies is
# DNS's own.
MAX_FQDN_LENGTH = 253

OPENAPI_TAGS = [
    {
        "name": "generation",
        "description": "Permutation math: a domain in, lookalike names out. No DNS.",
    },
    {
        "name": "enrichment",
        "description": (
            "Hit-time resolution of a single lookalike. Outbound traffic aimed "
            "at attacker-controlled infrastructure — see the operation's own "
            "description before enabling it in a hardened deployment."
        ),
    },
    {
        "name": "meta",
        "description": "Liveness and contract discovery.",
    },
]

# The OpenAPI document is derived from this app rather than hand-written beside
# it: FastAPI already knows every route, model and status code, so a second copy
# maintained by hand could only ever drift from the code it describes. What is
# committed (api/openapi.yaml) is that document exported to a file, so an API
# change shows up as a spec diff in review — `mise run spec` fails when the file
# and the app disagree, and `mise run contract` replays the file against a live
# server with Schemathesis. The running container publishes the same document at
# /openapi.json and /openapi.yaml, so a consumer can read the contract off the
# service it is actually talking to.
app = FastAPI(
    title="Merkleye dnstwist sidecar",
    description=(
        "Lookalike domain generation and hit-time enrichment.\n\n"
        "Stateless by design: it takes a domain and returns strings, touching "
        "no database. Consumed by "
        "[merkleye/merkleye](https://github.com/merkleye/merkleye)'s "
        "`internal/variants` client."
    ),
    version=SERVICE_VERSION,
    license_info={"name": "Apache-2.0", "identifier": "Apache-2.0"},
    openapi_tags=OPENAPI_TAGS,
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
        "service.version": SERVICE_VERSION,
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
    # The example is not decoration: it is what Schemathesis's examples phase
    # replays against a live server (scripts/test-contract.sh), which is the
    # only part of the contract run that exercises a *successful* generation —
    # a fuzzer inventing strings for an unconstrained `domain` produces names
    # dnstwist rejects, never one it can permute.
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "domain": "example.com",
                    "algorithms": ["homoglyph", "omission", "tld-swap"],
                    "tlds": ["com", "net", "xyz"],
                    "dictionary": [],
                    "max_variants": 25_000,
                }
            ]
        }
    }

    domain: str = Field(
        max_length=MAX_DOMAIN_LENGTH,
        description=(
            "The registrable domain (eTLD+1) to permute, e.g. `example.com`. "
            "Empty or unparseable input is answered with 400; the length cap "
            "is what keeps permutation cost bounded — see the field's maximum."
        ),
    )
    algorithms: list[str] = Field(
        default_factory=lambda: list(DEFAULT_ALGORITHMS),
        max_length=64,
        description=(
            "dnstwist fuzzers to keep in the output. Names outside the "
            "generated set are ignored rather than rejected, so a caller can "
            "pass a superset."
        ),
    )
    tlds: list[str] = Field(
        default_factory=lambda: list(DEFAULT_TLDS),
        max_length=256,
        description="TLDs the `tld-swap` fuzzer may swap in.",
    )
    dictionary: list[str] = Field(
        default_factory=list,
        max_length=1024,
        description="Extra words for the `dictionary` fuzzer.",
    )
    max_variants: int = Field(
        default=25_000,
        gt=0,
        le=1_000_000,
        description=(
            "Cap on returned variants. Generation itself is not bounded by "
            "this — it is a cap on the response, and `truncated` says whether "
            "it was reached."
        ),
    )


class Variant(BaseModel):
    fqdn: str = Field(
        description=(
            "A-label form, always. Certificate SANs carry IDNs punycode-"
            "encoded on the wire, so this is the match key (DESIGN G-08)."
        ),
    )
    algorithm: str = Field(description="The dnstwist fuzzer that produced it.")
    unicode: str | None = Field(
        default=None,
        description=(
            "U-label form, present only when `fqdn` is an IDN. For display: "
            "`xn--80ajb1au1a38g.com` conveys nothing, `ехамрӏе.com` shows the "
            "attack at a glance."
        ),
    )
    tld: str = Field(default="", description="Effective TLD of `fqdn`.")


class GenerateResponse(BaseModel):
    generator: str = "dnstwist"
    generator_version: str = Field(
        description="Version of the dnstwist package that produced the set."
    )
    config_hash: str = Field(
        description=(
            "`sha256:<hex>` over the generation inputs and the generator "
            "version. Two runs with the same hash produce the same set, which "
            "is what lets a caller skip a pointless regeneration and lets an "
            "analyst confirm months later that a stored set matches the config "
            "that claims to have produced it (DESIGN G-10)."
        ),
    )
    truncated: bool = Field(
        description="True when `max_variants` cut the set short."
    )
    variants: list[Variant]


class EnrichRequest(BaseModel):
    model_config = {"json_schema_extra": {"examples": [{"domain": "example.com"}]}}

    domain: str = Field(
        max_length=MAX_FQDN_LENGTH,
        description="The single lookalike to resolve. Empty input is answered with 400.",
    )


class EnrichResponse(BaseModel):
    resolves: bool = Field(description="Whether the name has at least one A record.")
    a: list[str] = Field(default_factory=list)
    mx: list[str] = Field(
        default_factory=list,
        description=(
            "MX presence is the signal that matters most: it means the "
            "lookalike can receive mail, i.e. it is capable of credential "
            "harvesting or BEC."
        ),
    )
    ns: list[str] = Field(default_factory=list)
    registered_at: datetime | None = Field(
        default=None,
        description="Always null for now — see the operation's phase-3 note.",
    )
    geo: str | None = None


class ErrorResponse(BaseModel):
    """FastAPI's own HTTPException body, declared so the 400s below are part
    of the published contract rather than an undocumented shape a caller
    discovers in production."""

    detail: str


class HealthResponse(BaseModel):
    status: str = Field(description='"ok" while the service can answer.')
    generator: str
    generator_version: str
    checked_at: datetime


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
    """Resolve one domain's A, MX, and NS records, for /enrich.

    Generation does not resolve anything any more, so this has exactly one
    caller. The scheduled state tracking that replaced the generation-time
    pass lives in Go (internal/variantscan), where reading a DNS RCODE is
    possible: distinguishing NXDOMAIN from NODATA is the whole basis of the
    delegation gate, and the socket API this uses cannot express it.
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


def _run_fuzzer(req: GenerateRequest) -> list[dict[str, str]]:
    if not req.domain:
        raise HTTPException(status_code=400, detail="domain is required")
    # Both of these are also expressed as schema constraints on
    # GenerateRequest, so over HTTP pydantic rejects them with a 422 before
    # this runs. They stay because the cost they bound is real (see
    # MAX_DOMAIN_LENGTH) and this function has callers that never went
    # through a request body.
    if len(req.domain) > MAX_DOMAIN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"domain must be at most {MAX_DOMAIN_LENGTH} characters",
        )
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
    behind /generate, so filtering and truncation can never
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


@app.post(
    "/generate",
    response_model=GenerateResponse,
    operation_id="generateVariants",
    summary="Generate lookalike permutations of one domain",
    tags=["generation"],
    responses={
        400: {
            "model": ErrorResponse,
            "description": (
                "The domain is empty, or dnstwist cannot parse it as a name "
                "(no TLD, an unencodable label). Permutation math has one "
                "input and this is what an unusable one produces."
            ),
        }
    },
)
def generate(req: GenerateRequest) -> GenerateResponse:
    """Batch: run when a domain is added or a set is regenerated.

    Produces permutation *names* and nothing else — no A lookups, no MX
    lookups, no registration check. That state belongs to merkleye's
    `internal/variantscan`, which refreshes it on a schedule against the
    active set, because the answer moving is the signal and a value frozen at
    generation time is wrong within weeks of being written.
    """
    permutations = _run_fuzzer(req)

    variants: list[Variant] = []
    truncated = False
    for variant, would_truncate in _filtered_variants(req, permutations):
        if would_truncate:
            truncated = True
            break
        variants.append(variant)

    return GenerateResponse(
        generator_version=_generator_version(),
        config_hash=_config_hash(req),
        truncated=truncated,
        variants=variants,
    )


@app.post(
    "/enrich",
    response_model=EnrichResponse,
    operation_id="enrichDomain",
    summary="Resolve one lookalike at hit time",
    tags=["enrichment"],
    responses={
        400: {"model": ErrorResponse, "description": "The domain is empty."}
    },
)
def enrich(req: EnrichRequest) -> EnrichResponse:
    """Resolve one lookalike, called only after a certificate for it has
    actually appeared in CT.

    NOTE: this is outbound traffic aimed at attacker-controlled infrastructure
    and signals that you are watching. Some SOCs want it proxied or disabled —
    the backend gates it behind config. See DESIGN §18, open decision 4.

    That is also why this operation is excluded from the live Schemathesis run
    (see schemathesis.toml): replaying it would point CI's resolver at whatever
    names a fuzzer invents, at DNS latency per example. tests/test_app.py
    covers its response contract with resolution mocked.
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


@app.get(
    "/health",
    response_model=HealthResponse,
    operation_id="getHealth",
    summary="Liveness probe",
    tags=["meta"],
)
def health() -> HealthResponse:
    """What the Containerfile's HEALTHCHECK polls, and what merkleye's perf
    suite reads the sidecar's dnstwist version from.
    """
    return HealthResponse(
        status="ok",
        generator="dnstwist",
        generator_version=_generator_version(),
        checked_at=datetime.now(timezone.utc),
    )


class _OpenAPIYAMLDumper(yaml.SafeDumper):
    """SafeDumper that writes multi-line strings as literal blocks.

    Every operation description in the document is a Python docstring, and
    pyyaml's default rendering for one is a quoted scalar with a blank line
    inserted at each embedded newline: correct YAML, unreadable diff. A
    reviewable diff is half the reason api/openapi.yaml is committed at all.
    """


def _represent_str(dumper: yaml.SafeDumper, data: str) -> Any:
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_OpenAPIYAMLDumper.add_representer(str, _represent_str)


def openapi_yaml_document() -> str:
    """The OpenAPI document as YAML.

    One serialization, shared by the route below and by
    scripts/export-openapi.py, so the file committed under api/ and the
    document a running container serves cannot differ by formatting alone —
    which would make the drift check in `mise run spec` fail for a reason
    that is not a contract change.
    """
    return yaml.dump(
        app.openapi(),
        Dumper=_OpenAPIYAMLDumper,
        sort_keys=False,
        allow_unicode=True,
        width=100,
    )


@app.get(
    "/openapi.yaml",
    operation_id="getOpenAPIDocumentYAML",
    summary="This service's OpenAPI document, as YAML",
    tags=["meta"],
    response_class=Response,
    responses={
        200: {
            "description": (
                "The same document FastAPI serves at /openapi.json, YAML-"
                "encoded. Byte-identical to the committed api/openapi.yaml "
                "for the image's own revision — CI fails when they differ."
            ),
            # An object, not a string: a YAML body is a serialized document,
            # and every consumer of this route — Schemathesis's own response
            # validation included — parses it before looking at it. Declaring
            # the three members an OpenAPI document must have turns this
            # response into a real assertion rather than "some bytes came
            # back": the contract run fails if the service ever serves
            # something that is not a document.
            "content": {
                "application/yaml": {
                    "schema": {
                        "type": "object",
                        "required": ["openapi", "info", "paths"],
                    }
                }
            },
        }
    },
)
def openapi_yaml() -> Response:
    return Response(content=openapi_yaml_document(), media_type="application/yaml")
