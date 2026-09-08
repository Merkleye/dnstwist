"""Unit tests for the dnstwist sidecar.

Every network call (DNS resolution) is mocked — this suite never touches
the network, matching app.py's own claim to be "trivially testable." The
coverage floor is 100% of statements (see mise.toml's `test` task and
pyproject.toml's coverage config), not branches: every line in app.py must
execute at least once across this file, which is why some tests exist only
to exercise one otherwise-unreached line (e.g. the ImportError branch in
_resolve) rather than to assert interesting behavior.
"""

from __future__ import annotations

import logging
import pathlib
import socket
import sys
from datetime import datetime

import pytest
import yaml
from fastapi import HTTPException
from fastapi.testclient import TestClient
from opentelemetry import trace

import app as app_module
from app import (
    DEFAULT_ALGORITHMS,
    DEFAULT_TLDS,
    EnrichRequest,
    GenerateRequest,
    Variant,
    _config_hash,
    _effective_tld,
    _filtered_variants,
    _generator_version,
    _normalize,
    _resolve,
    _run_fuzzer,
    app,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# --- _normalize --------------------------------------------------------


def test_normalize_empty_string() -> None:
    assert _normalize("") == ("", None)


def test_normalize_plain_ascii_is_unchanged() -> None:
    assert _normalize("example.com") == ("example.com", None)


def test_normalize_decodes_punycode_to_unicode() -> None:
    ascii_name, unicode_name = _normalize("xn--80ajb1au1a38g.com")
    assert ascii_name == "xn--80ajb1au1a38g.com"
    assert unicode_name == "ехамрӏе.com"


def test_normalize_undecodable_punycode_keeps_ascii_only() -> None:
    # Malformed punycode: decodes to A-label-or-nothing, never raises past
    # this function.
    assert _normalize("xn--zzzzzzzz.com") == ("xn--zzzzzzzz.com", None)


def test_normalize_encodes_unicode_to_punycode() -> None:
    ascii_name, unicode_name = _normalize("münchen.com")
    assert ascii_name == "xn--mnchen-3ya.com"
    assert unicode_name == "münchen.com"


def test_normalize_unencodable_unicode_returns_empty() -> None:
    # A label over 63 octets once IDNA-encoded cannot appear in a
    # certificate SAN, so this permutation is dropped entirely.
    assert _normalize("ü" * 64 + ".com") == ("", None)


# --- _effective_tld ------------------------------------------------------


def test_effective_tld_matches_original_suffix() -> None:
    assert _effective_tld("paypa1.com", "paypal.com", ["xyz"]) == "com"


def test_effective_tld_matches_tld_swap_candidate() -> None:
    assert _effective_tld("paypal.xyz", "paypal.com", ["xyz"]) == "xyz"


def test_effective_tld_handles_multi_label_suffix() -> None:
    assert _effective_tld("examp1e.co.uk", "example.co.uk", ["xyz"]) == "co.uk"


def test_effective_tld_prefers_longer_match() -> None:
    # "co.uk" and "uk" are both candidates; the fqdn ends in both, and the
    # longer one is the real suffix.
    assert _effective_tld("examp1e.co.uk", "example.co.uk", ["uk"]) == "co.uk"


def test_effective_tld_no_match_returns_empty() -> None:
    assert _effective_tld("totally-unrelated.net", "example.com", ["xyz"]) == ""


def test_effective_tld_original_domain_without_dot() -> None:
    # No "." in original_domain means nothing is added from it — only the
    # candidate_tlds set is checked.
    assert _effective_tld("example.xyz", "localhost", ["xyz"]) == "xyz"


# --- _resolve --------------------------------------------------------------


def test_resolve_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket, "gethostbyname_ex", lambda domain: (domain, [], ["1.2.3.4"])
    )

    class _Rdata:
        def __init__(self, value: str) -> None:
            self._value = value

        def __str__(self) -> str:
            return self._value

    def fake_resolve(domain: str, rtype: str, lifetime: float):
        if rtype == "MX":
            return [_Rdata("10 mail.example.com.")]
        return [_Rdata("ns1.example.com.")]

    import dns.resolver

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    a, mx, ns = _resolve("example.com")
    assert a == ["1.2.3.4"]
    assert mx == ["10 mail.example.com."]
    assert ns == ["ns1.example.com."]


def test_resolve_a_record_gaierror_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_gaierror(domain: str):
        raise socket.gaierror("not found")

    monkeypatch.setattr(socket, "gethostbyname_ex", raise_gaierror)

    import dns.resolver

    monkeypatch.setattr(
        dns.resolver, "resolve", lambda *a, **k: (_ for _ in ()).throw(Exception("no records"))
    )

    a, mx, ns = _resolve("nxdomain.invalid")
    assert a == []
    assert mx == []
    assert ns == []


def test_resolve_a_record_unicode_error_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_unicode_error(domain: str):
        raise UnicodeError("bad label")

    monkeypatch.setattr(socket, "gethostbyname_ex", raise_unicode_error)

    import dns.resolver

    monkeypatch.setattr(
        dns.resolver, "resolve", lambda *a, **k: (_ for _ in ()).throw(Exception("no records"))
    )

    a, mx, ns = _resolve("bad..label")
    assert a == []


def test_resolve_mx_ns_lookup_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "gethostbyname_ex", lambda domain: (domain, [], []))

    import dns.resolver

    def raise_any(*args, **kwargs):
        raise Exception("timeout")

    monkeypatch.setattr(dns.resolver, "resolve", raise_any)

    a, mx, ns = _resolve("example.com")
    assert mx == []
    assert ns == []


def test_resolve_without_dnspython_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Covers the `except ImportError: pass` branch: simulate dnspython not
    being importable at all, the way it would be if dnstwist were installed
    without its [full] extras.
    """
    monkeypatch.setattr(socket, "gethostbyname_ex", lambda domain: (domain, [], ["1.2.3.4"]))
    monkeypatch.setitem(sys.modules, "dns", None)
    monkeypatch.delitem(sys.modules, "dns.resolver", raising=False)

    a, mx, ns = _resolve("example.com")
    assert a == ["1.2.3.4"]
    assert mx == []
    assert ns == []


# --- _config_hash / _generator_version -------------------------------------


def test_generator_version_returns_a_string() -> None:
    assert isinstance(_generator_version(), str)


def test_config_hash_is_deterministic_regardless_of_input_order() -> None:
    req_a = GenerateRequest(domain="example.com", algorithms=["b", "a"], tlds=["net", "com"])
    req_b = GenerateRequest(domain="example.com", algorithms=["a", "b"], tlds=["com", "net"])
    assert _config_hash(req_a) == _config_hash(req_b)
    assert _config_hash(req_a).startswith("sha256:")


def test_config_hash_changes_with_domain() -> None:
    req_a = GenerateRequest(domain="example.com")
    req_b = GenerateRequest(domain="example.org")
    assert _config_hash(req_a) != _config_hash(req_b)


# --- _run_fuzzer -------------------------------------------------------


def test_run_fuzzer_rejects_empty_domain() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _run_fuzzer(GenerateRequest(domain=""))
    assert exc_info.value.status_code == 400


def test_run_fuzzer_rejects_non_positive_max_variants() -> None:
    # Assigned after construction rather than passed in: `max_variants` is
    # declared `gt=0`, so pydantic rejects a zero before the model exists.
    # The handler check this covers is what still stands between a direct
    # caller (this test, a future in-process one) and the same mistake.
    req = GenerateRequest(domain="example.com")
    req.max_variants = 0
    with pytest.raises(HTTPException) as exc_info:
        _run_fuzzer(req)
    assert exc_info.value.status_code == 400


def test_run_fuzzer_rejects_overlong_domain() -> None:
    # Same shape as above: the schema's maxLength answers this with a 422
    # over HTTP, and this is the handler-side guard behind it. It exists
    # because the cost is real — permutation is quadratic in the length of
    # the name, and a long enough one exhausts the container's memory.
    req = GenerateRequest(domain="example.com")
    req.domain = "a" * (app_module.MAX_DOMAIN_LENGTH + 1) + ".com"
    with pytest.raises(HTTPException) as exc_info:
        _run_fuzzer(req)
    assert exc_info.value.status_code == 400
    assert "at most" in exc_info.value.detail


def test_run_fuzzer_wraps_dnstwist_exceptions() -> None:
    # dnstwist's Fuzzer treats this input as producing an empty domain
    # internally and raises a bare exception, not an HTTPException.
    with pytest.raises(HTTPException) as exc_info:
        _run_fuzzer(GenerateRequest(domain="not a domain!!"))
    assert exc_info.value.status_code == 400
    assert "dnstwist:" in exc_info.value.detail


def test_run_fuzzer_repropagates_httpexception_from_fuzzer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Covers the `except HTTPException: raise` line: force something inside
    the try block to raise HTTPException directly, as if a future dnstwist
    version did so itself.
    """

    class _ExplodingFuzzer:
        def __init__(self, *args, **kwargs) -> None:
            raise HTTPException(status_code=400, detail="boom")

    monkeypatch.setattr(app_module.dnstwist, "Fuzzer", _ExplodingFuzzer)

    with pytest.raises(HTTPException) as exc_info:
        _run_fuzzer(GenerateRequest(domain="example.com"))
    assert exc_info.value.detail == "boom"


def test_run_fuzzer_success_returns_permutations() -> None:
    permutations = _run_fuzzer(GenerateRequest(domain="example.com", tlds=["com"]))
    assert len(permutations) > 100
    assert all("fuzzer" in p and "domain" in p for p in permutations)


# --- _filtered_variants --------------------------------------------------


def _perm(fuzzer: str, domain: str) -> dict[str, str]:
    return {"fuzzer": fuzzer, "domain": domain}


def test_filtered_variants_skips_original_and_unwanted_algorithms() -> None:
    req = GenerateRequest(domain="example.com", algorithms=["cyrillic"])
    permutations = [
        _perm("*original", "example.com"),
        _perm("addition", "examplea.com"),
        _perm("cyrillic", "xn--example-cyr.com"),
    ]
    results = list(_filtered_variants(req, permutations))
    assert [v.fqdn for v, _truncated in results] == ["xn--example-cyr.com"]


def test_filtered_variants_skips_empty_domain_entries() -> None:
    req = GenerateRequest(domain="example.com", algorithms=["addition"])
    permutations = [{"fuzzer": "addition", "domain": ""}]
    assert list(_filtered_variants(req, permutations)) == []


def test_filtered_variants_dedupes_by_ascii_name() -> None:
    req = GenerateRequest(domain="example.com", algorithms=["addition"])
    permutations = [_perm("addition", "examplea.com"), _perm("addition", "examplea.com")]
    results = list(_filtered_variants(req, permutations))
    assert len(results) == 1


def test_filtered_variants_drops_unnormalizable_names() -> None:
    req = GenerateRequest(domain="example.com", algorithms=["addition"])
    permutations = [_perm("addition", "ü" * 64 + ".com")]
    assert list(_filtered_variants(req, permutations)) == []


def test_filtered_variants_truncates_at_max_variants() -> None:
    req = GenerateRequest(domain="example.com", algorithms=["addition"], max_variants=1)
    permutations = [
        _perm("addition", "one.com"),
        _perm("addition", "two.com"),
        _perm("addition", "three.com"),
    ]
    results = list(_filtered_variants(req, permutations))
    assert [truncated for _v, truncated in results] == [False, True]
    # The generator returns immediately after the truncation marker.
    assert len(results) == 2


# --- /generate ---------------------------------------------------------


def test_generate_endpoint_returns_variants(client: TestClient) -> None:
    r = client.post("/generate", json={"domain": "example.com", "tlds": ["com"]})
    assert r.status_code == 200
    body = r.json()
    assert body["generator"] == "dnstwist"
    assert body["truncated"] is False
    assert len(body["variants"]) > 100
    assert all("registered" not in v and "mx" not in v for v in body["variants"])


def test_generate_endpoint_reports_truncation(client: TestClient) -> None:
    r = client.post(
        "/generate",
        json={"domain": "example.com", "algorithms": DEFAULT_ALGORITHMS, "tlds": ["com"], "max_variants": 1},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["truncated"] is True
    assert len(body["variants"]) == 1


def test_generate_endpoint_rejects_empty_domain(client: TestClient) -> None:
    r = client.post("/generate", json={"domain": ""})
    assert r.status_code == 400


def test_generate_stream_endpoint_no_longer_exists(client: TestClient) -> None:
    # /generate/stream was removed along with the resolution pass that made
    # a /generate call slow enough to need a progress stream.
    r = client.post("/generate/stream", json={"domain": "example.com"})
    assert r.status_code == 404


def test_generate_uses_default_algorithms_and_tlds() -> None:
    req = GenerateRequest(domain="example.com")
    assert req.algorithms == DEFAULT_ALGORITHMS
    assert req.tlds == DEFAULT_TLDS


# --- /enrich -------------------------------------------------------------


def test_enrich_endpoint_rejects_empty_domain(client: TestClient) -> None:
    r = client.post("/enrich", json={"domain": ""})
    assert r.status_code == 400


def test_enrich_endpoint_resolves_domain(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "_resolve", lambda domain: (["1.2.3.4"], ["mail.example.com"], ["ns1.example.com"]))
    r = client.post("/enrich", json={"domain": "example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["resolves"] is True
    assert body["a"] == ["1.2.3.4"]
    assert body["mx"] == ["mail.example.com"]
    assert body["ns"] == ["ns1.example.com"]
    assert body["registered_at"] is None


def test_enrich_endpoint_reports_unresolved_domain(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "_resolve", lambda domain: ([], [], []))
    r = client.post("/enrich", json={"domain": "nxdomain.invalid"})
    assert r.status_code == 200
    assert r.json()["resolves"] is False


def test_enrich_request_model_accepts_domain() -> None:
    assert EnrichRequest(domain="example.com").domain == "example.com"


# --- /health ---------------------------------------------------------------


def test_health_endpoint(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["generator"] == "dnstwist"
    # Not just "present": merkleye's perf suite and the Containerfile's
    # HEALTHCHECK both read this response, and the document now declares
    # checked_at as a date-time.
    assert datetime.fromisoformat(body["checked_at"]).tzinfo is not None


# --- the published OpenAPI document ----------------------------------------


def test_openapi_json_is_served(client: TestClient) -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert r.json()["info"]["version"] == app_module.SERVICE_VERSION


def test_openapi_yaml_endpoint_serves_a_parseable_document(client: TestClient) -> None:
    r = client.get("/openapi.yaml")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/yaml")
    document = yaml.safe_load(r.text)
    assert document["openapi"].startswith("3.1")
    assert set(document["paths"]) == {"/generate", "/enrich", "/health", "/openapi.yaml"}


def test_openapi_yaml_matches_the_committed_spec(client: TestClient) -> None:
    """The drift check, as a unit test.

    `mise run spec` runs the same comparison in CI via
    scripts/export-openapi.py --check; having it here too means a route or
    model change that forgets to regenerate api/openapi.yaml fails in the
    suite a contributor already runs, rather than one job later.
    """
    committed = pathlib.Path(__file__).resolve().parent.parent / "api" / "openapi.yaml"
    assert client.get("/openapi.yaml").text == committed.read_text(), (
        "api/openapi.yaml is stale — run `mise run spec:export` and commit the result"
    )


def test_openapi_document_declares_operation_ids() -> None:
    """Every operation is named explicitly.

    FastAPI's fallback operationId is derived from the function name and the
    path (`generate_variants_generate_post`), so it changes when either is
    renamed — and it is what a client generator turns into a method name.
    scripts/validate-spec.py enforces this over the committed document; this
    is the same rule at the source.
    """
    operations = [
        operation
        for item in app.openapi()["paths"].values()
        for operation in item.values()
    ]
    ids = [operation["operationId"] for operation in operations]
    assert ids == sorted(set(ids), key=ids.index), "duplicate operationId"
    assert all(not op_id.endswith("_post") and not op_id.endswith("_get") for op_id in ids)


def test_openapi_yaml_document_renders_descriptions_as_literal_blocks() -> None:
    # The dumper's whole purpose: a docstring must not come back as a quoted
    # scalar with a blank line per newline, which is what pyyaml does by
    # default and what makes the committed document unreadable in review.
    assert "description: |-" in app_module.openapi_yaml_document()


# --- Variant model -----------------------------------------------------


def test_variant_defaults() -> None:
    v = Variant(fqdn="example.com", algorithm="addition")
    assert v.unicode is None
    assert v.tld == ""


# --- logging: _JSONFormatter and _RequestLoggingMiddleware ------------------


def test_json_formatter_without_active_span() -> None:
    formatter = app_module.log.handlers[0].formatter
    record = logging.LogRecord(
        name="merkleye.dnstwist", level=logging.INFO, pathname=__file__,
        lineno=1, msg="hello", args=(), exc_info=None,
    )
    import json as _json

    payload = _json.loads(formatter.format(record))
    assert payload["msg"] == "hello"
    assert payload["level"] == "INFO"
    assert "trace_id" not in payload


def test_json_formatter_with_active_span_and_extra_fields() -> None:
    formatter = app_module.log.handlers[0].formatter
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("test-span"):
        record = logging.LogRecord(
            name="merkleye.dnstwist", level=logging.DEBUG, pathname=__file__,
            lineno=1, msg="http", args=(), exc_info=None,
        )
        record.extra_fields = {"method": "GET"}
        import json as _json

        payload = _json.loads(formatter.format(record))
    assert payload["method"] == "GET"
    # A real span was active, so both identifiers must be present and be
    # well-formed hex strings of the expected width.
    assert len(payload["trace_id"]) == 32
    assert len(payload["span_id"]) == 16


def test_request_logging_middleware_runs_on_every_request(client: TestClient) -> None:
    # The middleware's log.debug call always executes regardless of the
    # configured LOG_LEVEL; this just confirms the request completes
    # normally with the middleware installed.
    r = client.get("/health")
    assert r.status_code == 200


def test_configure_logging_reads_log_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "warning")
    logger = app_module._configure_logging()
    assert logger.level == logging.WARNING


def test_configure_logging_defaults_to_info_for_unknown_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOG_LEVEL", "nonsense")
    logger = app_module._configure_logging()
    assert logger.level == logging.INFO


# --- module-level OTEL setup (import-time) ----------------------------------


def test_otel_sdk_disabled_flag_reflects_environment() -> None:
    # The module under test was imported with OTEL_SDK_DISABLED unset (the
    # default CI/test environment), which is what exercises the "enabled"
    # branch's tracer/exporter/instrumentation setup at import time -- the
    # same lines this test asserts ran.
    assert app_module._otel_sdk_disabled is False
    assert app_module.trace.get_tracer_provider() is not None


def test_otel_sdk_disabled_true_skips_tracer_setup() -> None:
    """Covers the disabled branch by importing a fresh copy of the module in
    a subprocess -- module-level OTEL setup only runs once per process, and
    doing this in-process would mutate global SDK state every other test in
    this file depends on.
    """
    import subprocess

    result = subprocess.run(
        [sys.executable, "-c", "import os; os.environ['OTEL_SDK_DISABLED'] = 'true'; import app; assert app._otel_sdk_disabled is True; print('ok')"],
        cwd=".",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout
