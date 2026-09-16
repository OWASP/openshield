"""Shared observability layer: structured logging, request IDs, Prometheus
metrics and optional Sentry error tracking.

This module is intentionally free of any project imports so that it can be
used from both the API (``api.app``) and the background worker
(``scanner.worker``) without creating an import cycle.

Metric cardinality note: no metric is ever labelled with a request ID,
scan ID, subscription ID, resource ID, error message or free-form user
input. Only low-cardinality, bounded values (HTTP method, view name,
status code, scan status, rule ID and provider name) are used as labels.
"""

import logging
import os
import re
import threading
import time
import uuid
from collections import OrderedDict, deque
from functools import wraps
from typing import Callable, Deque, Dict, Optional, Tuple

from flask import Flask, Response, current_app, g, jsonify, request
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# python-json-logger moved ``JsonFormatter`` from ``pythonjsonlogger.jsonlogger``
# to ``pythonjsonlogger.json`` in 3.1. Prefer the new path, fall back for <3.1.
try:  # pragma: no cover - trivial import shim
    from pythonjsonlogger.json import JsonFormatter
except ImportError:  # pragma: no cover
    from pythonjsonlogger.jsonlogger import JsonFormatter

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

# --------------------------------------------------------------------------- #
# Prometheus metrics                                                           #
# --------------------------------------------------------------------------- #
# Defined at module import so they are process-wide singletons. Re-importing
# this module (e.g. across repeated create_app() calls in tests) reuses the
# same collectors and never double-registers.

HTTP_REQUESTS_TOTAL = Counter(
    "openshield_http_requests_total",
    "Total HTTP requests processed by the API.",
    ["method", "endpoint", "status"],
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "openshield_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ["method", "endpoint"],
)
SCANS_TOTAL = Counter(
    "openshield_scans_total",
    "Total scans processed by the worker, by terminal status.",
    ["status"],
)
SCAN_DURATION_SECONDS = Histogram(
    "openshield_scan_duration_seconds",
    "Wall-clock duration of a single scan execution in seconds.",
)
PENDING_SCANS = Gauge(
    "openshield_pending_scans",
    "Number of scans currently waiting in the pending queue.",
)
RULE_ERRORS_TOTAL = Counter(
    "openshield_rule_errors_total",
    "Total number of times a scanner rule raised an exception.",
    ["rule_id"],
)
NVD_REQUEST_LATENCY_SECONDS = Histogram(
    "openshield_nvd_request_latency_seconds",
    "Latency of outbound NVD HTTP requests in seconds.",
)
LLM_PROVIDER_LATENCY_SECONDS = Histogram(
    "openshield_llm_provider_latency_seconds",
    "Latency of outbound LLM provider requests in seconds.",
    ["provider"],
)
DB_POOL_CONNECTIONS_IN_USE = Gauge(
    "openshield_db_pool_connections_in_use",
    "Connections currently checked out from the shared database pool.",
)
DB_POOL_CONNECTIONS_IDLE = Gauge(
    "openshield_db_pool_connections_idle",
    "Connections currently idle in the shared database pool.",
)
DB_POOL_CONNECTIONS_MAX = Gauge(
    "openshield_db_pool_connections_max",
    "Configured maximum size of the shared database pool.",
)

# Set by api.app at startup (see set_pool_stats_provider). Kept as a plain
# module-level callable rather than importing api.models.finding directly -
# this module stays free of project imports (see module docstring) so it
# can be reused from the worker without pulling in the API's DB layer.
_pool_stats_provider: Optional[Callable[[], Dict[str, int]]] = None


def set_pool_stats_provider(fn: Callable[[], Dict[str, int]]) -> None:
    """Register the callable /metrics uses to refresh the DB pool gauges.

    Called lazily on every scrape (see ``metrics()`` below) rather than on a
    timer, so the numbers are exact at scrape time instead of aging between
    scrapes.
    """
    global _pool_stats_provider
    _pool_stats_provider = fn


def _refresh_pool_metrics() -> None:
    if _pool_stats_provider is None:
        return
    try:
        stats = _pool_stats_provider()
        DB_POOL_CONNECTIONS_IN_USE.set(stats["in_use"])
        DB_POOL_CONNECTIONS_IDLE.set(stats["idle"])
        DB_POOL_CONNECTIONS_MAX.set(stats["max_connections"])
    except Exception:
        # A stats lookup must never take /metrics down - the rest of the
        # scrape (HTTP/scan counters etc.) is still valid without it.
        logger.exception("Failed to refresh database pool metrics")


# --------------------------------------------------------------------------- #
# Structured logging                                                           #
# --------------------------------------------------------------------------- #
def configure_logging(level: int = logging.INFO) -> None:
    """Configure the root logger to emit structured JSON to stderr.

    Safe to call multiple times — it replaces the root handlers each call so
    repeated invocations (API import, worker start, tests) do not stack
    duplicate handlers. Any ``extra={...}`` fields passed to log calls are
    included as top-level JSON keys.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)


# --------------------------------------------------------------------------- #
# Sentry (optional)                                                            #
# --------------------------------------------------------------------------- #
def init_sentry() -> bool:
    """Initialise Sentry error tracking only when ``SENTRY_DSN`` is set.

    Returns ``True`` when Sentry was initialised, ``False`` otherwise (DSN
    unset, or ``sentry-sdk`` not installed). Never raises.
    """
    dsn = os.environ.get("SENTRY_DSN")
    if not dsn:
        return False
    try:
        import sentry_sdk
    except ImportError:
        logger.warning("SENTRY_DSN is set but sentry-sdk is not installed; skipping.")
        return False

    try:
        sentry_sdk.init(
            dsn=dsn,
            environment=os.environ.get("OPENSHIELD_ENV", "development"),
            traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.0")),
        )
    except Exception as exc:
        # A malformed DSN must never take down the API or the worker.
        logger.warning("Failed to initialise Sentry: %s", exc)
        return False
    logger.info("Sentry error tracking initialised.")
    return True


# --------------------------------------------------------------------------- #
# Request IDs                                                                  #
# --------------------------------------------------------------------------- #
def get_request_id() -> str:
    """Return the request ID bound to the current request context.

    Falls back to a freshly generated UUID if the middleware has not run
    (e.g. outside a request), so callers always receive a usable value.
    """
    rid = getattr(g, "request_id", None)
    if not rid:
        rid = str(uuid.uuid4())
        g.request_id = rid
    return rid


# --------------------------------------------------------------------------- #
# Probe/scrape rate limiting                                                   #
# --------------------------------------------------------------------------- #
# /health, /ready, and /metrics are exempt from JWT auth by design (see
# api.app._ALWAYS_PUBLIC) so uptime checkers and Prometheus scrapers can
# reach them without a token. That also makes /ready and /metrics the one
# place an unauthenticated caller can trigger repeated backend work - a
# pooled database checkout for /ready - without ever presenting a token.
#
# api.rate_limit.rate_limit (used elsewhere in the API) is the wrong tool
# here: it does its own Postgres round trip per check, which would add
# database load to /ready - the exact endpoint whose job is to protect the
# database pool from overload - and risks checking out a second, separate
# pooled connection under its own `g.db` alongside the one /ready's handler
# already manages, only one of which the teardown handler would return.
#
# This limiter is pure in-memory and per-process instead. The connection
# pool it protects (api.models.finding._POOLS) is itself process-local under
# Gunicorn's multi-worker model, so a per-process budget is the matching
# granularity, not a weaker substitute for a shared one: it bounds exactly
# the pool a single worker process can exhaust. It is a defense-in-depth
# backstop, not a replacement for restricting these paths at whatever
# reverse proxy/CDN/WAF fronts the deployment - see the "Restricting
# probe/scrape endpoints at the edge" section of docs/deployment/render.md.
_PROBE_WINDOW_SECONDS = 10.0
# Prometheus scrapes on a fixed interval (typically 15-30s) from a small,
# stable set of scraper IPs, so this stays generous; it exists to blunt a
# single caller hammering the endpoint, not to constrain normal scraping.
_METRICS_MAX_REQUESTS_PER_WINDOW = 20
# Hard ceiling on distinct (address, path) keys tracked at once. Same-key
# cleanup alone isn't enough: a caller that continuously rotates its source
# address (or a spoofed forwarded address wherever the trusted-proxy
# boundary is misconfigured) creates a new one-shot dict entry per address,
# and a key that's never revisited is never pruned by the per-call cleanup
# below - making the tracking dict itself an unbounded memory sink. This
# caps it regardless of how many distinct addresses show up.
_PROBE_MAX_TRACKED_KEYS = 10_000
# A full scan over every tracked key on every single request would undercut
# the point of a cheap in-memory limiter, so the sweep below runs every Nth
# call instead of every call. This bounds how long a key whose owner never
# returns can survive to at most this many requests' worth of accumulation
# - the hard cap above is what actually bounds worst-case memory regardless
# of traffic shape or how the sweep is scheduled.
_PROBE_SWEEP_INTERVAL = 200
_probe_lock = threading.Lock()


class _ProbeEntry:
    """One tracked (address, path) key's rate-limit state.

    window_seconds is stored per entry, not taken from whichever request
    happens to trigger the periodic sweep: _probe_hits is one dict shared
    across every probe_rate_limit-decorated view, so a sweep triggered by
    /metrics's decorator (its own window_seconds closure) must not apply
    that window to keys tracked for /ready, or vice versa. Both endpoints
    currently default to the same 10s window, which is exactly why this
    was dormant rather than visibly broken - the first endpoint added with
    a different window would have hit premature resets or lingering stale
    entries for every other endpoint's keys.
    """

    __slots__ = ("hits", "window_seconds")

    def __init__(self, window_seconds: float) -> None:
        self.hits: Deque[float] = deque()
        self.window_seconds = window_seconds


# An OrderedDict, not a plain dict: every touch (a request actually within
# budget, or a sweep pruning it survives) moves a key to the end, so the
# front is always the least recently touched key - the correct,
# deterministic thing to evict first when the hard cap above is reached.
_probe_hits: "OrderedDict[Tuple[str, str], _ProbeEntry]" = OrderedDict()
_probe_call_count = 0


def _sweep_expired_probe_hits(now: float) -> None:
    """Remove every tracked key whose hits have all expired.

    Must be called with _probe_lock already held. This is the global
    cleanup pass: the per-call logic in probe_rate_limit only ever prunes
    the one key the current request touched, which does nothing for a
    key that's never hit again. Each entry's own window_seconds is used,
    not the sweep caller's - see _ProbeEntry.
    """
    for key in list(_probe_hits.keys()):
        entry = _probe_hits[key]
        cutoff = now - entry.window_seconds
        while entry.hits and entry.hits[0] < cutoff:
            entry.hits.popleft()
        if not entry.hits:
            del _probe_hits[key]


def probe_rate_limit(max_requests: int, window_seconds: float = _PROBE_WINDOW_SECONDS):
    """Limit a probe/scrape view to ``max_requests`` per ``window_seconds`` per client IP.

    The check runs before the wrapped view body, so a request rejected here
    never reaches the database work it would otherwise trigger. Disabled in
    testing mode, matching the convention in api.rate_limit.rate_limit.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if current_app.testing:
                return fn(*args, **kwargs)

            global _probe_call_count
            key = (request.remote_addr or "unknown", request.path)
            now = time.monotonic()
            with _probe_lock:
                _probe_call_count += 1
                if _probe_call_count % _PROBE_SWEEP_INTERVAL == 0:
                    _sweep_expired_probe_hits(now)

                entry = _probe_hits.get(key)
                if entry is not None:
                    cutoff = now - entry.window_seconds
                    while entry.hits and entry.hits[0] < cutoff:
                        entry.hits.popleft()
                    if not entry.hits:
                        del _probe_hits[key]
                        entry = None

                if entry is None:
                    if len(_probe_hits) >= _PROBE_MAX_TRACKED_KEYS:
                        # Deterministic eviction: drop the least recently
                        # touched key, not an arbitrary/insertion-order one.
                        _probe_hits.popitem(last=False)
                    entry = _ProbeEntry(window_seconds)
                    # OrderedDict places a newly-inserted key at the end,
                    # so a brand-new entry doesn't need an explicit
                    # move_to_end - it's already the most recent.
                    _probe_hits[key] = entry

                allowed = len(entry.hits) < max_requests
                if allowed:
                    entry.hits.append(now)
                    # Only a request that actually counted against the
                    # budget refreshes this key's position. A rejected
                    # request must not keep an over-budget key artificially
                    # warm - otherwise a caller that never lets its own
                    # budget recover (an attacker) stays permanently
                    # protected from eviction while quiet, legitimate
                    # keys drift toward the front and get evicted instead.
                    _probe_hits.move_to_end(key)

            if not allowed:
                return jsonify({"status": "rate_limited"}), 429, {"Retry-After": str(int(window_seconds))}

            return fn(*args, **kwargs)

        return wrapped

    return decorator


# --------------------------------------------------------------------------- #
# Flask wiring                                                                 #
# --------------------------------------------------------------------------- #
def init_app(app: Flask) -> None:
    """Register request-ID and Prometheus middleware and the /metrics route.

    Must be called before any other ``before_request`` handlers (such as JWT
    auth) so that ``g.request_id`` is available to them and to error handlers.
    """

    @app.before_request
    def _start_observability() -> None:
        supplied_request_id = request.headers.get(REQUEST_ID_HEADER, "")
        g.request_id = supplied_request_id if _REQUEST_ID_RE.fullmatch(supplied_request_id) else str(uuid.uuid4())
        g.request_start_time = time.perf_counter()

    @app.after_request
    def _record_observability(response: Response) -> Response:
        response.headers[REQUEST_ID_HEADER] = get_request_id()

        endpoint = request.endpoint or "unknown"
        method = request.method
        HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=endpoint, status=response.status_code).inc()
        start = getattr(g, "request_start_time", None)
        if start is not None:
            HTTP_REQUEST_DURATION_SECONDS.labels(method=method, endpoint=endpoint).observe(time.perf_counter() - start)
        return response

    @app.get("/metrics")
    @probe_rate_limit(_METRICS_MAX_REQUESTS_PER_WINDOW)
    def metrics() -> Response:
        _refresh_pool_metrics()
        return Response(generate_latest(), content_type=CONTENT_TYPE_LATEST)
