"""Tests for issue #296's remaining scope: in-memory rate limiting for the
/ready and /metrics probe/scrape endpoints, and database pool utilization
telemetry.

The connection-leak fix itself (returning the pool connection via `g.db` +
the teardown handler) and its regression coverage are #306 - see
test_observability.py::test_ready_returns_every_real_connection_to_the_pool.
This file only covers what was still open after that: bounding how much
pooled-connection work an unauthenticated caller can trigger per window, and
exposing pool in-use/idle/max counts without leaking anything about the
underlying database (DSN, host, credentials).
"""

import threading
from unittest.mock import MagicMock

import flask
import pytest

import api.models.finding as finding_module
import api.observability as observability
from api.app import _READY_MAX_REQUESTS_PER_WINDOW, create_app
from api.models.finding import get_pool_stats
from api.observability import probe_rate_limit


@pytest.fixture(autouse=True)
def _clear_probe_rate_limit_state():
    """Isolate each test's rate-limit budget - the tracked-hits dict is a
    module-level global shared across every app instance in this process."""
    observability._probe_hits.clear()
    yield
    observability._probe_hits.clear()


def _build_ready_app(db_mock, monkeypatch):
    """Build a real app with /ready's rate limiter active (TESTING left
    False - probe_rate_limit is a no-op under app.testing, and these tests
    exist specifically to exercise it)."""
    monkeypatch.setattr("api.app.DatabaseManager", MagicMock(return_value=db_mock))
    return create_app()


# --------------------------------------------------------------------------- #
# probe_rate_limit() - decorator behavior in isolation                        #
# --------------------------------------------------------------------------- #


def _tiny_app(max_requests=2, window_seconds=5.0):
    app = flask.Flask(__name__)

    @app.get("/probe")
    @probe_rate_limit(max_requests, window_seconds=window_seconds)
    def probe():
        return {"ok": True}

    return app


def test_probe_rate_limit_allows_up_to_the_budget_then_429s():
    client = _tiny_app(max_requests=2).test_client()

    assert client.get("/probe").status_code == 200
    assert client.get("/probe").status_code == 200
    resp = client.get("/probe")

    assert resp.status_code == 429


def test_probe_rate_limit_budget_resets_after_the_window(monkeypatch):
    client = _tiny_app(max_requests=2, window_seconds=5.0).test_client()
    fake_now = [1000.0]
    monkeypatch.setattr(observability.time, "monotonic", lambda: fake_now[0])

    assert client.get("/probe").status_code == 200
    assert client.get("/probe").status_code == 200
    assert client.get("/probe").status_code == 429

    fake_now[0] += 5.1  # past the window
    assert client.get("/probe").status_code == 200


def test_probe_rate_limit_budget_is_independent_per_source_ip():
    client = _tiny_app(max_requests=2).test_client()

    assert client.get("/probe", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}).status_code == 200
    assert client.get("/probe", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}).status_code == 200
    assert client.get("/probe", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}).status_code == 429

    # A different source IP has its own, untouched budget.
    assert client.get("/probe", environ_overrides={"REMOTE_ADDR": "198.51.100.9"}).status_code == 200


def test_probe_rate_limit_is_a_noop_under_testing_mode():
    app = _tiny_app(max_requests=2)
    app.config["TESTING"] = True
    client = app.test_client()

    for _ in range(5):
        assert client.get("/probe").status_code == 200


def test_probe_rate_limit_prunes_expired_keys_instead_of_growing_forever(monkeypatch):
    """A key with no hits inside the window must not linger in the tracking
    dict - otherwise every distinct one-off caller would accumulate state
    forever, which is its own memory-growth DoS vector."""
    client = _tiny_app(max_requests=1, window_seconds=1.0).test_client()
    fake_now = [1000.0]
    monkeypatch.setattr(observability.time, "monotonic", lambda: fake_now[0])

    assert client.get("/probe", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}).status_code == 200
    assert ("203.0.113.5", "/probe") in observability._probe_hits

    fake_now[0] += 1.1
    assert client.get("/probe", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}).status_code == 200
    # The stale hit expired and only the new one remains tracked - the key
    # was pruned and recreated, not left growing with dead timestamps.
    assert len(observability._probe_hits[("203.0.113.5", "/probe")].hits) == 1


def test_probe_rate_limit_sweeps_stale_one_shot_addresses_globally(monkeypatch):
    """A caller that rotates its source address to defeat same-key cleanup
    (issue: each address is a one-shot key that's never revisited, so it's
    never pruned) must still be bounded - the periodic global sweep has to
    catch keys nobody ever hits a second time, not just the one the current
    request touched."""
    monkeypatch.setattr(observability, "_PROBE_SWEEP_INTERVAL", 5)
    client = _tiny_app(max_requests=1, window_seconds=1.0).test_client()
    fake_now = [1000.0]
    monkeypatch.setattr(observability.time, "monotonic", lambda: fake_now[0])

    # 20 distinct one-shot source addresses, each hit exactly once - none of
    # them is ever revisited, so per-key cleanup alone would never touch them.
    for i in range(20):
        addr = f"203.0.113.{i}"
        assert client.get("/probe", environ_overrides={"REMOTE_ADDR": addr}).status_code == 200
    assert len(observability._probe_hits) == 20

    # Advance well past the window, then trigger enough calls (from yet more
    # different addresses) for the sweep interval to fire.
    fake_now[0] += 5.0
    for i in range(20, 25):
        client.get("/probe", environ_overrides={"REMOTE_ADDR": f"203.0.113.{i}"})

    # Every one of the original 20 stale one-shot keys is gone. Only recent
    # activity (some subset of the newest addresses) remains tracked.
    for i in range(20):
        assert ("203.0.113.{}".format(i), "/probe") not in observability._probe_hits
    assert len(observability._probe_hits) <= 5


def test_probe_rate_limit_enforces_a_hard_cap_with_lru_eviction(monkeypatch):
    """Even within the window (nothing has expired yet), the number of
    tracked keys must never exceed the hard cap - bounds worst-case memory
    against a burst of many distinct addresses regardless of timing."""
    monkeypatch.setattr(observability, "_PROBE_MAX_TRACKED_KEYS", 3)
    monkeypatch.setattr(observability, "_PROBE_SWEEP_INTERVAL", 1_000_000)  # don't let the sweep interfere
    client = _tiny_app(max_requests=5, window_seconds=100.0).test_client()

    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})
    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.2"})
    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.3"})
    assert list(observability._probe_hits.keys()) == [
        ("10.0.0.1", "/probe"),
        ("10.0.0.2", "/probe"),
        ("10.0.0.3", "/probe"),
    ]

    # A 4th distinct address at the cap evicts the least-recently-touched
    # key (10.0.0.1, never touched again) rather than growing past the cap.
    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.4"})
    assert len(observability._probe_hits) == 3
    assert ("10.0.0.1", "/probe") not in observability._probe_hits
    assert ("10.0.0.4", "/probe") in observability._probe_hits


def test_probe_rate_limit_touching_a_key_protects_it_from_eviction(monkeypatch):
    """Re-hitting an existing key must move it to the back of the eviction
    order - an active caller must not be evicted just because other callers
    showed up afterward."""
    monkeypatch.setattr(observability, "_PROBE_MAX_TRACKED_KEYS", 2)
    monkeypatch.setattr(observability, "_PROBE_SWEEP_INTERVAL", 1_000_000)
    client = _tiny_app(max_requests=5, window_seconds=100.0).test_client()

    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})
    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.2"})
    # Touch 10.0.0.1 again - it's now the most recently active, not the
    # least, even though it was inserted first.
    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})

    # A 3rd distinct address should evict 10.0.0.2 (untouched since its
    # first hit), not 10.0.0.1 (touched most recently).
    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.3"})
    assert ("10.0.0.1", "/probe") in observability._probe_hits
    assert ("10.0.0.2", "/probe") not in observability._probe_hits
    assert ("10.0.0.3", "/probe") in observability._probe_hits


def test_probe_rate_limit_rejected_requests_do_not_refresh_eviction_order(monkeypatch):
    """A caller already over budget (rejected with 429) must not get its key
    moved to the back of the eviction order just by hammering the endpoint -
    otherwise an attacker who never lets their own budget recover stays
    permanently protected from eviction, while quiet legitimate keys drift
    toward the front and get evicted in its place. Only a request that
    actually counts against the budget may refresh a key's position."""
    monkeypatch.setattr(observability, "_PROBE_MAX_TRACKED_KEYS", 2)
    monkeypatch.setattr(observability, "_PROBE_SWEEP_INTERVAL", 1_000_000)
    client = _tiny_app(max_requests=1, window_seconds=100.0).test_client()

    # 10.0.0.1 spends its one-request budget, then keeps hammering - every
    # further call is rejected (429), not counted toward the budget again.
    assert client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code == 200
    for _ in range(5):
        assert client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code == 429

    # A quiet second address takes the other slot at the cap.
    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.2"})

    # A 3rd distinct address arrives. If the repeated 429s had kept
    # 10.0.0.1 "warm", 10.0.0.2 (touched once, then quiet) would be the
    # one evicted instead - exactly backwards from what should happen.
    client.get("/probe", environ_overrides={"REMOTE_ADDR": "10.0.0.3"})
    assert ("10.0.0.1", "/probe") not in observability._probe_hits
    assert ("10.0.0.2", "/probe") in observability._probe_hits
    assert ("10.0.0.3", "/probe") in observability._probe_hits


def test_probe_rate_limit_sweep_uses_each_keys_own_window_not_the_callers(monkeypatch):
    """_probe_hits is one dict shared by every probe_rate_limit-decorated
    endpoint. A sweep triggered by one endpoint's request must apply each
    tracked key's own window_seconds, not the window of whichever endpoint
    happened to trigger the sweep - otherwise a short-window endpoint's
    sweep could prematurely wipe a long-window endpoint's still-valid
    entries, or a long-window endpoint's sweep could leave a short-window
    endpoint's genuinely-expired entries lingering."""
    monkeypatch.setattr(observability, "_PROBE_SWEEP_INTERVAL", 1)
    fake_now = [1000.0]
    monkeypatch.setattr(observability.time, "monotonic", lambda: fake_now[0])

    app = flask.Flask(__name__)

    @app.get("/short")
    @probe_rate_limit(5, window_seconds=1.0)
    def short_window():
        return {"ok": True}

    @app.get("/long")
    @probe_rate_limit(5, window_seconds=1000.0)
    def long_window():
        return {"ok": True}

    client = app.test_client()

    # Seed one key per endpoint.
    client.get("/short", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})
    client.get("/long", environ_overrides={"REMOTE_ADDR": "10.0.0.2"})
    assert ("10.0.0.1", "/short") in observability._probe_hits
    assert ("10.0.0.2", "/long") in observability._probe_hits

    # Advance past the short window but nowhere near the long one, then
    # trigger a sweep via a request to the *long*-window endpoint. A sweep
    # that used the triggering request's own window (1000s) would wrongly
    # treat /short's entry as unexpired; using each entry's own window
    # correctly expires it while leaving /long's entry alone.
    fake_now[0] += 2.0
    client.get("/long", environ_overrides={"REMOTE_ADDR": "10.0.0.3"})  # sweep interval is 1, fires every call

    assert ("10.0.0.1", "/short") not in observability._probe_hits
    assert ("10.0.0.2", "/long") in observability._probe_hits


def test_probe_rate_limit_429_includes_retry_after_header():
    client = _tiny_app(max_requests=1, window_seconds=7.0).test_client()

    client.get("/probe")
    resp = client.get("/probe")

    assert resp.status_code == 429
    assert resp.headers.get("Retry-After") == "7"


# --------------------------------------------------------------------------- #
# /ready - rate limiting wired into the real route                            #
# --------------------------------------------------------------------------- #


def test_ready_rate_limits_a_single_source_after_the_window_budget(monkeypatch):
    healthy_db = MagicMock()
    healthy_db.ping.return_value = True
    app = _build_ready_app(healthy_db, monkeypatch)
    client = app.test_client()

    for _ in range(_READY_MAX_REQUESTS_PER_WINDOW):
        assert client.get("/ready", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}).status_code == 200

    limited = client.get("/ready", environ_overrides={"REMOTE_ADDR": "203.0.113.5"})
    assert limited.status_code == 429
    # A rejected-before-checkout request never touches the database at all.
    assert healthy_db.ping.call_count == _READY_MAX_REQUESTS_PER_WINDOW


def test_ready_rate_limit_does_not_affect_other_source_ips(monkeypatch):
    healthy_db = MagicMock()
    healthy_db.ping.return_value = True
    app = _build_ready_app(healthy_db, monkeypatch)
    client = app.test_client()

    for _ in range(_READY_MAX_REQUESTS_PER_WINDOW):
        client.get("/ready", environ_overrides={"REMOTE_ADDR": "203.0.113.5"})
    assert client.get("/ready", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}).status_code == 429

    fresh_source = client.get("/ready", environ_overrides={"REMOTE_ADDR": "198.51.100.9"})
    assert fresh_source.status_code == 200


# --------------------------------------------------------------------------- #
# get_pool_stats()                                                             #
# --------------------------------------------------------------------------- #


def test_pool_stats_report_zero_before_any_connection_is_made():
    stats = get_pool_stats("postgresql://unused-test-dsn/db")

    assert stats == {
        "max_connections": finding_module._POOL_MAX_CONN,
        "in_use": 0,
        "idle": 0,
        "utilization_percent": 0.0,
    }


def test_pool_stats_reflect_checked_out_and_idle_connections(monkeypatch):
    dsn = "postgresql://stats-test-dsn/db"
    monkeypatch.setattr(finding_module, "_POOL_MAX_CONN", 4)

    fake_pool = MagicMock()
    fake_pool.maxconn = 4
    fake_pool._used = {1: object(), 2: object()}
    fake_pool._pool = [object()]
    fake_pool._lock = threading.Lock()

    with finding_module._POOLS_LOCK:
        finding_module._POOLS[dsn] = fake_pool
    try:
        stats = get_pool_stats(dsn)
    finally:
        with finding_module._POOLS_LOCK:
            finding_module._POOLS.pop(dsn, None)

    assert stats == {"max_connections": 4, "in_use": 2, "idle": 1, "utilization_percent": 50.0}


def test_pool_stats_utilization_percent_handles_a_zero_size_pool():
    """A pool that hasn't been created yet reports the configured ceiling
    with zero utilization, never a division by zero."""
    dsn = "postgresql://never-connected-test-dsn/db"
    stats = get_pool_stats(dsn)

    assert stats["utilization_percent"] == 0.0


def test_pool_stats_never_reveal_the_dsn_host_or_credentials():
    dsn = "postgresql://produser:s3cr3t-password@internal-db-host.example:5432/openshield"
    stats = get_pool_stats(dsn)

    serialized = repr(stats)
    assert "s3cr3t-password" not in serialized
    assert "internal-db-host" not in serialized
    assert "produser" not in serialized
    assert set(stats.keys()) == {"max_connections", "in_use", "idle", "utilization_percent"}


# --------------------------------------------------------------------------- #
# /metrics - pool gauges reflect get_pool_stats() at scrape time              #
# --------------------------------------------------------------------------- #


def test_metrics_endpoint_reports_pool_utilization_gauges(monkeypatch):
    dsn = "postgresql://metrics-test-dsn/db"
    monkeypatch.setenv("DATABASE_URL", dsn)
    monkeypatch.setattr(finding_module, "_POOL_MAX_CONN", 4)

    fake_pool = MagicMock()
    fake_pool.maxconn = 4
    fake_pool._used = {1: object(), 2: object(), 3: object()}
    fake_pool._pool = [object()]
    fake_pool._lock = threading.Lock()

    with finding_module._POOLS_LOCK:
        finding_module._POOLS[dsn] = fake_pool
    try:
        app = create_app()
        app.config["TESTING"] = True
        resp = app.test_client().get("/metrics")
        body = resp.get_data(as_text=True)
    finally:
        with finding_module._POOLS_LOCK:
            finding_module._POOLS.pop(dsn, None)

    assert resp.status_code == 200
    assert "openshield_db_pool_connections_in_use 3.0" in body
    assert "openshield_db_pool_connections_idle 1.0" in body
    assert "openshield_db_pool_connections_max 4.0" in body
    # The DSN itself must never appear in a public scrape endpoint's body.
    assert dsn not in body


def test_metrics_endpoint_survives_a_pool_stats_failure(monkeypatch):
    """A broken stats provider must not take the whole /metrics scrape down -
    the HTTP/scan counters are still valid without the pool gauges."""

    def _boom():
        raise RuntimeError("stats provider exploded")

    monkeypatch.setattr(observability, "_pool_stats_provider", _boom)
    app = create_app()
    app.config["TESTING"] = True

    resp = app.test_client().get("/metrics")

    assert resp.status_code == 200
    assert "openshield_scan_duration_seconds" in resp.get_data(as_text=True)
