"""Scanner metrics shared with the hosted API, without importing Flask."""

from prometheus_client import Counter, Histogram

RULE_ERRORS_TOTAL = Counter(
    "openshield_rule_errors_total",
    "Total number of times a scanner rule raised an exception.",
    ["rule_id"],
)
NVD_REQUEST_LATENCY_SECONDS = Histogram(
    "openshield_nvd_request_latency_seconds",
    "Latency of outbound NVD HTTP requests in seconds.",
)
