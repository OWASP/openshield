import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path
import requests

from api.validation import ValidationError, bounded_string, uuid_string
from openshield.severity import SeverityContractError, normalize_severity, severity_rank

WORKSPACE_ID = os.environ.get("SENTINEL_WORKSPACE_ID", "")
SHARED_KEY = os.environ.get("SENTINEL_SHARED_KEY", "")
LOG_TYPE = os.environ.get("SENTINEL_LOG_TYPE", "OpenShieldFindings")

_LOG_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,99}$")
_MAX_INPUT_BYTES = 10 * 1024 * 1024
_MAX_RECORDS = 1000
_MAX_FIELD_LENGTH = 8192


def _safe_text(value, field, *, maximum=_MAX_FIELD_LENGTH):
    if value in (None, ""):
        return ""
    return bounded_string(value, field, maximum=maximum)


def validate_config():
    uuid_string(WORKSPACE_ID, "SENTINEL_WORKSPACE_ID")
    bounded_string(SHARED_KEY, "SENTINEL_SHARED_KEY", maximum=16384)
    bounded_string(LOG_TYPE, "SENTINEL_LOG_TYPE", maximum=100, pattern=_LOG_TYPE_RE)
    try:
        base64.b64decode(SHARED_KEY, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValidationError("SENTINEL_SHARED_KEY must be valid base64") from exc


def load_findings(path_value):
    path = Path(path_value).expanduser().resolve()
    if path.suffix.lower() != ".json" or not path.is_file():
        raise ValidationError("input path must be an existing JSON file")
    if path.stat().st_size > _MAX_INPUT_BYTES:
        raise ValidationError(f"input file must be at most {_MAX_INPUT_BYTES} bytes")
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError("input file must contain valid UTF-8 JSON") from exc
    findings = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else None
    if not isinstance(findings, list):
        raise ValidationError("input JSON must be a findings list or contain a findings list")
    if len(findings) > _MAX_RECORDS:
        raise ValidationError(f"input must contain at most {_MAX_RECORDS} findings")
    return findings


def build_signature(date, content_length):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    decoded_key = base64.b64decode(SHARED_KEY)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {WORKSPACE_ID}:{encoded_hash}"


def normalise(raw, scan_id):
    if not isinstance(raw, dict):
        raise ValidationError("each Sentinel finding must be an object")
    scan_id = bounded_string(scan_id, "scan_id", maximum=128, pattern=re.compile(r"^[A-Za-z0-9._:-]+$"))
    if raw.get("severity") in (None, ""):
        raise ValidationError("severity is required for every Sentinel finding")
    raw_severity = _safe_text(raw["severity"], "severity", maximum=16)
    try:
        sev = normalize_severity(raw_severity)
    except SeverityContractError as exc:
        raise ValidationError("severity is outside the OpenShield severity contract") from exc
    compliance = raw.get("compliance", {})
    if not isinstance(compliance, dict):
        raise ValidationError("compliance must be an object")
    return {
        "ScanId": scan_id,
        "FindingId": _safe_text("" if raw.get("id") is None else str(raw.get("id", "")), "id", maximum=128),
        "TimeGenerated": _safe_text(
            raw.get("detected_at", datetime.datetime.now(datetime.UTC).isoformat()), "detected_at", maximum=64
        ),
        "ResourceId": _safe_text(raw.get("resource_id", ""), "resource_id"),
        "ResourceType": _safe_text(raw.get("resource_type", ""), "resource_type", maximum=256),
        "ResourceName": _safe_text(raw.get("resource_name", ""), "resource_name", maximum=512),
        "SubscriptionId": _safe_text(raw.get("subscription_id", ""), "subscription_id", maximum=128),
        "ResourceGroup": _safe_text(raw.get("resource_group", ""), "resource_group", maximum=256),
        "Region": _safe_text(raw.get("region", ""), "region", maximum=128),
        "RuleId": _safe_text(raw.get("rule_id", ""), "rule_id", maximum=64),
        "RuleName": _safe_text(raw.get("rule_name", ""), "rule_name", maximum=512),
        "Severity": sev.capitalize(),
        "SeverityScore": severity_rank(sev),
        "Description": _safe_text(raw.get("description", ""), "description"),
        "Remediation": _safe_text(raw.get("remediation", ""), "remediation"),
        "CisControl": _safe_text(compliance.get("cis", ""), "compliance.cis", maximum=128),
        "NistControl": _safe_text(compliance.get("nist", ""), "compliance.nist", maximum=128),
        "Source": "OpenShield",
        "ToolVersion": _safe_text(raw.get("tool_version", "0.1.0"), "tool_version", maximum=64),
    }


def send(records):
    body = json.dumps(records).encode("utf-8")
    rfc_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    sig = build_signature(rfc_date, len(body))
    url = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        "Content-Type": "application/json",
        "Authorization": sig,
        "Log-Type": LOG_TYPE,
        "x-ms-date": rfc_date,
        "time-generated-field": "TimeGenerated",
    }
    for attempt in range(1, 4):
        try:
            r = requests.post(url, data=body, headers=headers, timeout=30)
            if r.status_code == 200:
                print(f"[OK] Ingested {len(records)} findings → {LOG_TYPE}_CL")
                return True
            print(f"[WARN] Attempt {attempt} — HTTP {r.status_code}: {r.text}")
        except Exception as e:
            print(f"[WARN] Attempt {attempt} — {e}")
        time.sleep(2**attempt)
    print("[ERROR] Failed after 3 attempts")
    return False


def main():
    try:
        path = sys.argv[1] if len(sys.argv) > 1 else "scanner/output/test_findings.json"
        scan_id = sys.argv[2] if len(sys.argv) > 2 else datetime.datetime.now(datetime.UTC).strftime("scan-%Y%m%d-%H%M")
        print(f"[INFO] Scan ID: {scan_id}")
        validate_config()
        findings = load_findings(path)
        print(f"[INFO] Loaded {len(findings)} findings")
        records = [normalise(f, scan_id) for f in findings]
    except ValidationError:
        print("[ERROR] Invalid Sentinel configuration or findings input", file=sys.stderr)
        return 2
    return 0 if send(records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
