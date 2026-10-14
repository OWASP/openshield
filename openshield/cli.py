"""Command line entry point for the standalone Azure scanner."""

import argparse
import json
import logging
import os
import re
import sys
from importlib.metadata import PackageNotFoundError, version

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import CredentialUnavailableError
from azure.mgmt.resource import SubscriptionClient

_SUBSCRIPTION_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _report(result: dict, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result, indent=2))
        return
    print(f"OpenShield scan {result['scan_id']}")
    print(f"Subscription: {result['subscription_id']}")
    print(f"Status: {result['status']}")
    print(f"Findings: {result['total_findings']}")
    for finding in result["findings"]:
        print(
            f"  [{finding.get('severity', 'UNKNOWN')}] {finding.get('rule_id', 'UNKNOWN')}: "
            f"{finding.get('resource_id', finding.get('resource_name', 'unknown resource'))}"
        )
    print("Failed rules: " + (", ".join(result["failed_rule_ids"]) or "none"))


def _preflight(credential: object, subscription_id: str) -> None:
    """Reject missing credentials and inaccessible subscriptions before scanning."""
    credential.get_token("https://management.azure.com/.default")
    SubscriptionClient(credential).subscriptions.get(subscription_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openshield", description="Scan an Azure subscription for security findings")
    try:
        package_version = version("owasp-openshield")
    except PackageNotFoundError:
        package_version = "development"
    parser.add_argument("--version", action="version", version=f"%(prog)s {package_version}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Scan an Azure subscription")
    scan.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID"),
        help="Azure subscription UUID (defaults to AZURE_SUBSCRIPTION_ID)",
    )
    scan.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    if not args.subscription_id or not _SUBSCRIPTION_RE.fullmatch(args.subscription_id):
        return _failure(
            args, "invalid_configuration", "Provide a valid UUID with --subscription-id or AZURE_SUBSCRIPTION_ID."
        )

    # Azure SDK and legacy rule exceptions can contain resource details. The
    # public CLI prints safe status codes and rule IDs instead of raw logs.
    previous_logging_level = logging.root.manager.disable
    logging.disable(logging.CRITICAL)

    try:
        from scanner.engine import ScanEngine

        engine = ScanEngine(args.subscription_id)
        # Fail before rule evaluation if the configured Azure credential chain
        # cannot authenticate. Rules may otherwise turn auth failures into
        # empty inventories and misleading clean results.
        _preflight(engine.client.credential, args.subscription_id)
        result = engine.run_scan()
    except (ClientAuthenticationError, CredentialUnavailableError):
        return _failure(
            args, "authentication_failed", "Azure authentication failed; check your credential configuration."
        )
    except HttpResponseError:
        return _failure(args, "subscription_unavailable", "Azure denied or could not find this subscription.")
    except Exception as exc:
        return _failure(args, "scan_failed", f"Scanner failed before completion ({type(exc).__name__}).")
    finally:
        logging.disable(previous_logging_level)

    if result["failed_rule_ids"]:
        result["status"] = "incomplete"
    _report(result, args.format)
    return 2 if result["status"] != "completed" else 0


def _failure(args: argparse.Namespace, status: str, message: str) -> int:
    if args.format == "json":
        print(
            json.dumps(
                {"status": status, "subscription_id": args.subscription_id, "failed_rule_ids": [], "error": message}
            )
        )
    else:
        print(f"OpenShield {status}: {message}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
