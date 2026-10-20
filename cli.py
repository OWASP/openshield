#!/usr/bin/env python3
"""OpenShield CLI.

Usage:
    openshield ask "What are my critical findings?" --subscription sub-001
    openshield ask "What is my MCSB compliance score?" -s sub-001 --framework mcsb
"""

from __future__ import annotations

import os
import sys
from typing import Optional

import requests


def cmd_ask(
    question: str,
    subscription_id: str,
    token: str,
    url: str,
    framework: Optional[str] = None,
) -> int:
    """Call POST /api/agent/query and print the result."""
    body: dict = {"question": question, "subscription_id": subscription_id}
    if framework:
        body["framework"] = framework

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(f"{url}/api/agent/query", json=body, headers=headers, timeout=120)
    except requests.exceptions.RequestException as exc:
        print(f"error: cannot connect to {url} ({exc})", file=sys.stderr)
        return 1

    if resp.status_code == 200:
        data = resp.json()
        print(data.get("answer", ""))
        tools = " | ".join(data.get("tools_used") or []) or "-"
        confidence = data.get("confidence", "-")
        iterations = data.get("iterations", "-")
        print(f"\n[tools used: {tools} | confidence: {confidence} | iterations: {iterations}]")
        return 0

    # 4xx / 5xx
    try:
        error_msg = resp.json().get("error", resp.text)
    except Exception:
        error_msg = resp.text
    print(f"error: {error_msg}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="openshield", description="OpenShield CLI")
    subparsers = parser.add_subparsers(dest="command")

    ask_parser = subparsers.add_parser("ask", help="Ask the CSPM AI agent a question")
    ask_parser.add_argument("question", help="Question to ask the agent")
    ask_parser.add_argument(
        "--subscription",
        "-s",
        dest="subscription",
        default=None,
        help="Azure subscription ID (or set AZURE_SUBSCRIPTION_ID)",
    )
    ask_parser.add_argument(
        "--framework",
        "-f",
        dest="framework",
        default=None,
        help="Compliance framework (optional)",
    )
    ask_parser.add_argument(
        "--url",
        dest="url",
        default=None,
        help="API base URL (default: OPENSHIELD_API_URL or http://localhost:5000)",
    )
    ask_parser.add_argument(
        "--token",
        dest="token",
        default=None,
        help="Bearer token (or set OPENSHIELD_TOKEN)",
    )

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "ask":
        subscription_id = args.subscription or os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not subscription_id:
            print(
                "error: --subscription is required (or set AZURE_SUBSCRIPTION_ID)",
                file=sys.stderr,
            )
            return 1

        token = args.token or os.environ.get("OPENSHIELD_TOKEN")
        if not token:
            print(
                "error: --token is required (or set OPENSHIELD_TOKEN)",
                file=sys.stderr,
            )
            return 1

        url = args.url or os.environ.get("OPENSHIELD_API_URL", "http://localhost:5000")

        return cmd_ask(
            question=args.question,
            subscription_id=subscription_id,
            token=token,
            url=url,
            framework=args.framework,
        )

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
