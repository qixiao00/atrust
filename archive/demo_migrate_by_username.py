#!/usr/bin/env python3
"""
Demo script: migrate aTrust permissions from one AD user to one Feishu user by username.

This script is intentionally narrow for feasibility testing:
- It looks up one AD user by username.
- It looks up one Feishu user by username.
- It copies that AD user's grants to the Feishu user.
- It runs in dry-run mode unless --execute is passed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from atrust_feishu_resource_sync import (
    ATrustClient,
    discover_ad_user_grants,
    output_reports,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demo: copy one AD user's aTrust grants to one Feishu user by username."
    )
    parser.add_argument("--base-url", required=True, help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", required=True, help="OpenAPI API ID")
    parser.add_argument("--api-secret", required=True, help="OpenAPI API secret")
    parser.add_argument("--ad-domain", required=True, help="AD user directory domain, for example custom01339")
    parser.add_argument("--feishu-domain", required=True, help="Feishu user directory domain")
    parser.add_argument("--ad-username", required=True, help="AD username to migrate from")
    parser.add_argument(
        "--feishu-username",
        help="Feishu username to migrate to. Defaults to the same value as --ad-username.",
    )
    parser.add_argument(
        "--match-field",
        default="name",
        help="User field used to find the account by username. Default: name",
    )
    parser.add_argument(
        "--skip-resource-groups",
        action="store_true",
        help="Only copy application grants, not application category grants.",
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Only copy grants directly assigned to the AD user. Role-derived grants are included by default.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually assign resources to the Feishu user. Without this flag the script only reports changes.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for self-signed aTrust certificates.",
    )
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument("--output-dir", default="output-demo", help="Directory for CSV reports.")
    return parser.parse_args()


def find_user(users: list[dict[str, Any]], field: str, value: str) -> dict[str, Any] | None:
    target = value.strip().lower()
    if not target:
        return None
    for user in users:
        candidate = str(user.get(field) or "").strip().lower()
        if candidate == target:
            return user
    return None


def main() -> int:
    args = parse_args()
    feishu_username = args.feishu_username or args.ad_username

    client = ATrustClient(
        args.base_url,
        args.api_id,
        args.api_secret,
        timeout=args.timeout,
        verify_tls=not args.insecure,
    )

    print("Querying AD users...")
    ad_users = client.query_users(args.ad_domain)
    print(f"AD users: {len(ad_users)}")

    print("Querying Feishu users...")
    feishu_users = client.query_users(args.feishu_domain)
    print(f"Feishu users: {len(feishu_users)}")

    ad_user = find_user(ad_users, args.match_field, args.ad_username)
    if not ad_user:
        print(
            f"AD user not found: field={args.match_field} value={args.ad_username}",
            file=sys.stderr,
        )
        return 2

    feishu_user = find_user(feishu_users, args.match_field, feishu_username)
    if not feishu_user:
        print(
            f"Feishu user not found: field={args.match_field} value={feishu_username}",
            file=sys.stderr,
        )
        return 2

    print(
        f"Matched AD user {ad_user.get('id')} -> Feishu user {feishu_user.get('id')} "
        f"using {args.match_field}"
    )

    grants_by_ad_user = discover_ad_user_grants(
        client,
        [ad_user],
        include_groups=not args.skip_resource_groups,
        include_roles=not args.direct_only,
        resource_ids=None,
        group_ids=None,
    )
    grants = grants_by_ad_user.get(str(ad_user.get("id")), [])
    print(f"Discovered grants: {len(grants)}")

    copied_rows: list[dict[str, Any]] = []
    failed_rows: list[dict[str, Any]] = []
    if grants:
        try:
            if args.execute:
                client.assign_to_user_by_id(
                    args.feishu_domain,
                    str(feishu_user["id"]),
                    grants,
                )
            status = "assigned" if args.execute else "dry_run"
            for grant in grants:
                copied_rows.append(
                    {
                        "status": status,
                        "ad_user_id": ad_user.get("id"),
                        "ad_user_name": ad_user.get("name"),
                        "feishu_user_id": feishu_user.get("id"),
                        "feishu_user_name": feishu_user.get("name"),
                        "kind": grant.kind,
                        "resource_id": grant.resource_id,
                        "resource_name": grant.resource_name,
                        "source_type": grant.source_type,
                        "source_id": grant.source_id,
                        "source_name": grant.source_name,
                        "effectiveTime": grant.effective_time or "",
                        "expireTime": grant.expire_time or "",
                    }
                )
        except Exception as exc:  # noqa: BLE001 - demo script should keep reporting on failure.
            failed_rows.append(
                {
                    "ad_user_id": ad_user.get("id"),
                    "ad_user_name": ad_user.get("name"),
                    "feishu_user_id": feishu_user.get("id"),
                    "feishu_user_name": feishu_user.get("name"),
                    "error": str(exc),
                }
            )

    output_reports(
        Path(args.output_dir),
        matches=[],
        unmatched=[],
        ambiguous=[],
        copied_rows=copied_rows,
        failed_rows=failed_rows,
    )

    print(f"Grant rows {'assigned' if args.execute else 'planned'}: {len(copied_rows)}")
    print(f"Failed user assignments: {len(failed_rows)}")
    print(f"Reports written to: {Path(args.output_dir).resolve()}")
    if not args.execute:
        print("Dry-run only. Re-run with --execute after reviewing the CSV reports.")
    return 0 if not failed_rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
