#!/usr/bin/env python3
"""
Sync aTrust resource grants from AD users to Feishu users.

This dedicated script matches AD users by description to Feishu users by user_id.
AD users with empty description are skipped because they do not have an employee
number that can be migrated.

Dry-run scans the current grant relationships and writes a plan. Execute mode
reads that plan and only submits append-assignment requests, saving API ops.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from atrust_feishu_resource_sync import (
    ATrustClient,
    build_reassociate_user_rows,
    discover_ad_user_grants,
    execute_from_plan,
    match_users_by_field_pair,
    normalize_value,
    output_reports,
    parse_id_file,
    write_csv,
)


AD_MATCH_FIELD = "description"
FEISHU_MATCH_FIELD = "user_id"
DEFAULT_CONFIG_FILE = "atrust_feishu_config.json"


def load_config(path: str) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8-sig") as fp:
        data = json.load(fp)
    if not isinstance(data, dict):
        raise ValueError(f"Config must be a JSON object: {path}")
    return data


def coalesce(cli_value: Any, config: dict[str, Any], key: str, default: Any = None) -> Any:
    if cli_value is not None:
        return cli_value
    value = config.get(key)
    return default if value is None else value


def require_value(args: argparse.Namespace, name: str, option: str) -> bool:
    if getattr(args, name):
        return True
    print(f"{option} is required unless set in --config.", file=sys.stderr)
    return False


def apply_config(args: argparse.Namespace) -> argparse.Namespace:
    config = load_config(args.config)
    args.base_url = coalesce(args.base_url, config, "base_url")
    args.api_id = coalesce(args.api_id, config, "api_id")
    args.api_secret = coalesce(args.api_secret, config, "api_secret")
    args.ad_domain = coalesce(args.ad_domain, config, "ad_domain")
    args.feishu_domain = coalesce(args.feishu_domain, config, "feishu_domain")
    args.insecure = args.insecure or bool(config.get("insecure", False))
    args.max_ops_per_second = coalesce(
        args.max_ops_per_second,
        config,
        "max_ops_per_second",
        8.0,
    )
    return args


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync AD grants to Feishu by matching AD description to Feishu user_id."
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="JSON config file path.")
    parser.add_argument("--base-url", help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", help="OpenAPI API ID")
    parser.add_argument("--api-secret", help="OpenAPI API secret")
    parser.add_argument("--ad-domain", help="AD user directory domain")
    parser.add_argument("--feishu-domain", help="Feishu user directory domain")
    parser.add_argument(
        "--confirmed-file",
        help="Confirmed user CSV. With --execute, defaults to <output-dir>/reassociate_users.csv.",
    )
    parser.add_argument(
        "--planned-grants-file",
        help="Grant plan CSV from dry-run. With --execute, defaults to <output-dir>/copied_grants.csv.",
    )
    parser.add_argument(
        "--resource-id-file",
        help="Optional UTF-8 text file containing application IDs to process, one per line.",
    )
    parser.add_argument(
        "--resource-group-id-file",
        help="Optional UTF-8 text file containing application category IDs to process, one per line.",
    )
    parser.add_argument(
        "--skip-resource-groups",
        action="store_true",
        help="Only copy application grants, not application category grants.",
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Only copy grants directly assigned to AD users. Role-derived grants are included by default.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Apply the dry-run plan. Without this flag the script only reports changes.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for self-signed aTrust certificates.",
    )
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--max-ops-per-second",
        type=float,
        default=None,
        help="Maximum aTrust API request rate. Default: 8.",
    )
    parser.add_argument(
        "--output-dir",
        default="output-ad-description-to-feishu",
        help="Directory for CSV reports.",
    )
    return parser.parse_args()


def build_copied_rows(
    matches_by_ad_id: dict[str, Any],
    grants_by_ad_user: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ad_user_id, grants in grants_by_ad_user.items():
        match = matches_by_ad_id.get(ad_user_id)
        if not match or not grants:
            continue
        for grant in grants:
            rows.append(
                {
                    "status": "dry_run",
                    "ad_user_id": match.ad_user.get("id"),
                    "ad_user_name": match.ad_user.get("name"),
                    "feishu_user_id": match.feishu_user.get("id"),
                    "feishu_user_name": match.feishu_user.get("name"),
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
    return rows


def write_execute_reports(
    output_dir: Path,
    copied_rows: list[dict[str, Any]],
    failed_rows: list[dict[str, Any]],
) -> None:
    write_csv(
        output_dir / "assigned_grants.csv",
        copied_rows,
        [
            "status",
            "ad_user_id",
            "ad_user_name",
            "feishu_user_id",
            "feishu_user_name",
            "kind",
            "resource_id",
            "resource_name",
            "source_type",
            "source_id",
            "source_name",
            "effectiveTime",
            "expireTime",
        ],
    )
    write_csv(
        output_dir / "failed_grants.csv",
        failed_rows,
        [
            "ad_user_id",
            "ad_user_name",
            "feishu_user_id",
            "feishu_user_name",
            "error",
        ],
    )


def main() -> int:
    args = apply_config(parse_args())
    if not all(
        [
            require_value(args, "base_url", "--base-url"),
            require_value(args, "api_id", "--api-id"),
            require_value(args, "api_secret", "--api-secret"),
            require_value(args, "ad_domain", "--ad-domain"),
            require_value(args, "feishu_domain", "--feishu-domain"),
        ]
    ):
        return 2
    base_path = urlsplit(args.base_url).path
    if base_path and base_path != "/":
        print("--base-url should only include scheme/host/port, not an API path.", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir)
    client = ATrustClient(
        args.base_url,
        args.api_id,
        args.api_secret,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        max_ops_per_second=args.max_ops_per_second,
    )

    if args.execute:
        confirmed_file = args.confirmed_file or str(output_dir / "reassociate_users.csv")
        planned_grants_file = args.planned_grants_file or str(output_dir / "copied_grants.csv")
        if not Path(confirmed_file).exists():
            print(f"Confirmed file not found: {confirmed_file}", file=sys.stderr)
            return 2
        if not Path(planned_grants_file).exists():
            print(f"Planned grants file not found: {planned_grants_file}", file=sys.stderr)
            return 2

        print("Executing from dry-run plan files to save API operations...")
        copied_rows, failed_rows = execute_from_plan(
            client,
            args.feishu_domain,
            confirmed_file,
            planned_grants_file,
        )
        write_execute_reports(output_dir, copied_rows, failed_rows)
        print(f"Grant rows assigned: {len(copied_rows)}")
        print(f"Failed user assignments: {len(failed_rows)}")
        print(f"Reports written to: {output_dir.resolve()}")
        return 0 if not failed_rows else 1

    print("Querying AD users...")
    ad_users = client.query_users(args.ad_domain)
    print(f"AD users: {len(ad_users)}")

    print("Querying Feishu users...")
    feishu_users = client.query_users(args.feishu_domain)
    print(f"Feishu users: {len(feishu_users)}")

    skipped_without_employee_no = sum(
        1 for user in ad_users if not normalize_value(AD_MATCH_FIELD, user.get(AD_MATCH_FIELD))
    )
    matches, unmatched, ambiguous = match_users_by_field_pair(
        ad_users,
        feishu_users,
        AD_MATCH_FIELD,
        FEISHU_MATCH_FIELD,
    )
    print(f"Matched by {AD_MATCH_FIELD}->{FEISHU_MATCH_FIELD}: {len(matches)}")
    print(f"AD users skipped because {AD_MATCH_FIELD} is empty: {skipped_without_employee_no}")
    print(f"Unmatched AD users: {len(unmatched)}, ambiguous AD users: {len(ambiguous)}")

    print("Discovering AD user resource grants...")
    grants_by_ad_user = discover_ad_user_grants(
        client,
        [match.ad_user for match in matches],
        include_groups=not args.skip_resource_groups,
        include_roles=not args.direct_only,
        resource_ids=parse_id_file(args.resource_id_file),
        group_ids=parse_id_file(args.resource_group_id_file),
    )

    reassociate_user_rows = build_reassociate_user_rows(matches, grants_by_ad_user)
    copied_rows = build_copied_rows(
        {str(match.ad_user.get("id")): match for match in matches},
        grants_by_ad_user,
    )

    output_reports(
        output_dir,
        matches,
        unmatched,
        ambiguous,
        copied_rows,
        failed_rows=[],
        reassociate_user_rows=reassociate_user_rows,
    )

    print(f"Users needing resource reassociation: {len(reassociate_user_rows)}")
    print(f"Grant rows planned: {len(copied_rows)}")
    print(f"Reports written to: {output_dir.resolve()}")
    print("Dry-run only. Review reassociate_users.csv, then re-run with --execute to apply that plan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
