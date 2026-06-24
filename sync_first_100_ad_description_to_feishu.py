#!/usr/bin/env python3
"""Migrate up to 100 matched AD users' grants to Feishu and cache grant details.

The script keeps the same matching rule as sync_ad_description_to_feishu_user_id.py:
AD description -> Feishu user_id. It always writes a reusable CSV containing the
AD users' discovered grant details, so later runs can execute from that CSV
instead of scanning resources again.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

from atrust_feishu_resource_sync import (
    ATrustClient,
    ResourceGrant,
    UserMatch,
    build_reassociate_user_rows,
    discover_ad_user_grants,
    match_users_by_field_pair,
    normalize_value,
    parse_id_file,
    write_csv,
)
from sync_ad_description_to_feishu_user_id import (
    AD_MATCH_FIELD,
    DEFAULT_CONFIG_FILE,
    FEISHU_MATCH_FIELD,
    apply_config,
    build_copied_rows,
    require_value,
    write_execute_reports,
)

GRANT_DETAIL_COLUMNS = [
    "status",
    "ad_user_id",
    "ad_user_name",
    "ad_displayName",
    "ad_description",
    "feishu_user_id",
    "feishu_user_name",
    "feishu_displayName",
    "feishu_user_id_field",
    "match_field",
    "target_field",
    "match_value",
    "kind",
    "resource_id",
    "resource_name",
    "source_type",
    "source_id",
    "source_name",
    "effectiveTime",
    "expireTime",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate at most N AD-description matched users to Feishu and cache AD grant details."
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="JSON config file path.")
    parser.add_argument("--base-url", help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", help="OpenAPI API ID")
    parser.add_argument("--api-secret", help="OpenAPI API secret")
    parser.add_argument("--ad-domain", help="AD user directory domain")
    parser.add_argument("--feishu-domain", help="Feishu user directory domain")
    parser.add_argument(
        "--max-successful-users",
        type=int,
        default=100,
        help="Stop after this many users are successfully assigned. Default: 100.",
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
        help="Actually append grants to Feishu users. Without this flag, only CSV files are generated.",
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
        default="output-first-100-ad-description-to-feishu",
        help="Directory for CSV reports.",
    )
    return parser.parse_args()


def build_grant_detail_rows(
    matches: list[UserMatch],
    grants_by_ad_user: dict[str, list[ResourceGrant]],
) -> list[dict]:
    rows: list[dict] = []
    for match in matches:
        ad_user_id = str(match.ad_user.get("id") or "")
        for grant in grants_by_ad_user.get(ad_user_id, []):
            rows.append(
                {
                    "status": "planned",
                    "ad_user_id": match.ad_user.get("id"),
                    "ad_user_name": match.ad_user.get("name"),
                    "ad_displayName": match.ad_user.get("displayName"),
                    "ad_description": match.ad_user.get(AD_MATCH_FIELD),
                    "feishu_user_id": match.feishu_user.get("id"),
                    "feishu_user_name": match.feishu_user.get("name"),
                    "feishu_displayName": match.feishu_user.get("displayName"),
                    "feishu_user_id_field": match.feishu_user.get(match.target_field or FEISHU_MATCH_FIELD),
                    "match_field": match.match_field,
                    "target_field": match.target_field or FEISHU_MATCH_FIELD,
                    "match_value": match.match_value,
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


def execute_until_success_limit(
    client: ATrustClient,
    feishu_domain: str,
    matches: list[UserMatch],
    grants_by_ad_user: dict[str, list[ResourceGrant]],
    max_successful_users: int,
) -> tuple[list[dict], list[dict], int, set[str]]:
    assigned_rows: list[dict] = []
    failed_rows: list[dict] = []
    successful_users = 0
    successful_ad_user_ids: set[str] = set()

    for match in matches:
        if successful_users >= max_successful_users:
            break
        ad_user_id = str(match.ad_user.get("id") or "")
        grants = grants_by_ad_user.get(ad_user_id, [])
        if not grants:
            continue
        try:
            client.assign_to_user_by_id(feishu_domain, str(match.feishu_user["id"]), grants)
        except Exception as exc:  # noqa: BLE001 - report and continue until enough successes.
            failed_rows.append(
                {
                    "ad_user_id": match.ad_user.get("id"),
                    "ad_user_name": match.ad_user.get("name"),
                    "feishu_user_id": match.feishu_user.get("id"),
                    "feishu_user_name": match.feishu_user.get("name"),
                    "error": str(exc),
                }
            )
            continue

        successful_users += 1
        successful_ad_user_ids.add(ad_user_id)
        for grant in grants:
            assigned_rows.append(
                {
                    "status": "assigned",
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
    return assigned_rows, failed_rows, successful_users, successful_ad_user_ids


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
    if args.max_successful_users <= 0:
        print("--max-successful-users must be greater than 0.", file=sys.stderr)
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

    print("Discovering matched AD users' resource grants...")
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
    grant_detail_rows = build_grant_detail_rows(matches, grants_by_ad_user)

    write_csv(output_dir / "ad_authorized_grants.csv", grant_detail_rows, GRANT_DETAIL_COLUMNS)
    write_csv(
        output_dir / "reassociate_users.csv",
        reassociate_user_rows,
        [
            "ad_user_id",
            "ad_user_name",
            "ad_displayName",
            "ad_description",
            "feishu_user_id",
            "feishu_user_name",
            "feishu_displayName",
            "feishu_user_id_field",
            "match_field",
            "target_field",
            "match_value",
            "grant_count",
            "resource_count",
            "resource_group_count",
        ],
    )
    write_csv(
        output_dir / "copied_grants.csv",
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

    assigned_rows: list[dict] = []
    failed_rows: list[dict] = []
    successful_users = 0
    successful_ad_user_ids: set[str] = set()
    if args.execute:
        print(f"Executing until {args.max_successful_users} users are successfully assigned...")
        assigned_rows, failed_rows, successful_users, successful_ad_user_ids = execute_until_success_limit(
            client,
            args.feishu_domain,
            matches,
            grants_by_ad_user,
            args.max_successful_users,
        )
        write_execute_reports(output_dir, assigned_rows, failed_rows)
    else:
        print("Dry-run only. Re-run with --execute to migrate users.")

    remaining_matches = [
        match for match in matches if str(match.ad_user.get("id") or "") not in successful_ad_user_ids
    ]
    remaining_reassociate_user_rows = build_reassociate_user_rows(remaining_matches, grants_by_ad_user)
    remaining_copied_rows = build_copied_rows(
        {str(match.ad_user.get("id")): match for match in remaining_matches},
        grants_by_ad_user,
    )
    write_csv(
        output_dir / "remaining_reassociate_users.csv",
        remaining_reassociate_user_rows,
        [
            "ad_user_id",
            "ad_user_name",
            "ad_displayName",
            "ad_description",
            "feishu_user_id",
            "feishu_user_name",
            "feishu_displayName",
            "feishu_user_id_field",
            "match_field",
            "target_field",
            "match_value",
            "grant_count",
            "resource_count",
            "resource_group_count",
        ],
    )
    write_csv(
        output_dir / "remaining_copied_grants.csv",
        remaining_copied_rows,
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

    print(f"AD users with grants: {len(reassociate_user_rows)}")
    print(f"Cached AD grant detail rows: {len(grant_detail_rows)}")
    print(f"Reusable grant plan rows: {len(copied_rows)}")
    print(f"Remaining users with grants: {len(remaining_reassociate_user_rows)}")
    print(f"Remaining reusable grant plan rows: {len(remaining_copied_rows)}")
    if args.execute:
        print(f"Successful user assignments: {successful_users}")
        print(f"Assigned grant rows: {len(assigned_rows)}")
        print(f"Failed user assignments: {len(failed_rows)}")
    print(f"Reports written to: {output_dir.resolve()}")
    return 0 if not failed_rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
