#!/usr/bin/env python3
"""Precheck: export AD authorized grants matched to Feishu by description."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from atrust_common import (
    ATrustClient,
    DEFAULT_CONFIG_FILE,
    apply_config,
    discover_user_grants,
    match_by_description,
    normalize_value,
    parse_id_file,
    require_config_values,
    write_csv,
)


OUTPUT_FIELDS = [
    "ad_user_id",
    "ad_user_name",
    "ad_display_name",
    "ad_description",
    "feishu_user_id",
    "feishu_user_name",
    "feishu_display_name",
    "feishu_description",
    "match_source_field",
    "match_target_field",
    "match_value",
    "grant_kind",
    "resource_id",
    "resource_name",
    "grant_source_type",
    "grant_source_id",
    "grant_source_name",
    "effective_time",
    "expire_time",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate ad_authorized_grants.csv for AD description -> Feishu description migration."
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="JSON config file path.")
    parser.add_argument("--base-url", help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", help="OpenAPI API ID")
    parser.add_argument("--api-secret", help="OpenAPI API secret")
    parser.add_argument("--ad-domain", help="AD user directory domain")
    parser.add_argument("--feishu-domain", help="Feishu user directory domain")
    parser.add_argument("--resource-id-file", help="Optional file with application IDs, one per line.")
    parser.add_argument("--resource-group-id-file", help="Optional file with application category IDs, one per line.")
    parser.add_argument("--skip-resource-groups", action="store_true", help="Do not include application categories.")
    parser.add_argument("--direct-only", action="store_true", help="Do not include role-derived grants.")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Generate full ad_authorized_grants.csv. Without this flag, only 10 authorized users are sampled.",
    )
    parser.add_argument(
        "--sample-user-count",
        type=int,
        default=10,
        help="Authorized user count to sample before stopping. Default: 10.",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument("--max-ops-per-second", type=float, default=None, help="Default: 8.")
    parser.add_argument("--output-dir", default="outputs/precheck", help="Directory for this script's outputs.")
    return parser.parse_args()


def validate_base_url(base_url: str) -> bool:
    base_path = urlsplit(base_url).path
    if base_path and base_path != "/":
        print("--base-url should only include scheme/host/port, not an API path.", file=sys.stderr)
        return False
    return True


def select_pairs_with_grants(pairs, grants_by_ad_user, limit: int | None):
    selected = []
    for pair in pairs:
        ad_user_id = str(pair.ad_user.get("id") or "")
        if not grants_by_ad_user.get(ad_user_id):
            continue
        selected.append(pair)
        if limit and len(selected) >= limit:
            break
    return selected


def build_grant_rows(pairs, grants_by_ad_user) -> list[dict]:
    rows: list[dict] = []
    pairs_by_ad_id = {str(pair.ad_user.get("id")): pair for pair in pairs}
    for ad_user_id, grants in sorted(grants_by_ad_user.items()):
        pair = pairs_by_ad_id.get(ad_user_id)
        if not pair:
            continue
        for grant in grants:
            rows.append(
                {
                    "ad_user_id": pair.ad_user.get("id"),
                    "ad_user_name": pair.ad_user.get("name"),
                    "ad_display_name": pair.ad_user.get("displayName"),
                    "ad_description": pair.ad_user.get("description"),
                    "feishu_user_id": pair.feishu_user.get("id"),
                    "feishu_user_name": pair.feishu_user.get("name"),
                    "feishu_display_name": pair.feishu_user.get("displayName"),
                    "feishu_description": pair.feishu_user.get("description"),
                    "match_source_field": "description",
                    "match_target_field": "description",
                    "match_value": pair.match_value,
                    "grant_kind": grant.kind,
                    "resource_id": grant.resource_id,
                    "resource_name": grant.resource_name,
                    "grant_source_type": grant.source_type,
                    "grant_source_id": grant.source_id,
                    "grant_source_name": grant.source_name,
                    "effective_time": grant.effective_time or "",
                    "expire_time": grant.expire_time or "",
                }
            )
    return rows


def build_user_rows(pairs, grants_by_ad_user) -> list[dict]:
    rows: list[dict] = []
    for pair in pairs:
        ad_user_id = str(pair.ad_user.get("id") or "")
        grants = grants_by_ad_user.get(ad_user_id, [])
        if not grants:
            continue
        rows.append(
            {
                "ad_user_id": pair.ad_user.get("id"),
                "ad_user_name": pair.ad_user.get("name"),
                "ad_display_name": pair.ad_user.get("displayName"),
                "ad_description": pair.ad_user.get("description"),
                "feishu_user_id": pair.feishu_user.get("id"),
                "feishu_user_name": pair.feishu_user.get("name"),
                "feishu_display_name": pair.feishu_user.get("displayName"),
                "feishu_description": pair.feishu_user.get("description"),
                "match_value": pair.match_value,
                "grant_count": len(grants),
                "resource_count": sum(1 for grant in grants if grant.kind == "resource"),
                "resource_group_count": sum(1 for grant in grants if grant.kind == "resourceGroup"),
            }
        )
    return rows


def main() -> int:
    args = apply_config(parse_args())
    if not require_config_values(args) or not validate_base_url(args.base_url):
        return 2

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

    pairs, unmatched, ambiguous = match_by_description(ad_users, feishu_users)
    empty_ad_description = sum(1 for user in ad_users if not normalize_value(user.get("description")))
    print(f"Matched by description: {len(pairs)}")
    print(f"AD users skipped because description is empty: {empty_ad_description}")
    print(f"Unmatched AD users: {len(unmatched)}, ambiguous AD users: {len(ambiguous)}")

    sample_limit = None if args.full else max(args.sample_user_count, 1)
    print("Discovering AD-side grants for matched users...")
    grants_by_ad_user = discover_user_grants(
        client,
        [pair.ad_user for pair in pairs],
        include_groups=not args.skip_resource_groups,
        include_roles=not args.direct_only,
        resource_ids=parse_id_file(args.resource_id_file),
        group_ids=parse_id_file(args.resource_group_id_file),
        stop_after_users=sample_limit,
    )

    output_dir = Path(args.output_dir)
    output_pairs = pairs if args.full else select_pairs_with_grants(pairs, grants_by_ad_user, sample_limit)
    grant_rows = build_grant_rows(output_pairs, grants_by_ad_user)
    user_rows = build_user_rows(output_pairs, grants_by_ad_user)
    grants_filename = "ad_authorized_grants.csv" if args.full else "ad_authorized_grants_10.csv"
    users_filename = "authorized_users.csv" if args.full else "authorized_users_10.csv"
    write_csv(output_dir / grants_filename, grant_rows, OUTPUT_FIELDS)
    write_csv(
        output_dir / users_filename,
        user_rows,
        [
            "ad_user_id",
            "ad_user_name",
            "ad_display_name",
            "ad_description",
            "feishu_user_id",
            "feishu_user_name",
            "feishu_display_name",
            "feishu_description",
            "match_value",
            "grant_count",
            "resource_count",
            "resource_group_count",
        ],
    )
    write_csv(
        output_dir / "unmatched_ad_users.csv",
        [
            {
                "ad_user_id": user.get("id"),
                "ad_user_name": user.get("name"),
                "ad_display_name": user.get("displayName"),
                "ad_description": user.get("description"),
                "reason": user.get("_reason"),
            }
            for user in unmatched
        ],
        ["ad_user_id", "ad_user_name", "ad_display_name", "ad_description", "reason"],
    )
    write_csv(
        output_dir / "ambiguous_ad_users.csv",
        [
            {
                "ad_user_id": user.get("id"),
                "ad_user_name": user.get("name"),
                "ad_display_name": user.get("displayName"),
                "ad_description": user.get("description"),
                "reason": user.get("_reason"),
                "duplicate_keys": user.get("_duplicate_keys"),
            }
            for user in ambiguous
        ],
        ["ad_user_id", "ad_user_name", "ad_display_name", "ad_description", "reason", "duplicate_keys"],
    )
    summary = {
        "mode": "full" if args.full else "sample",
        "sample_user_count": None if args.full else sample_limit,
        "ad_user_total": len(ad_users),
        "feishu_user_total": len(feishu_users),
        "matched_by_description": len(pairs),
        "empty_ad_description": empty_ad_description,
        "unmatched_ad_users": len(unmatched),
        "ambiguous_ad_users": len(ambiguous),
        "users_with_authorized_grants": len(user_rows),
        "authorized_grant_rows": len(grant_rows),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_filename = "summary.json" if args.full else "summary_10.json"
    (output_dir / summary_filename).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Users with AD-side grants: {len(user_rows)}")
    print(f"AD authorized grant rows: {len(grant_rows)}")
    print(f"Output CSV: {(output_dir / grants_filename).resolve()}")
    print(f"Outputs written to: {output_dir.resolve()}")
    if not args.full:
        print("Sample mode complete. Re-run with --full when you are ready to generate ad_authorized_grants.csv.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
