#!/usr/bin/env python3
"""Precheck: generate AD authorized grants CSV for AD.description -> Feishu.description."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ad_description_to_feishu_description_common import (  # noqa: E402
    AD_MATCH_FIELD,
    FEISHU_MATCH_FIELD,
    GRANT_DETAIL_COLUMNS,
    add_common_args,
    apply_config,
    build_grant_detail_rows,
    missing_required_options,
)
from atrust_feishu_resource_sync import (  # noqa: E402
    ATrustClient,
    build_reassociate_user_rows,
    discover_ad_user_grants,
    match_users_by_field_pair,
    normalize_value,
    parse_id_file,
    write_csv,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate ad_authorized_grants.csv for AD.description -> Feishu.description migration."
    )
    add_common_args(parser, default_output_dir="output-precheck-ad-description-to-feishu-description")
    parser.add_argument("--resource-id-file", help="Optional UTF-8 text file with application IDs, one per line.")
    parser.add_argument("--resource-group-id-file", help="Optional UTF-8 text file with category IDs, one per line.")
    parser.add_argument("--skip-resource-groups", action="store_true", help="Only include applications.")
    parser.add_argument("--direct-only", action="store_true", help="Exclude role-derived grants.")
    return parser.parse_args()


def main() -> int:
    args = apply_config(parse_args())
    missing = missing_required_options(args)
    if missing:
        for option in missing:
            print(f"{option} is required unless set in --config.", file=sys.stderr)
        return 2
    base_path = urlsplit(args.base_url).path
    if base_path and base_path != "/":
        print("--base-url should only include scheme/host/port, not an API path.", file=sys.stderr)
        return 2

    client = ATrustClient(
        args.base_url,
        args.api_id,
        args.api_secret,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        max_ops_per_second=args.max_ops_per_second,
    )
    output_dir = Path(args.output_dir)

    print("Querying AD users...")
    ad_users = client.query_users(args.ad_domain)
    print(f"AD users: {len(ad_users)}")

    print("Querying Feishu users...")
    feishu_users = client.query_users(args.feishu_domain)
    print(f"Feishu users: {len(feishu_users)}")

    skipped_without_description = sum(
        1 for user in ad_users if not normalize_value(AD_MATCH_FIELD, user.get(AD_MATCH_FIELD))
    )
    matches, unmatched, ambiguous = match_users_by_field_pair(
        ad_users,
        feishu_users,
        AD_MATCH_FIELD,
        FEISHU_MATCH_FIELD,
    )
    print(f"Matched by {AD_MATCH_FIELD}->{FEISHU_MATCH_FIELD}: {len(matches)}")
    print(f"AD users skipped because {AD_MATCH_FIELD} is empty: {skipped_without_description}")
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

    grant_detail_rows = build_grant_detail_rows(matches, grants_by_ad_user)
    reassociate_user_rows = build_reassociate_user_rows(matches, grants_by_ad_user)
    write_csv(output_dir / "ad_authorized_grants.csv", grant_detail_rows, GRANT_DETAIL_COLUMNS)
    write_csv(
        output_dir / "matched_users_with_grants.csv",
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
        output_dir / "unmatched_ad_users.csv",
        [
            {
                "id": user.get("id"),
                "name": user.get("name"),
                "displayName": user.get("displayName"),
                "description": user.get("description"),
            }
            for user in unmatched
        ],
        ["id", "name", "displayName", "description"],
    )
    write_csv(
        output_dir / "ambiguous_ad_users.csv",
        [
            {
                "id": user.get("id"),
                "name": user.get("name"),
                "displayName": user.get("displayName"),
                "description": user.get("description"),
                "reason": user.get("_reason"),
                "duplicate_keys": user.get("_duplicate_keys"),
            }
            for user in ambiguous
        ],
        ["id", "name", "displayName", "description", "reason", "duplicate_keys"],
    )

    print(f"AD users with grants: {len(reassociate_user_rows)}")
    print(f"Grant detail rows: {len(grant_detail_rows)}")
    print(f"Reports written to: {output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
