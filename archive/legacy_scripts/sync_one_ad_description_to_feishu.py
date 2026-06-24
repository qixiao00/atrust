#!/usr/bin/env python3
"""
Verify and optionally sync one AD user's aTrust grants to Feishu.

Input is the AD description value, which is also the Feishu user_id.
By default this script is dry-run. Add --execute to append grants to Feishu.
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
    normalize_value,
    parse_id_file,
    write_csv,
)
from sync_ad_description_to_feishu_user_id import (
    AD_MATCH_FIELD,
    DEFAULT_CONFIG_FILE,
    FEISHU_MATCH_FIELD,
    apply_config,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync one AD user's grants to Feishu by AD description / Feishu user_id."
    )
    parser.add_argument("--ad-description", required=True, help="AD description value, for example HCXXXXXXXX.")
    parser.add_argument(
        "--feishu-match-field",
        default=FEISHU_MATCH_FIELD,
        help="Feishu user field matched against the AD description. Default: user_id.",
    )
    parser.add_argument(
        "--feishu-match-value",
        help="Value to search in --feishu-match-field. Default: same as --ad-description.",
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="JSON config file path.")
    parser.add_argument("--base-url", help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", help="OpenAPI API ID")
    parser.add_argument("--api-secret", help="OpenAPI API secret")
    parser.add_argument("--ad-domain", help="AD user directory domain")
    parser.add_argument("--feishu-domain", help="Feishu user directory domain")
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
        help="Actually append grants to the matched Feishu user.",
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
        default="output-one-ad-description-to-feishu",
        help="Directory for CSV reports.",
    )
    return parser.parse_args()


def require_config(args: argparse.Namespace) -> bool:
    required = [
        ("base_url", "--base-url"),
        ("api_id", "--api-id"),
        ("api_secret", "--api-secret"),
        ("ad_domain", "--ad-domain"),
        ("feishu_domain", "--feishu-domain"),
    ]
    missing = [option for attr, option in required if not getattr(args, attr)]
    for option in missing:
        print(f"{option} is required unless set in --config.", file=sys.stderr)
    return not missing


def find_unique_user(
    users: list[dict],
    field: str,
    value: str,
    label: str,
) -> dict | None:
    target = normalize_value(field, value)
    matches = [user for user in users if normalize_value(field, user.get(field)) == target]
    if not matches:
        print(f"No {label} user found where {field}={value}.", file=sys.stderr)
        if label == "Feishu" and field == FEISHU_MATCH_FIELD:
            print(
                "If this user exists in Feishu, confirm which aTrust field stores the employee number "
                "and retry with --feishu-match-field, for example name, displayName, externalId, "
                "email, phone, or description.",
                file=sys.stderr,
            )
        return None
    if len(matches) > 1:
        print(f"Multiple {label} users found where {field}={value}; refusing to sync.", file=sys.stderr)
        for user in matches:
            print(f"  id={user.get('id')} name={user.get('name')} displayName={user.get('displayName')}", file=sys.stderr)
        return None
    return matches[0]


def build_grant_rows(
    status: str,
    match: UserMatch,
    grants: list[ResourceGrant],
) -> list[dict]:
    rows: list[dict] = []
    for grant in grants:
        rows.append(
            {
                "status": status,
                "ad_user_id": match.ad_user.get("id"),
                "ad_user_name": match.ad_user.get("name"),
                "ad_description": match.ad_user.get(AD_MATCH_FIELD),
                "feishu_user_id": match.feishu_user.get("id"),
                "feishu_user_name": match.feishu_user.get("name"),
                "feishu_user_id_field": match.feishu_user.get(match.target_field or FEISHU_MATCH_FIELD),
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


def main() -> int:
    args = apply_config(parse_args())
    if not require_config(args):
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

    print("Querying AD users...")
    ad_users = client.query_users(args.ad_domain)
    ad_user = find_unique_user(ad_users, AD_MATCH_FIELD, args.ad_description, "AD")
    if not ad_user:
        return 1

    print("Querying Feishu users...")
    feishu_users = client.query_users(args.feishu_domain)
    feishu_match_value = args.feishu_match_value or args.ad_description
    feishu_user = find_unique_user(feishu_users, args.feishu_match_field, feishu_match_value, "Feishu")
    if not feishu_user:
        return 1

    match_value = normalize_value(AD_MATCH_FIELD, args.ad_description)
    match = UserMatch(ad_user, feishu_user, AD_MATCH_FIELD, match_value, args.feishu_match_field)

    print("Discovering this AD user's resource grants...")
    grants_by_ad_user = discover_ad_user_grants(
        client,
        [ad_user],
        include_groups=not args.skip_resource_groups,
        include_roles=not args.direct_only,
        resource_ids=parse_id_file(args.resource_id_file),
        group_ids=parse_id_file(args.resource_group_id_file),
    )
    grants = grants_by_ad_user.get(str(ad_user.get("id")), [])
    status = "assigned" if args.execute else "dry_run"
    grant_rows = build_grant_rows(status, match, grants)
    reassociate_rows = build_reassociate_user_rows([match], grants_by_ad_user)

    output_dir = Path(args.output_dir)
    write_csv(
        output_dir / "single_user_match.csv",
        reassociate_rows,
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
        output_dir / "single_user_grants.csv",
        grant_rows,
        [
            "status",
            "ad_user_id",
            "ad_user_name",
            "ad_description",
            "feishu_user_id",
            "feishu_user_name",
            "feishu_user_id_field",
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

    failed_rows: list[dict] = []
    if args.execute and grants:
        try:
            client.assign_to_user_by_id(args.feishu_domain, str(feishu_user["id"]), grants)
        except Exception as exc:  # noqa: BLE001 - report clearly for manual handling.
            failed_rows.append(
                {
                    "ad_user_id": ad_user.get("id"),
                    "ad_user_name": ad_user.get("name"),
                    "feishu_user_id": feishu_user.get("id"),
                    "feishu_user_name": feishu_user.get("name"),
                    "error": str(exc),
                }
            )
    write_csv(
        output_dir / "single_user_failed.csv",
        failed_rows,
        ["ad_user_id", "ad_user_name", "feishu_user_id", "feishu_user_name", "error"],
    )

    print(f"Matched AD user: id={ad_user.get('id')} name={ad_user.get('name')}")
    print(f"Matched Feishu user: id={feishu_user.get('id')} name={feishu_user.get('name')}")
    print(f"Grant rows {'assigned' if args.execute else 'planned'}: {len(grant_rows)}")
    print(f"Failed user assignments: {len(failed_rows)}")
    print(f"Reports written to: {output_dir.resolve()}")
    if not args.execute:
        print("Dry-run only. Re-run with --execute to append grants for this user.")
    return 0 if not failed_rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
