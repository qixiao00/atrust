#!/usr/bin/env python3
"""
Analyze AD users that are associated with aTrust resources.

This script is read-only. It first finds AD directory users that have application
or application-category grants, then analyzes phone/email coverage and quality
for only those resource-associated users.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from atrust_feishu_resource_sync import (
    ATrustClient,
    ResourceGrant,
    discover_ad_user_grants,
    normalize_value,
    parse_id_file,
    write_csv,
)


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalized_phone(user: dict[str, Any]) -> str:
    for field in ("phone", "mobile", "mobilePhone", "mobile_number"):
        value = normalize_value(field, user.get(field))
        if value:
            return value
    return ""


def normalized_email(user: dict[str, Any]) -> str:
    return normalize_value("email", user.get("email"))


def is_valid_email(value: str) -> bool:
    return bool(value and EMAIL_RE.match(value))


def summarize_grants(grants: list[ResourceGrant]) -> dict[str, int]:
    counts = Counter()
    for grant in grants:
        counts["grant_count"] += 1
        if grant.kind == "resource":
            counts["resource_count"] += 1
        elif grant.kind == "resourceGroup":
            counts["resource_group_count"] += 1
        if grant.source_type == "user":
            counts["direct_grant_count"] += 1
        elif grant.source_type == "band":
            counts["role_grant_count"] += 1
    return dict(counts)


def user_display_name(user: dict[str, Any]) -> str:
    return str(user.get("displayName") or user.get("name") or "")


def build_user_rows(
    resource_users: list[dict[str, Any]],
    grants_by_user: dict[str, list[ResourceGrant]],
    duplicate_phones: set[str],
    duplicate_emails: set[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for user in resource_users:
        user_id = str(user.get("id") or "")
        grants = grants_by_user.get(user_id, [])
        phone = normalized_phone(user)
        email = normalized_email(user)
        grant_counts = summarize_grants(grants)
        rows.append(
            {
                "id": user.get("id"),
                "name": user.get("name"),
                "displayName": user.get("displayName"),
                "externalId": user.get("externalId"),
                "phone": user.get("phone"),
                "normalized_phone": phone,
                "email": user.get("email"),
                "normalized_email": email,
                "has_phone": "yes" if phone else "no",
                "has_email": "yes" if email else "no",
                "has_both_phone_email": "yes" if phone and email else "no",
                "valid_email_format": "yes" if is_valid_email(email) else "no",
                "duplicate_phone_in_resource_users": "yes" if phone in duplicate_phones else "no",
                "duplicate_email_in_resource_users": "yes" if email in duplicate_emails else "no",
                "grant_count": grant_counts.get("grant_count", 0),
                "resource_count": grant_counts.get("resource_count", 0),
                "resource_group_count": grant_counts.get("resource_group_count", 0),
                "direct_grant_count": grant_counts.get("direct_grant_count", 0),
                "role_grant_count": grant_counts.get("role_grant_count", 0),
                "roleIdList": ";".join(str(v) for v in (user.get("roleIdList") or [])),
                "description": user.get("description"),
            }
        )
    return rows


def build_grant_rows(
    resource_users: list[dict[str, Any]],
    grants_by_user: dict[str, list[ResourceGrant]],
) -> list[dict[str, Any]]:
    users_by_id = {str(user.get("id")): user for user in resource_users}
    rows: list[dict[str, Any]] = []
    for user_id, grants in sorted(grants_by_user.items()):
        user = users_by_id.get(user_id, {})
        for grant in grants:
            rows.append(
                {
                    "ad_user_id": user.get("id") or user_id,
                    "ad_user_name": user.get("name"),
                    "ad_user_displayName": user_display_name(user),
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


def duplicate_values(values: list[str]) -> set[str]:
    counts = Counter(value for value in values if value)
    return {value for value, count in counts.items() if count > 1}


def percent(part: int, total: int) -> str:
    if total <= 0:
        return "0.00%"
    return f"{part / total:.2%}"


def build_summary(
    all_ad_users: list[dict[str, Any]],
    resource_users: list[dict[str, Any]],
    grants_by_user: dict[str, list[ResourceGrant]],
    duplicate_phones: set[str],
    duplicate_emails: set[str],
) -> dict[str, Any]:
    total_resource_users = len(resource_users)
    phone_users = [user for user in resource_users if normalized_phone(user)]
    email_users = [user for user in resource_users if normalized_email(user)]
    both_users = [
        user
        for user in resource_users
        if normalized_phone(user) and normalized_email(user)
    ]
    neither_users = [
        user
        for user in resource_users
        if not normalized_phone(user) and not normalized_email(user)
    ]
    invalid_email_users = [
        user
        for user in resource_users
        if normalized_email(user) and not is_valid_email(normalized_email(user))
    ]

    grant_kind_counts = Counter()
    grant_source_counts = Counter()
    for grants in grants_by_user.values():
        for grant in grants:
            grant_kind_counts[grant.kind] += 1
            grant_source_counts[grant.source_type] += 1

    return {
        "ad_user_total": len(all_ad_users),
        "resource_associated_user_total": total_resource_users,
        "resource_associated_user_ratio": percent(total_resource_users, len(all_ad_users)),
        "users_with_phone": len(phone_users),
        "users_with_phone_ratio": percent(len(phone_users), total_resource_users),
        "users_with_email": len(email_users),
        "users_with_email_ratio": percent(len(email_users), total_resource_users),
        "users_with_both_phone_email": len(both_users),
        "users_with_both_phone_email_ratio": percent(len(both_users), total_resource_users),
        "users_with_neither_phone_nor_email": len(neither_users),
        "users_with_neither_phone_nor_email_ratio": percent(len(neither_users), total_resource_users),
        "users_with_invalid_email_format": len(invalid_email_users),
        "duplicate_phone_value_count": len(duplicate_phones),
        "duplicate_email_value_count": len(duplicate_emails),
        "grant_total": sum(len(grants) for grants in grants_by_user.values()),
        "grant_kind_counts": dict(sorted(grant_kind_counts.items())),
        "grant_source_counts": dict(sorted(grant_source_counts.items())),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze AD users that have aTrust resource grants and their phone/email status."
    )
    parser.add_argument("--base-url", required=True, help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", required=True, help="OpenAPI API ID")
    parser.add_argument("--api-secret", required=True, help="OpenAPI API secret")
    parser.add_argument("--ad-domain", required=True, help="AD user directory domain, for example custom01339")
    parser.add_argument(
        "--resource-id-file",
        help="Optional UTF-8 text file containing application IDs to analyze, one per line.",
    )
    parser.add_argument(
        "--resource-group-id-file",
        help="Optional UTF-8 text file containing application category IDs to analyze, one per line.",
    )
    parser.add_argument(
        "--skip-resource-groups",
        action="store_true",
        help="Only analyze application grants, not application category grants.",
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Only count grants directly assigned to AD users. Role-derived grants are included by default.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for self-signed aTrust certificates.",
    )
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument("--output-dir", default="output-ad-analysis", help="Directory for CSV/JSON reports.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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
    )

    print("Querying AD users...")
    ad_users = client.query_users(args.ad_domain)
    print(f"AD users: {len(ad_users)}")

    print("Discovering resource-associated AD users...")
    grants_by_user = discover_ad_user_grants(
        client,
        ad_users,
        include_groups=not args.skip_resource_groups,
        include_roles=not args.direct_only,
        resource_ids=parse_id_file(args.resource_id_file),
        group_ids=parse_id_file(args.resource_group_id_file),
    )
    grants_by_user = {user_id: grants for user_id, grants in grants_by_user.items() if grants}
    resource_user_ids = set(grants_by_user)
    resource_users = [
        user
        for user in ad_users
        if str(user.get("id") or "") in resource_user_ids
    ]

    phones = [normalized_phone(user) for user in resource_users]
    emails = [normalized_email(user) for user in resource_users]
    duplicate_phones = duplicate_values(phones)
    duplicate_emails = duplicate_values(emails)

    user_rows = build_user_rows(
        resource_users,
        grants_by_user,
        duplicate_phones,
        duplicate_emails,
    )
    grant_rows = build_grant_rows(resource_users, grants_by_user)
    contact_rows = [
        row
        for row in user_rows
        if row["has_phone"] == "yes" or row["has_email"] == "yes"
    ]
    summary = build_summary(
        ad_users,
        resource_users,
        grants_by_user,
        duplicate_phones,
        duplicate_emails,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    user_fieldnames = [
        "id",
        "name",
        "displayName",
        "externalId",
        "phone",
        "normalized_phone",
        "email",
        "normalized_email",
        "has_phone",
        "has_email",
        "has_both_phone_email",
        "valid_email_format",
        "duplicate_phone_in_resource_users",
        "duplicate_email_in_resource_users",
        "grant_count",
        "resource_count",
        "resource_group_count",
        "direct_grant_count",
        "role_grant_count",
        "roleIdList",
        "description",
    ]
    write_csv(output_dir / "ad_resource_users.csv", user_rows, user_fieldnames)
    write_csv(output_dir / "ad_resource_users_with_phone_or_email.csv", contact_rows, user_fieldnames)
    write_csv(
        output_dir / "ad_resource_user_grants.csv",
        grant_rows,
        [
            "ad_user_id",
            "ad_user_name",
            "ad_user_displayName",
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
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\nSummary:")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\nReports written to: {output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
