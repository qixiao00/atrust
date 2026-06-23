#!/usr/bin/env python3
"""
Two-phase demo for migrating permissions from AD to Paeira/Para SSO.

Phase 1: match AD users to target users where AD username equals target AD_no
         (or another configurable target field), then export a review CSV.
Phase 2: after manual confirmation, re-run with --execute and --confirmed-file
         to migrate grants only for the confirmed rows.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Any

from atrust_feishu_resource_sync import (
    ATrustClient,
    discover_ad_user_grants,
    normalize_value,
    output_reports,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demo: migrate grants from AD users to target users after AD_no matching."
    )
    parser.add_argument("--base-url", required=True, help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", required=True, help="OpenAPI API ID")
    parser.add_argument("--api-secret", required=True, help="OpenAPI API secret")
    parser.add_argument("--source-domain", required=True, help="AD user directory domain")
    parser.add_argument("--target-domain", required=True, help="Paeira/Para SSO user directory domain")
    parser.add_argument("--source-field", default="name", help="AD field used as the username source. Default: name")
    parser.add_argument(
        "--target-field",
        default="AD_no",
        help="Target user field used to compare with the AD username. Default: AD_no",
    )
    parser.add_argument(
        "--confirmed-file",
        help="UTF-8 CSV from the review step containing rows to migrate. Required with --execute.",
    )
    parser.add_argument(
        "--skip-resource-groups",
        action="store_true",
        help="Only copy application grants, not application category grants.",
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Only copy grants directly assigned to source users. Role-derived grants are included by default.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually assign resources to target users. Without this flag the script only reports changes.",
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
        default=8.0,
        help="Maximum aTrust API request rate. Default: 8.",
    )
    parser.add_argument("--output-dir", default="output-ad-to-para-demo", help="Directory for CSV reports.")
    return parser.parse_args()


def get_field(user: dict[str, Any], field: str) -> str:
    return normalize_value(field, user.get(field))


def match_by_fields(
    source_users: list[dict[str, Any]],
    target_users: list[dict[str, Any]],
    source_field: str,
    target_field: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    target_index: dict[str, list[dict[str, Any]]] = {}
    for user in target_users:
        key = get_field(user, target_field)
        if not key:
            continue
        target_index.setdefault(key, []).append(user)

    matches: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []

    for source_user in source_users:
        key = get_field(source_user, source_field)
        if not key:
            unmatched.append(source_user)
            continue
        candidates = target_index.get(key, [])
        if len(candidates) == 1:
            matches.append(
                {
                    "source_user": source_user,
                    "target_user": candidates[0],
                    "match_value": key,
                }
            )
        elif len(candidates) > 1:
            row = dict(source_user)
            row["_reason"] = "duplicate_target_match"
            row["_duplicate_keys"] = f"{target_field}={key}"
            ambiguous.append(row)
        else:
            unmatched.append(source_user)
    return matches, unmatched, ambiguous


def read_confirmed_file(path: str) -> set[str]:
    confirmed: set[str] = set()
    with Path(path).open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            source_id = str(row.get("source_id") or "").strip()
            if source_id:
                confirmed.add(source_id)
    return confirmed


def main() -> int:
    args = parse_args()

    if args.execute and not args.confirmed_file:
        print("--confirmed-file is required when using --execute.", file=sys.stderr)
        return 2

    client = ATrustClient(
        args.base_url,
        args.api_id,
        args.api_secret,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        max_ops_per_second=args.max_ops_per_second,
    )

    print("Querying source users (AD)...")
    source_users = client.query_users(args.source_domain)
    print(f"Source users: {len(source_users)}")

    print("Querying target users (Paeira)...")
    target_users = client.query_users(args.target_domain)
    print(f"Target users: {len(target_users)}")

    matches, unmatched, ambiguous = match_by_fields(
        source_users,
        target_users,
        args.source_field,
        args.target_field,
    )
    print(f"Matched: {len(matches)}, unmatched: {len(unmatched)}, ambiguous: {len(ambiguous)}")

    confirmed_source_ids: set[str] | None = None
    if args.execute:
        confirmed_source_ids = read_confirmed_file(args.confirmed_file)
        print(f"Confirmed rows loaded: {len(confirmed_source_ids)}")

    copied_rows: list[dict[str, Any]] = []
    failed_rows: list[dict[str, Any]] = []

    eligible_matches = matches
    if confirmed_source_ids is not None:
        eligible_matches = [
            row for row in matches if str(row["source_user"].get("id")) in confirmed_source_ids
        ]

    print("Discovering source user resource grants...")
    grants_by_source_user = discover_ad_user_grants(
        client,
        [row["source_user"] for row in eligible_matches],
        include_groups=not args.skip_resource_groups,
        include_roles=not args.direct_only,
        resource_ids=None,
        group_ids=None,
    )

    matches_by_source_id = {str(row["source_user"].get("id")): row for row in eligible_matches}
    for source_user_id, grants in grants_by_source_user.items():
        match = matches_by_source_id.get(source_user_id)
        if not match or not grants:
            continue
        try:
            if args.execute:
                client.assign_to_user_by_id(
                    args.target_domain,
                    str(match["target_user"]["id"]),
                    grants,
                )
            status = "assigned" if args.execute else "dry_run"
            for grant in grants:
                copied_rows.append(
                    {
                        "status": status,
                        "source_id": match["source_user"].get("id"),
                        "source_name": match["source_user"].get("name"),
                        "target_user_id": match["target_user"].get("id"),
                        "target_user_name": match["target_user"].get("name"),
                        "kind": grant.kind,
                        "resource_id": grant.resource_id,
                        "resource_name": grant.resource_name,
                        "source_type": grant.source_type,
                        "source_id_grant": grant.source_id,
                        "source_name_grant": grant.source_name,
                        "effectiveTime": grant.effective_time or "",
                        "expireTime": grant.expire_time or "",
                    }
                )
        except Exception as exc:  # noqa: BLE001 - report and continue.
            failed_rows.append(
                {
                    "source_id": match["source_user"].get("id"),
                    "source_name": match["source_user"].get("name"),
                    "target_user_id": match["target_user"].get("id"),
                    "target_user_name": match["target_user"].get("name"),
                    "error": str(exc),
                }
            )

    review_rows = [
        {
            "source_id": row["source_user"].get("id"),
            "source_name": row["source_user"].get("name"),
            "source_displayName": row["source_user"].get("displayName"),
            "source_field": args.source_field,
            "source_value": row["source_user"].get(args.source_field),
            "target_user_id": row["target_user"].get("id"),
            "target_user_name": row["target_user"].get("name"),
            "target_displayName": row["target_user"].get("displayName"),
            "target_field": args.target_field,
            "target_value": row["target_user"].get(args.target_field),
            "match_value": row["match_value"],
        }
        for row in matches
    ]

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "review_matches.csv").open("w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "source_id",
                "source_name",
                "source_displayName",
                "source_field",
                "source_value",
                "target_user_id",
                "target_user_name",
                "target_displayName",
                "target_field",
                "target_value",
                "match_value",
            ],
        )
        writer.writeheader()
        writer.writerows(review_rows)

    output_reports(
        output_dir,
        matches=[],
        unmatched=unmatched,
        ambiguous=ambiguous,
        copied_rows=copied_rows,
        failed_rows=failed_rows,
    )

    print(f"Review rows written to: {(output_dir / 'review_matches.csv').resolve()}")
    print(f"Grant rows {'assigned' if args.execute else 'planned'}: {len(copied_rows)}")
    print(f"Failed user assignments: {len(failed_rows)}")
    print(f"Reports written to: {output_dir.resolve()}")
    if not args.execute:
        print("Dry-run only. Review review_matches.csv, then re-run with --execute --confirmed-file ...")
    return 0 if not failed_rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
