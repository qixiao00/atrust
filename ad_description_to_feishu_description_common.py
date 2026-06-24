"""Shared helpers for AD description -> Feishu description migration scripts."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from atrust_feishu_resource_sync import ResourceGrant, UserMatch, normalize_value

AD_MATCH_FIELD = "description"
FEISHU_MATCH_FIELD = "description"
DEFAULT_CONFIG_FILE = "atrust_feishu_config.json"

GRANT_DETAIL_COLUMNS = [
    "ad_user_id",
    "ad_user_name",
    "ad_displayName",
    "ad_description",
    "feishu_user_id",
    "feishu_user_name",
    "feishu_displayName",
    "feishu_description",
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

ASSIGNMENT_REPORT_COLUMNS = [
    "status",
    "ad_user_id",
    "ad_user_name",
    "ad_description",
    "feishu_user_id",
    "feishu_user_name",
    "feishu_description",
    "kind",
    "resource_id",
    "resource_name",
    "source_type",
    "source_id",
    "source_name",
    "effectiveTime",
    "expireTime",
]

FAILED_REPORT_COLUMNS = [
    "ad_user_id",
    "ad_user_name",
    "ad_description",
    "feishu_user_id",
    "feishu_user_name",
    "feishu_description",
    "error",
]


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


def add_common_args(parser: argparse.ArgumentParser, *, default_output_dir: str) -> None:
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="JSON config file path.")
    parser.add_argument("--base-url", help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", help="OpenAPI API ID")
    parser.add_argument("--api-secret", help="OpenAPI API secret")
    parser.add_argument("--ad-domain", help="AD user directory domain")
    parser.add_argument("--feishu-domain", help="Feishu user directory domain")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--max-ops-per-second",
        type=float,
        default=None,
        help="Maximum aTrust API request rate. Default: 8.",
    )
    parser.add_argument("--output-dir", default=default_output_dir, help="Directory for this script's outputs.")


def apply_config(args: argparse.Namespace) -> argparse.Namespace:
    config = load_config(args.config)
    args.base_url = coalesce(args.base_url, config, "base_url")
    args.api_id = coalesce(args.api_id, config, "api_id")
    args.api_secret = coalesce(args.api_secret, config, "api_secret")
    args.ad_domain = coalesce(args.ad_domain, config, "ad_domain")
    args.feishu_domain = coalesce(args.feishu_domain, config, "feishu_domain")
    args.insecure = args.insecure or bool(config.get("insecure", False))
    args.max_ops_per_second = coalesce(args.max_ops_per_second, config, "max_ops_per_second", 8.0)
    return args


def missing_required_options(args: argparse.Namespace) -> list[str]:
    required = [
        ("base_url", "--base-url"),
        ("api_id", "--api-id"),
        ("api_secret", "--api-secret"),
        ("ad_domain", "--ad-domain"),
        ("feishu_domain", "--feishu-domain"),
    ]
    return [option for attr, option in required if not getattr(args, attr)]


def build_grant_detail_rows(
    matches: list[UserMatch],
    grants_by_ad_user: dict[str, list[ResourceGrant]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for match in matches:
        ad_user_id = str(match.ad_user.get("id") or "")
        for grant in grants_by_ad_user.get(ad_user_id, []):
            rows.append(
                {
                    "ad_user_id": match.ad_user.get("id"),
                    "ad_user_name": match.ad_user.get("name"),
                    "ad_displayName": match.ad_user.get("displayName"),
                    "ad_description": match.ad_user.get(AD_MATCH_FIELD),
                    "feishu_user_id": match.feishu_user.get("id"),
                    "feishu_user_name": match.feishu_user.get("name"),
                    "feishu_displayName": match.feishu_user.get("displayName"),
                    "feishu_description": match.feishu_user.get(FEISHU_MATCH_FIELD),
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


def read_grant_detail_csv(path: str) -> dict[str, dict[str, Any]]:
    users: dict[str, dict[str, Any]] = {}
    with Path(path).open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            feishu_user_id = str(row.get("feishu_user_id") or "").strip()
            resource_id = str(row.get("resource_id") or "").strip()
            kind = str(row.get("kind") or "").strip()
            if not feishu_user_id or not resource_id or not kind:
                continue
            user = users.setdefault(
                feishu_user_id,
                {
                    "ad_user_id": str(row.get("ad_user_id") or ""),
                    "ad_user_name": str(row.get("ad_user_name") or ""),
                    "ad_description": str(row.get("ad_description") or ""),
                    "feishu_user_id": feishu_user_id,
                    "feishu_user_name": str(row.get("feishu_user_name") or ""),
                    "feishu_description": str(row.get("feishu_description") or ""),
                    "grants": [],
                },
            )
            user["grants"].append(
                ResourceGrant(
                    kind=kind,
                    resource_id=resource_id,
                    resource_name=str(row.get("resource_name") or ""),
                    source_type=str(row.get("source_type") or ""),
                    source_id=str(row.get("source_id") or ""),
                    source_name=str(row.get("source_name") or ""),
                    effective_time=as_optional_str(row.get("effectiveTime")),
                    expire_time=as_optional_str(row.get("expireTime")),
                )
            )
    return users


def as_optional_str(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def select_one_user(users_by_feishu_id: dict[str, dict[str, Any]], ad_description: str | None) -> dict[str, Any] | None:
    if ad_description:
        target = normalize_value(AD_MATCH_FIELD, ad_description)
        matches = [
            user for user in users_by_feishu_id.values() if normalize_value(AD_MATCH_FIELD, user["ad_description"]) == target
        ]
        if len(matches) != 1:
            return None
        return matches[0]
    return next(iter(users_by_feishu_id.values()), None)


def build_assignment_rows(status: str, user: dict[str, Any], grants: list[ResourceGrant]) -> list[dict[str, Any]]:
    return [
        {
            "status": status,
            "ad_user_id": user["ad_user_id"],
            "ad_user_name": user["ad_user_name"],
            "ad_description": user["ad_description"],
            "feishu_user_id": user["feishu_user_id"],
            "feishu_user_name": user["feishu_user_name"],
            "feishu_description": user["feishu_description"],
            "kind": grant.kind,
            "resource_id": grant.resource_id,
            "resource_name": grant.resource_name,
            "source_type": grant.source_type,
            "source_id": grant.source_id,
            "source_name": grant.source_name,
            "effectiveTime": grant.effective_time or "",
            "expireTime": grant.expire_time or "",
        }
        for grant in grants
    ]
