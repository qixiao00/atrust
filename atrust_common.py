#!/usr/bin/env python3
"""Shared aTrust OpenAPI helpers for the AD-to-Feishu migration scripts."""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import ssl
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


PAGE_SIZE = 5000
DEFAULT_CONFIG_FILE = "atrust_feishu_config.json"
DEFAULT_ORG_ENTITY_TYPES = ["department", "dept", "org", "organization"]
DEFAULT_ORG_USER_FIELDS = [
    "departmentId",
    "department_id",
    "deptId",
    "dept_id",
    "orgId",
    "org_id",
    "organizationId",
    "organization_id",
    "ouId",
    "ou_id",
    "departmentIdList",
    "deptIdList",
    "orgIdList",
    "organizationIdList",
    "departments",
    "departmentList",
    "deptList",
    "orgList",
    "organizationList",
]


@dataclass(frozen=True)
class ResourceGrant:
    kind: str
    resource_id: str
    resource_name: str
    source_type: str
    source_id: str
    source_name: str
    effective_time: str | None = None
    expire_time: str | None = None


@dataclass(frozen=True)
class UserPair:
    ad_user: dict[str, Any]
    feishu_user: dict[str, Any]
    match_value: str
    match_target_field: str


def compact_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def normalize_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def as_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def load_config(path: str = DEFAULT_CONFIG_FILE) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8-sig") as fp:
        data = json.load(fp)
    if not isinstance(data, dict):
        raise ValueError(f"Config must be a JSON object: {path}")
    return data


def config_value(args: Any, config: dict[str, Any], attr: str, key: str | None = None, default: Any = None) -> Any:
    cli_value = getattr(args, attr, None)
    if cli_value is not None:
        return cli_value
    value = config.get(key or attr)
    return default if value is None else value


def require_config_values(args: Any) -> bool:
    required = [
        ("base_url", "--base-url"),
        ("api_id", "--api-id"),
        ("api_secret", "--api-secret"),
        ("ad_domain", "--ad-domain"),
        ("feishu_domain", "--feishu-domain"),
    ]
    missing = [option for attr, option in required if not getattr(args, attr, None)]
    for option in missing:
        print(f"{option} is required unless set in --config.")
    return not missing


def apply_config(args: Any) -> Any:
    config = load_config(args.config)
    args.base_url = config_value(args, config, "base_url")
    args.api_id = config_value(args, config, "api_id")
    args.api_secret = config_value(args, config, "api_secret")
    args.ad_domain = config_value(args, config, "ad_domain")
    args.feishu_domain = config_value(args, config, "feishu_domain")
    args.insecure = bool(getattr(args, "insecure", False) or config.get("insecure", False))
    args.max_ops_per_second = config_value(
        args,
        config,
        "max_ops_per_second",
        default=8.0,
    )
    return args


def extract_data_list(payload: dict[str, Any]) -> list[dict[str, Any]]:
    data = payload.get("data", {})
    if isinstance(data, dict):
        items = data.get("data", [])
        if isinstance(items, list):
            return items
    return []


def page_count(payload: dict[str, Any]) -> int:
    data = payload.get("data", {})
    if isinstance(data, dict):
        try:
            return int(data.get("pageCount") or 1)
        except (TypeError, ValueError):
            return 1
    return 1


class ATrustClient:
    def __init__(
        self,
        base_url: str,
        api_id: str,
        api_secret: str,
        *,
        timeout: int = 30,
        verify_tls: bool = True,
        lang: str = "zh-CN",
        max_ops_per_second: float = 8.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_id = api_id
        self.api_secret = api_secret
        self.timeout = timeout
        self.lang = lang
        self.ssl_context = None if verify_tls else ssl._create_unverified_context()
        self._min_request_interval = 1.0 / max_ops_per_second if max_ops_per_second > 0 else 0.0
        self._next_request_at = 0.0

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        query = {k: v for k, v in (query or {}).items() if v is not None}
        if self.lang and "lang" not in query:
            query["lang"] = self.lang

        body_text = compact_json(body) if body is not None else ""
        body_bytes = body_text.encode("utf-8") if body is not None else b""
        self._throttle()

        query_text = urlencode(sorted(query.items()), doseq=True)
        url = f"{self.base_url}{path}"
        if query_text:
            url = f"{url}?{query_text}"

        req = Request(
            url,
            data=body_bytes or None,
            headers=self._signed_headers(path, query_text, body_text),
            method=method.upper(),
        )
        try:
            with urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {method} {path}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Request failed {method} {path}: {exc}") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Non-JSON response from {path}: {raw[:500]}") from exc
        if payload.get("code") != "OK":
            raise RuntimeError(
                f"aTrust API error on {path}: code={payload.get('code')} "
                f"msg={payload.get('msg')} traceId={payload.get('traceId')}"
            )
        return payload

    def _throttle(self) -> None:
        if self._min_request_interval <= 0:
            return
        now = time.monotonic()
        if self._next_request_at > now:
            time.sleep(self._next_request_at - now)
        self._next_request_at = max(now, self._next_request_at) + self._min_request_interval

    def _signed_headers(self, path: str, query_text: str, body_text: str) -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())
        sign_key = (
            f"appId={self.api_id}&appSecret={self.api_secret}"
            f"&timestamp={timestamp}&nonce={nonce}"
        )

        sign_string = path
        if query_text and body_text:
            sign_string = f"{path}?{query_text}&{body_text}"
        elif query_text:
            sign_string = f"{path}?{query_text}"
        elif body_text:
            sign_string = f"{path}?{body_text}"

        signature = hmac.new(
            sign_key.encode("utf-8"),
            sign_string.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {
            "Content-Type": "application/json;charset=UTF-8",
            "X-Ca-Key": self.api_id,
            "X-Ca-TimeStamp": timestamp,
            "X-Ca-Nonce": nonce,
            "X-Ca-Sign": signature,
        }

    def query_users(self, directory_domain: str) -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []
        page_index = 1
        while True:
            payload = self.request(
                "POST",
                "/api/v3/user/queryAll",
                body={
                    "directoryDomain": directory_domain,
                    "pageSize": PAGE_SIZE,
                    "pageIndex": page_index,
                },
            )
            users.extend(extract_data_list(payload))
            if page_index >= page_count(payload):
                return users
            page_index += 1

    def query_resources(self) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        page_index = 1
        while True:
            payload = self.request(
                "GET",
                "/api/v3/resource/queryAll",
                query={"pageSize": PAGE_SIZE, "pageIndex": page_index, "isPaged": 1},
            )
            resources.extend(extract_data_list(payload))
            if page_index >= page_count(payload):
                return resources
            page_index += 1

    def query_resource_groups(self) -> list[dict[str, Any]]:
        payload = self.request("GET", "/api/v3/resourceGroup/queryAll", query={"asc": 1})
        data = payload.get("data", {})
        groups = data.get("resourceGroup", []) if isinstance(data, dict) else []
        return groups if isinstance(groups, list) else []

    def query_assignments(self, path: str, resource_id: str, entity_types: list[str]) -> list[dict[str, Any]]:
        assignments: list[dict[str, Any]] = []
        page_index = 1
        while True:
            payload = self.request(
                "POST",
                path,
                body={
                    "id": resource_id,
                    "fieldMode": "all",
                    "sortBy": "default",
                    "entityType": entity_types,
                    "pageSize": PAGE_SIZE,
                    "pageIndex": page_index,
                },
            )
            assignments.extend(extract_data_list(payload))
            if page_index >= page_count(payload):
                return assignments
            page_index += 1

    def assign_to_user_by_id(self, directory_domain: str, user_id: str, grants: list[ResourceGrant]) -> None:
        resource_data = [grant_payload(grant) for grant in grants if grant.kind == "resource"]
        group_data = [grant_payload(grant) for grant in grants if grant.kind == "resourceGroup"]
        body: dict[str, Any] = {"directoryDomain": directory_domain, "id": user_id}
        if resource_data:
            body["resource"] = {"op": "append", "key": "id", "data": resource_data}
        if group_data:
            body["resourceGroup"] = {"op": "append", "key": "id", "data": group_data}
        if len(body) > 2:
            self.request("POST", "/api/v3/user/assignResourceById", body=body)


def grant_payload(grant: ResourceGrant) -> dict[str, str]:
    payload = {"data": grant.resource_id}
    if grant.effective_time and grant.effective_time != "0":
        payload["effectiveTime"] = grant.effective_time
    if grant.expire_time and grant.expire_time != "0":
        payload["expireTime"] = grant.expire_time
    return payload


def parse_id_file(path: str | None) -> set[str] | None:
    if not path:
        return None
    values: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            values.add(value)
    return values


def parse_csv_arg(value: str | None, default: list[str]) -> list[str]:
    if value is None:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as fp:
        return list(csv.DictReader(fp))


def index_unique_users(
    users: list[dict[str, Any]],
    field: str,
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    index: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    counts: dict[str, int] = defaultdict(int)
    for user in users:
        value = normalize_value(user.get(field))
        if not value:
            continue
        counts[value] += 1
        index.setdefault(value, user)
    for value, count in counts.items():
        if count > 1:
            duplicates.add(value)
    return index, duplicates


def collect_identity_values(value: Any) -> set[str]:
    values: set[str] = set()
    if value is None:
        return values
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        if text:
            values.add(text)
        return values
    if isinstance(value, dict):
        for key in (
            "id",
            "value",
            "departmentId",
            "department_id",
            "deptId",
            "dept_id",
            "orgId",
            "org_id",
            "organizationId",
            "organization_id",
            "ouId",
            "ou_id",
        ):
            values.update(collect_identity_values(value.get(key)))
        return values
    if isinstance(value, list):
        for item in value:
            values.update(collect_identity_values(item))
        return values
    return values


def build_org_to_users(
    users: list[dict[str, Any]],
    org_user_fields: list[str],
) -> dict[str, list[dict[str, Any]]]:
    org_to_users: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for user in users:
        seen_values: set[str] = set()
        for field in org_user_fields:
            seen_values.update(collect_identity_values(user.get(field)))
        for value in seen_values:
            org_to_users[value].append(user)
    return org_to_users


def match_ad_description_to_feishu_identifiers(
    ad_users: list[dict[str, Any]],
    feishu_users: list[dict[str, Any]],
    feishu_fields: list[str] | None = None,
) -> tuple[list[UserPair], list[dict[str, Any]], list[dict[str, Any]]]:
    fields = feishu_fields or ["user_id", "use_id", "externalId", "external_id"]
    indexes: dict[str, dict[str, dict[str, Any]]] = {}
    duplicates_by_field: dict[str, set[str]] = {}
    for field in fields:
        indexes[field], duplicates_by_field[field] = index_unique_users(feishu_users, field)

    pairs: list[UserPair] = []
    unmatched: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    used_feishu_ids: set[str] = set()

    for ad_user in ad_users:
        value = normalize_value(ad_user.get("description"))
        if not value:
            row = dict(ad_user)
            row["_reason"] = "empty_ad_description"
            unmatched.append(row)
            continue

        duplicate_fields = [field for field in fields if value in duplicates_by_field[field]]
        if duplicate_fields:
            row = dict(ad_user)
            row["_reason"] = "duplicate_feishu_identifier"
            row["_duplicate_keys"] = ";".join(f"{field}={value}" for field in duplicate_fields)
            ambiguous.append(row)
            continue

        feishu_user: dict[str, Any] | None = None
        matched_field = ""
        for field in fields:
            candidate = indexes[field].get(value)
            if candidate:
                feishu_user = candidate
                matched_field = field
                break
        if not feishu_user:
            row = dict(ad_user)
            row["_reason"] = "no_feishu_identifier_match"
            row["_checked_fields"] = ",".join(fields)
            unmatched.append(row)
            continue

        feishu_id = str(feishu_user.get("id") or "")
        if feishu_id in used_feishu_ids:
            row = dict(ad_user)
            row["_reason"] = "duplicate_ad_match_to_same_feishu_user"
            row["_duplicate_keys"] = f"{matched_field}={value}"
            ambiguous.append(row)
            continue
        used_feishu_ids.add(feishu_id)
        pairs.append(
            UserPair(
                ad_user=ad_user,
                feishu_user=feishu_user,
                match_value=value,
                match_target_field=matched_field,
            )
        )
    return pairs, unmatched, ambiguous


def match_by_description(
    ad_users: list[dict[str, Any]],
    feishu_users: list[dict[str, Any]],
) -> tuple[list[UserPair], list[dict[str, Any]], list[dict[str, Any]]]:
    return match_ad_description_to_feishu_identifiers(ad_users, feishu_users)


def discover_user_grants(
    client: ATrustClient,
    ad_users: list[dict[str, Any]],
    *,
    include_groups: bool,
    include_roles: bool,
    resource_ids: set[str] | None,
    group_ids: set[str] | None,
    include_orgs: bool = True,
    org_entity_types: list[str] | None = None,
    org_user_fields: list[str] | None = None,
    stop_after_users: int | None = None,
) -> dict[str, list[ResourceGrant]]:
    grants_by_user: dict[str, list[ResourceGrant]] = defaultdict(list)
    seen: set[tuple[str, str, str]] = set()
    ad_user_ids = {str(user.get("id")) for user in ad_users if user.get("id")}
    role_to_users: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if include_roles:
        for user in ad_users:
            for role_id in user.get("roleIdList") or []:
                role_to_users[str(role_id)].append(user)

    entity_types = ["user", "band"] if include_roles else ["user"]
    org_types = org_entity_types or DEFAULT_ORG_ENTITY_TYPES
    org_to_users: dict[str, list[dict[str, Any]]] = {}
    if include_orgs:
        entity_types.extend(org_types)
        org_to_users = build_org_to_users(ad_users, org_user_fields or DEFAULT_ORG_USER_FIELDS)

    base_entity_types = ["user", "band"] if include_roles else ["user"]
    warned_org_entity_type_failure = False

    def query_assignments_safely(path: str, rid: str) -> list[dict[str, Any]]:
        nonlocal warned_org_entity_type_failure
        try:
            return client.query_assignments(path, rid, entity_types)
        except RuntimeError:
            if not include_orgs:
                raise
            if not warned_org_entity_type_failure:
                print(
                    "Warning: aTrust rejected the configured AD organization entity types; "
                    "retrying with user/band only. Use --org-entity-types to set the actual AD values."
                )
                warned_org_entity_type_failure = True
            return client.query_assignments(path, rid, base_entity_types)

    resources = client.query_resources()
    if resource_ids is not None:
        resources = [r for r in resources if str(r.get("id")) in resource_ids]
    for resource in resources:
        rid = str(resource.get("id") or "")
        if not rid:
            continue
        assignments = query_assignments_safely("/api/v3/resourceAssign/queryById", rid)
        for assignment in assignments:
            append_assignment_grant(
                grants_by_user,
                seen,
                assignment,
                kind="resource",
                resource_id=rid,
                resource_name=str(resource.get("name") or ""),
                ad_user_ids=ad_user_ids,
                role_to_users=role_to_users,
                org_to_users=org_to_users,
                org_entity_types=set(org_types),
            )
            if stop_after_users and len(grants_by_user) >= stop_after_users:
                return grants_by_user

    if include_groups:
        groups = client.query_resource_groups()
        if group_ids is not None:
            groups = [g for g in groups if str(g.get("id")) in group_ids]
        for group in groups:
            gid = str(group.get("id") or "")
            if not gid:
                continue
            assignments = query_assignments_safely("/api/v3/resourceGroupAssign/queryById", gid)
            for assignment in assignments:
                append_assignment_grant(
                    grants_by_user,
                    seen,
                    assignment,
                    kind="resourceGroup",
                    resource_id=gid,
                    resource_name=str(group.get("name") or ""),
                    ad_user_ids=ad_user_ids,
                    role_to_users=role_to_users,
                    org_to_users=org_to_users,
                    org_entity_types=set(org_types),
                )
                if stop_after_users and len(grants_by_user) >= stop_after_users:
                    return grants_by_user
    return grants_by_user


def append_assignment_grant(
    grants_by_user: dict[str, list[ResourceGrant]],
    seen: set[tuple[str, str, str]],
    assignment: dict[str, Any],
    *,
    kind: str,
    resource_id: str,
    resource_name: str,
    ad_user_ids: set[str],
    role_to_users: dict[str, list[dict[str, Any]]],
    org_to_users: dict[str, list[dict[str, Any]]],
    org_entity_types: set[str],
) -> None:
    source_id = str(assignment.get("id") or "")
    entity_type = str(assignment.get("entityType") or "")
    if entity_type == "user":
        target_user_ids = [source_id] if source_id in ad_user_ids else []
    elif entity_type == "band":
        target_user_ids = [str(user.get("id")) for user in role_to_users.get(source_id, []) if user.get("id")]
    elif entity_type in org_entity_types:
        target_user_ids = [str(user.get("id")) for user in org_to_users.get(source_id, []) if user.get("id")]
    else:
        target_user_ids = []

    for user_id in target_user_ids:
        key = (user_id, kind, resource_id)
        if key in seen:
            continue
        seen.add(key)
        grants_by_user[user_id].append(
            ResourceGrant(
                kind=kind,
                resource_id=resource_id,
                resource_name=resource_name,
                source_type=entity_type,
                source_id=source_id,
                source_name=str(assignment.get("name") or assignment.get("displayName") or ""),
                effective_time=as_optional_str(assignment.get("effectiveTime")),
                expire_time=as_optional_str(assignment.get("expireTime")),
            )
        )


def grant_from_csv_row(row: dict[str, str]) -> ResourceGrant:
    return ResourceGrant(
        kind=str(row.get("grant_kind") or ""),
        resource_id=str(row.get("resource_id") or ""),
        resource_name=str(row.get("resource_name") or ""),
        source_type=str(row.get("grant_source_type") or ""),
        source_id=str(row.get("grant_source_id") or ""),
        source_name=str(row.get("grant_source_name") or ""),
        effective_time=as_optional_str(row.get("effective_time")),
        expire_time=as_optional_str(row.get("expire_time")),
    )


def group_csv_grants_by_feishu_user(rows: list[dict[str, str]]) -> dict[str, list[ResourceGrant]]:
    grants_by_user: dict[str, list[ResourceGrant]] = defaultdict(list)
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        feishu_user_id = str(row.get("feishu_user_id") or "").strip()
        resource_id = str(row.get("resource_id") or "").strip()
        kind = str(row.get("grant_kind") or "").strip()
        if not feishu_user_id or not resource_id or not kind:
            continue
        key = (feishu_user_id, kind, resource_id)
        if key in seen:
            continue
        seen.add(key)
        grants_by_user[feishu_user_id].append(grant_from_csv_row(row))
    return grants_by_user
