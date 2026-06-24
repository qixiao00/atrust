#!/usr/bin/env python3
"""
Copy aTrust application/resource-group authorizations from matching AD users to
Feishu users.

The script reads both user directories from aTrust, matches users by one or more
shared fields, discovers resources currently assigned to AD users, and optionally
assigns the same resources to the matching Feishu users. It runs in dry-run mode
unless --execute is passed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import ssl
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


PAGE_SIZE = 5000


def compact_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def normalize_value(field: str, value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if field.lower() in {"phone", "mobile", "mobilephone", "mobile_number"}:
        return "".join(ch for ch in text if ch.isdigit())
    return text.lower()


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


def build_http_error_message(code: int, method: str, path: str, detail: str) -> str:
    message = f"HTTP {code} {method} {path}: {detail}"
    try:
        payload = json.loads(detail)
    except json.JSONDecodeError:
        return message

    if payload.get("code") == "AuthFailed.OpenAPI":
        return (
            f"{message}\n"
            "OpenAPI authentication failed. Please check atrust_feishu_config.json: "
            "base_url must be the aTrust console scheme/host/port only, api_id and "
            "api_secret must match an enabled OpenAPI app, and the app must have "
            "permission to call this API."
        )
    return message


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
class UserMatch:
    ad_user: dict[str, Any]
    feishu_user: dict[str, Any]
    match_field: str
    match_value: str
    target_field: str | None = None


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
        self.max_ops_per_second = max_ops_per_second
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

        body_bytes = b""
        body_text = ""
        if body is not None:
            body_text = compact_json(body)
            body_bytes = body_text.encode("utf-8")

        self._throttle()

        query_text = urlencode(sorted(query.items()), doseq=True)
        url = f"{self.base_url}{path}"
        if query_text:
            url = f"{url}?{query_text}"

        headers = self._signed_headers(path, query_text, body_text)
        req = Request(url, data=body_bytes or None, headers=headers, method=method.upper())

        try:
            with urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(build_http_error_message(exc.code, method, path, detail)) from exc
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
                query={
                    "pageSize": PAGE_SIZE,
                    "pageIndex": page_index,
                    "isPaged": 1,
                },
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

    def query_assignments(
        self,
        path: str,
        resource_id: str,
        entity_types: list[str],
    ) -> list[dict[str, Any]]:
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

    def assign_to_user_by_id(
        self,
        directory_domain: str,
        user_id: str,
        grants: list[ResourceGrant],
    ) -> None:
        resource_data = [
            grant_payload(grant)
            for grant in grants
            if grant.kind == "resource"
        ]
        group_data = [
            grant_payload(grant)
            for grant in grants
            if grant.kind == "resourceGroup"
        ]
        body: dict[str, Any] = {
            "directoryDomain": directory_domain,
            "id": user_id,
        }
        if resource_data:
            body["resource"] = {"op": "append", "key": "id", "data": resource_data}
        if group_data:
            body["resourceGroup"] = {"op": "append", "key": "id", "data": group_data}
        if len(body) == 2:
            return
        self.request("POST", "/api/v3/user/assignResourceById", body=body)


def grant_payload(grant: ResourceGrant) -> dict[str, str]:
    payload = {"data": grant.resource_id}
    if grant.effective_time and grant.effective_time != "0":
        payload["effectiveTime"] = grant.effective_time
    if grant.expire_time and grant.expire_time != "0":
        payload["expireTime"] = grant.expire_time
    return payload


def build_match_index(
    users: list[dict[str, Any]],
    match_fields: list[str],
) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[tuple[str, str], int]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for user in users:
        for field in match_fields:
            value = normalize_value(field, user.get(field))
            if not value:
                continue
            key = (field, value)
            counts[key] += 1
            index.setdefault(key, user)
    return index, counts


def match_users(
    ad_users: list[dict[str, Any]],
    feishu_users: list[dict[str, Any]],
    match_fields: list[str],
) -> tuple[list[UserMatch], list[dict[str, Any]], list[dict[str, Any]]]:
    feishu_index, feishu_counts = build_match_index(feishu_users, match_fields)
    matches: list[UserMatch] = []
    unmatched: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    used_feishu_ids: set[str] = set()

    for ad_user in ad_users:
        found: UserMatch | None = None
        duplicate_keys: list[str] = []
        for field in match_fields:
            value = normalize_value(field, ad_user.get(field))
            if not value:
                continue
            key = (field, value)
            if feishu_counts.get(key, 0) > 1:
                duplicate_keys.append(f"{field}={value}")
                continue
            feishu_user = feishu_index.get(key)
            if feishu_user and str(feishu_user.get("id")) not in used_feishu_ids:
                found = UserMatch(ad_user, feishu_user, field, value)
                break
        if found:
            used_feishu_ids.add(str(found.feishu_user.get("id")))
            matches.append(found)
        elif duplicate_keys:
            row = dict(ad_user)
            row["_reason"] = "duplicate_feishu_match"
            row["_duplicate_keys"] = ";".join(duplicate_keys)
            ambiguous.append(row)
        else:
            unmatched.append(ad_user)
    return matches, unmatched, ambiguous


def match_users_by_field_pair(
    ad_users: list[dict[str, Any]],
    feishu_users: list[dict[str, Any]],
    ad_field: str,
    feishu_field: str,
) -> tuple[list[UserMatch], list[dict[str, Any]], list[dict[str, Any]]]:
    feishu_index: dict[str, dict[str, Any]] = {}
    feishu_counts: dict[str, int] = defaultdict(int)
    for feishu_user in feishu_users:
        value = normalize_value(feishu_field, feishu_user.get(feishu_field))
        if not value:
            continue
        feishu_counts[value] += 1
        feishu_index.setdefault(value, feishu_user)

    matches: list[UserMatch] = []
    unmatched: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    used_feishu_ids: set[str] = set()

    for ad_user in ad_users:
        value = normalize_value(ad_field, ad_user.get(ad_field))
        if not value:
            row = dict(ad_user)
            row["_reason"] = f"empty_ad_{ad_field}"
            unmatched.append(row)
            continue
        if feishu_counts.get(value, 0) > 1:
            row = dict(ad_user)
            row["_reason"] = "duplicate_feishu_match"
            row["_duplicate_keys"] = f"{feishu_field}={value}"
            ambiguous.append(row)
            continue
        feishu_user = feishu_index.get(value)
        if not feishu_user:
            unmatched.append(ad_user)
            continue
        feishu_id = str(feishu_user.get("id"))
        if feishu_id in used_feishu_ids:
            row = dict(ad_user)
            row["_reason"] = "duplicate_ad_match_to_same_feishu_user"
            row["_duplicate_keys"] = f"{ad_field}={value};{feishu_field}={value}"
            ambiguous.append(row)
            continue
        used_feishu_ids.add(feishu_id)
        matches.append(UserMatch(ad_user, feishu_user, ad_field, value, feishu_field))
    return matches, unmatched, ambiguous


def read_confirmed_ad_user_ids(path: str) -> set[str]:
    confirmed: set[str] = set()
    with Path(path).open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            ad_user_id = str(row.get("ad_user_id") or row.get("ad_id") or "").strip()
            if ad_user_id:
                confirmed.add(ad_user_id)
    return confirmed


def read_grant_plan(path: str) -> dict[str, list[ResourceGrant]]:
    grants_by_feishu_user: dict[str, list[ResourceGrant]] = defaultdict(list)
    with Path(path).open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            feishu_user_id = str(row.get("feishu_user_id") or "").strip()
            resource_id = str(row.get("resource_id") or "").strip()
            kind = str(row.get("kind") or "").strip()
            if not feishu_user_id or not resource_id or not kind:
                continue
            grants_by_feishu_user[feishu_user_id].append(
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
    return grants_by_feishu_user


def read_confirmed_assignments(path: str) -> dict[str, dict[str, str]]:
    assignments: dict[str, dict[str, str]] = {}
    with Path(path).open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            ad_user_id = str(row.get("ad_user_id") or row.get("ad_id") or "").strip()
            feishu_user_id = str(row.get("feishu_user_id") or row.get("feishu_id") or "").strip()
            if not ad_user_id or not feishu_user_id:
                continue
            assignments[ad_user_id] = {
                "ad_user_id": ad_user_id,
                "ad_user_name": str(row.get("ad_user_name") or row.get("ad_name") or ""),
                "feishu_user_id": feishu_user_id,
                "feishu_user_name": str(row.get("feishu_user_name") or row.get("feishu_name") or ""),
            }
    return assignments


def execute_from_plan(
    client: ATrustClient,
    feishu_domain: str,
    confirmed_file: str,
    planned_grants_file: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    confirmed_assignments = read_confirmed_assignments(confirmed_file)
    grants_by_feishu_user = read_grant_plan(planned_grants_file)
    copied_rows: list[dict[str, Any]] = []
    failed_rows: list[dict[str, Any]] = []

    for row in confirmed_assignments.values():
        grants = grants_by_feishu_user.get(row["feishu_user_id"], [])
        if not grants:
            continue
        try:
            client.assign_to_user_by_id(feishu_domain, row["feishu_user_id"], grants)
            for grant in grants:
                copied_rows.append(
                    {
                        "status": "assigned",
                        "ad_user_id": row["ad_user_id"],
                        "ad_user_name": row["ad_user_name"],
                        "feishu_user_id": row["feishu_user_id"],
                        "feishu_user_name": row["feishu_user_name"],
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
        except Exception as exc:  # noqa: BLE001 - report and continue with other users.
            failed_rows.append(
                {
                    "ad_user_id": row["ad_user_id"],
                    "ad_user_name": row["ad_user_name"],
                    "feishu_user_id": row["feishu_user_id"],
                    "feishu_user_name": row["feishu_user_name"],
                    "error": str(exc),
                }
            )
    return copied_rows, failed_rows


def build_reassociate_user_rows(
    matches: list[UserMatch],
    grants_by_ad_user: dict[str, list[ResourceGrant]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for match in matches:
        ad_user_id = str(match.ad_user.get("id") or "")
        grants = grants_by_ad_user.get(ad_user_id, [])
        if not grants:
            continue
        resource_count = sum(1 for grant in grants if grant.kind == "resource")
        group_count = sum(1 for grant in grants if grant.kind == "resourceGroup")
        rows.append(
            {
                "ad_user_id": match.ad_user.get("id"),
                "ad_user_name": match.ad_user.get("name"),
                "ad_displayName": match.ad_user.get("displayName"),
                "ad_description": match.ad_user.get("description"),
                "feishu_user_id": match.feishu_user.get("id"),
                "feishu_user_name": match.feishu_user.get("name"),
                "feishu_displayName": match.feishu_user.get("displayName"),
                "feishu_user_id_field": match.feishu_user.get(match.target_field or "user_id"),
                "match_field": match.match_field,
                "target_field": match.target_field or match.match_field,
                "match_value": match.match_value,
                "grant_count": len(grants),
                "resource_count": resource_count,
                "resource_group_count": group_count,
            }
        )
    return rows


def discover_ad_user_grants(
    client: ATrustClient,
    matched_ad_users: list[dict[str, Any]],
    *,
    include_groups: bool,
    include_roles: bool,
    resource_ids: set[str] | None,
    group_ids: set[str] | None,
) -> dict[str, list[ResourceGrant]]:
    grants_by_ad_user: dict[str, list[ResourceGrant]] = defaultdict(list)
    seen: set[tuple[str, str, str]] = set()
    ad_user_ids = {str(user.get("id")) for user in matched_ad_users if user.get("id")}
    role_to_ad_users: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if include_roles:
        for user in matched_ad_users:
            for role_id in user.get("roleIdList") or []:
                role_to_ad_users[str(role_id)].append(user)

    entity_types = ["user", "band"] if include_roles else ["user"]

    resources = client.query_resources()
    if resource_ids is not None:
        resources = [r for r in resources if str(r.get("id")) in resource_ids]

    for resource in resources:
        rid = str(resource.get("id") or "")
        if not rid:
            continue
        assignments = client.query_assignments(
            "/api/v3/resourceAssign/queryById",
            rid,
            entity_types,
        )
        for assignment in assignments:
            append_assignment_grants(
                grants_by_ad_user,
                seen,
                assignment,
                kind="resource",
                resource_id=rid,
                resource_name=str(resource.get("name") or ""),
                ad_user_ids=ad_user_ids,
                role_to_ad_users=role_to_ad_users,
            )

    if include_groups:
        groups = client.query_resource_groups()
        if group_ids is not None:
            groups = [g for g in groups if str(g.get("id")) in group_ids]
        for group in groups:
            gid = str(group.get("id") or "")
            if not gid:
                continue
            assignments = client.query_assignments(
                "/api/v3/resourceGroupAssign/queryById",
                gid,
                entity_types,
            )
            for assignment in assignments:
                append_assignment_grants(
                    grants_by_ad_user,
                    seen,
                    assignment,
                    kind="resourceGroup",
                    resource_id=gid,
                    resource_name=str(group.get("name") or ""),
                    ad_user_ids=ad_user_ids,
                    role_to_ad_users=role_to_ad_users,
                )
    return grants_by_ad_user


def append_assignment_grants(
    grants_by_ad_user: dict[str, list[ResourceGrant]],
    seen: set[tuple[str, str, str]],
    assignment: dict[str, Any],
    *,
    kind: str,
    resource_id: str,
    resource_name: str,
    ad_user_ids: set[str],
    role_to_ad_users: dict[str, list[dict[str, Any]]],
) -> None:
    source_id = str(assignment.get("id") or "")
    entity_type = str(assignment.get("entityType") or "")
    if entity_type == "user":
        target_user_ids = [source_id] if source_id in ad_user_ids else []
    elif entity_type == "band":
        target_user_ids = [
            str(user.get("id"))
            for user in role_to_ad_users.get(source_id, [])
            if user.get("id")
        ]
    else:
        target_user_ids = []

    for ad_user_id in target_user_ids:
        key = (ad_user_id, kind, resource_id)
        if key in seen:
            continue
        seen.add(key)
        grants_by_ad_user[ad_user_id].append(
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


def as_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_id_file(path: str | None) -> set[str] | None:
    if not path:
        return None
    values: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            values.add(value)
    return values


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def output_reports(
    output_dir: Path,
    matches: list[UserMatch],
    unmatched: list[dict[str, Any]],
    ambiguous: list[dict[str, Any]],
    copied_rows: list[dict[str, Any]],
    failed_rows: list[dict[str, Any]],
    reassociate_user_rows: list[dict[str, Any]] | None = None,
) -> None:
    write_csv(
        output_dir / "matched_users.csv",
        [
            {
                "ad_id": m.ad_user.get("id"),
                "ad_name": m.ad_user.get("name"),
                "ad_displayName": m.ad_user.get("displayName"),
                "feishu_id": m.feishu_user.get("id"),
                "feishu_name": m.feishu_user.get("name"),
                "feishu_displayName": m.feishu_user.get("displayName"),
                "match_field": m.match_field,
                "target_field": m.target_field or m.match_field,
                "match_value": m.match_value,
            }
            for m in matches
        ],
        [
            "ad_id",
            "ad_name",
            "ad_displayName",
            "feishu_id",
            "feishu_name",
            "feishu_displayName",
            "match_field",
            "target_field",
            "match_value",
        ],
    )
    write_csv(
        output_dir / "unmatched_ad_users.csv",
        [
            {
                "id": u.get("id"),
                "name": u.get("name"),
                "displayName": u.get("displayName"),
                "externalId": u.get("externalId"),
                "phone": u.get("phone"),
                "email": u.get("email"),
                "description": u.get("description"),
            }
            for u in unmatched
        ],
        ["id", "name", "displayName", "externalId", "phone", "email", "description"],
    )
    write_csv(
        output_dir / "ambiguous_ad_users.csv",
        [
            {
                "id": u.get("id"),
                "name": u.get("name"),
                "displayName": u.get("displayName"),
                "externalId": u.get("externalId"),
                "phone": u.get("phone"),
                "email": u.get("email"),
                "reason": u.get("_reason"),
                "duplicate_keys": u.get("_duplicate_keys"),
            }
            for u in ambiguous
        ],
        [
            "id",
            "name",
            "displayName",
            "externalId",
            "phone",
            "email",
            "reason",
            "duplicate_keys",
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
    write_csv(
        output_dir / "reassociate_users.csv",
        reassociate_user_rows or [],
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Copy aTrust resource grants from AD users to matching Feishu users."
    )
    parser.add_argument("--base-url", required=True, help="aTrust base URL, for example https://1.1.1.1:4433")
    parser.add_argument("--api-id", required=True, help="OpenAPI API ID")
    parser.add_argument("--api-secret", required=True, help="OpenAPI API secret")
    parser.add_argument("--ad-domain", required=True, help="AD user directory domain, for example custom01339")
    parser.add_argument("--feishu-domain", required=True, help="Feishu user directory domain")
    parser.add_argument(
        "--match-fields",
        default="",
        help="Comma-separated user fields used in order. Example: externalId,phone,email,name",
    )
    parser.add_argument(
        "--ad-match-field",
        default="description",
        help="AD user field used to match Feishu users. Default: description.",
    )
    parser.add_argument(
        "--feishu-match-field",
        default="user_id",
        help="Feishu user field used to match AD users. Default: user_id.",
    )
    parser.add_argument(
        "--confirmed-file",
        help="CSV user confirmation file. With --execute, defaults to <output-dir>/reassociate_users.csv.",
    )
    parser.add_argument(
        "--planned-grants-file",
        help="CSV grant plan file from dry-run. With --execute, defaults to <output-dir>/copied_grants.csv.",
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
        help="Actually assign resources to Feishu users. Without this flag the script only reports changes.",
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
    parser.add_argument("--output-dir", default="output", help="Directory for CSV reports.")
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
        max_ops_per_second=args.max_ops_per_second,
    )

    output_dir = Path(args.output_dir)

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
        print(f"Users submitted for reassociation: {len(read_confirmed_assignments(confirmed_file))}")
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

    match_fields = [f.strip() for f in args.match_fields.split(",") if f.strip()]
    if match_fields:
        matches, unmatched, ambiguous = match_users(ad_users, feishu_users, match_fields)
        empty_ad_match_value_count = 0
    else:
        empty_ad_match_value_count = sum(
            1 for user in ad_users if not normalize_value(args.ad_match_field, user.get(args.ad_match_field))
        )
        matches, unmatched, ambiguous = match_users_by_field_pair(
            ad_users,
            feishu_users,
            args.ad_match_field,
            args.feishu_match_field,
        )
    print(f"Matched: {len(matches)}, unmatched: {len(unmatched)}, ambiguous: {len(ambiguous)}")
    if not match_fields:
        print(f"AD users skipped because {args.ad_match_field} is empty: {empty_ad_match_value_count}")

    print("Discovering AD user resource grants...")
    grants_by_ad_user = discover_ad_user_grants(
        client,
        [match.ad_user for match in matches],
        include_groups=not args.skip_resource_groups,
        include_roles=not args.direct_only,
        resource_ids=parse_id_file(args.resource_id_file),
        group_ids=parse_id_file(args.resource_group_id_file),
    )

    copied_rows: list[dict[str, Any]] = []
    failed_rows: list[dict[str, Any]] = []
    reassociate_user_rows = build_reassociate_user_rows(matches, grants_by_ad_user)
    matches_by_ad_id = {str(m.ad_user.get("id")): m for m in matches}

    for ad_user_id, grants in grants_by_ad_user.items():
        match = matches_by_ad_id.get(ad_user_id)
        if not match or not grants:
            continue
        try:
            if args.execute:
                client.assign_to_user_by_id(
                    args.feishu_domain,
                    str(match.feishu_user["id"]),
                    grants,
                )
            status = "assigned" if args.execute else "dry_run"
            for grant in grants:
                copied_rows.append(
                    {
                        "status": status,
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
        except Exception as exc:  # noqa: BLE001 - report and continue with other users.
            failed_rows.append(
                {
                    "ad_user_id": match.ad_user.get("id"),
                    "ad_user_name": match.ad_user.get("name"),
                    "feishu_user_id": match.feishu_user.get("id"),
                    "feishu_user_name": match.feishu_user.get("name"),
                    "error": str(exc),
                }
            )

    output_reports(
        output_dir,
        matches,
        unmatched,
        ambiguous,
        copied_rows,
        failed_rows,
        reassociate_user_rows,
    )

    print(f"Users needing resource reassociation: {len(reassociate_user_rows)}")
    print(f"Grant rows {'assigned' if args.execute else 'planned'}: {len(copied_rows)}")
    print(f"Failed user assignments: {len(failed_rows)}")
    print(f"Reports written to: {output_dir.resolve()}")
    if not args.execute:
        print("Dry-run only. Review reassociate_users.csv, then re-run with --execute to apply that plan.")
    return 0 if not failed_rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
