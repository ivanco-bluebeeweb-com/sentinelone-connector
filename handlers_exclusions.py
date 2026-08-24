"""Exclusions -- allowlist entries (hash/path/certificate/browser/file_type)
that stop SentinelOne agents from flagging known-good items."""
from __future__ import annotations

import sentinelone_client as sc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import (
    ListExclusionsParams, SentinelOneExclusion, ExclusionList,
    CreateExclusionParams, DeleteExclusionParams, DeleteResult,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No SentinelOne tenant is connected yet.")


def _to_exclusion(d: dict) -> SentinelOneExclusion:
    return SentinelOneExclusion(
        exclusion_id=str(d.get("id", "")),
        exclusion_type=d.get("type", ""),
        value=d.get("value", "") or "",
        os_type=d.get("osType", "") or "",
        mode=d.get("mode", "") or "",
        description=d.get("description", "") or "",
    )


@chat.function("list_exclusions", "List Exclusions (allowlisted hashes/paths/certificates) configured on the connected SentinelOne tenant.", action_type="read", chain_callable=True, data_model=ExclusionList, event="sentinelone-connector.list_exclusions")
async def list_exclusions(ctx, params: ListExclusionsParams) -> ActionResult:
    """List Exclusions configured on the connected SentinelOne tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await sc.list_exclusions(ctx, conn, limit=params.limit)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("data", []) or []) if isinstance(body, dict) else []
    out = ExclusionList(items=[_to_exclusion(d) for d in items])
    return ActionResult.success(data=out, summary=f"Found {len(out.items)} exclusion(s).")


@chat.function("create_exclusion", "Create a new Exclusion (allowlist entry) on the connected SentinelOne tenant -- e.g. a known-good file hash or path.", action_type="write", chain_callable=True, data_model=SentinelOneExclusion, event="sentinelone-connector.create_exclusion", effects=["sentinelone.exclusion.created"])
async def create_exclusion(ctx, params: CreateExclusionParams) -> ActionResult:
    """Create a new Exclusion (allowlist entry) on the connected SentinelOne tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await sc.create_exclusion(ctx, conn, params.exclusion_type, params.value, params.os_type, params.mode, params.description)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    data = (body.get("data", [{}]) or [{}])[0] if isinstance(body, dict) else {}
    return ActionResult.success(data=_to_exclusion(data), summary=f"Created exclusion for '{params.value}'.")


@chat.function("delete_exclusion", "Permanently delete an Exclusion from the connected SentinelOne tenant. Cannot be undone.", action_type="write", chain_callable=True, data_model=DeleteResult, event="sentinelone-connector.delete_exclusion", effects=["sentinelone.exclusion.deleted"])
async def delete_exclusion(ctx, params: DeleteExclusionParams) -> ActionResult:
    """Permanently delete an Exclusion from the connected SentinelOne tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        await sc.delete_exclusion(ctx, conn, params.exclusion_id)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    return ActionResult.success(data=DeleteResult(deleted=True), summary=f"Deleted exclusion {params.exclusion_id}.")
