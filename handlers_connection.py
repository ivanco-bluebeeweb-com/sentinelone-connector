"""Connection management: connect/disconnect SentinelOne tenants. Validates
credentials with a real list_threats call before saving (IDEAL_ONBOARDING.md
step 2) so a bad token/console_url is caught at connect time.
"""
from __future__ import annotations

import json
import uuid

from imperal_sdk import ActionResult

import sentinelone_client as sc
from app import ext, chat
from schemas import (
    NoParams, ConnectSentinelOneParams, ProviderConnection, ProviderConnectionList,
    DisconnectSentinelOneParams, DeleteResult,
)

_CONN_SECRET = "sentinelone_connections"


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_CONN_SECRET)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, items: list[dict]) -> None:
    await ctx.secrets.set(_CONN_SECRET, json.dumps(items))


async def _resolve_connection(ctx, connection_id: str = "") -> dict | None:
    conns = await _load_connections(ctx)
    if not conns:
        return None
    if connection_id:
        for c in conns:
            if c.get("id") == connection_id:
                return c
        return None
    return conns[0]


def _to_conn_entity(c: dict) -> ProviderConnection:
    return ProviderConnection(
        id=c.get("id", ""),
        title=c.get("label") or c.get("console_url", ""),
        connected=True,
        detail=c.get("console_url", ""),
        console_url=c.get("console_url", ""),
    )


@chat.function("connect_sentinelone", "Connect your own SentinelOne Singularity tenant (Management Console URL + API Token), verifying the credentials with a real call before saving.", action_type="write", chain_callable=True, data_model=ProviderConnection, event="sentinelone-connector.connect_sentinelone", effects=["sentinelone.connection.created"])
async def connect_sentinelone(ctx, params: ConnectSentinelOneParams) -> ActionResult:
    """Connect your own SentinelOne tenant, verifying credentials first."""
    conn = {
        "id": uuid.uuid4().hex,
        "label": params.label,
        "console_url": params.console_url.strip(),
        "api_token": params.api_token,
    }
    try:
        await sc.list_threats(ctx, conn, limit=1)
    except sc.ClientFail as exc:
        return ActionResult.error(f"Could not verify SentinelOne credentials: {exc}", retryable=(exc.status in (0, 429, 500, 502, 503)))
    conns = await _load_connections(ctx)
    conns.append(conn)
    await _save_connections(ctx, conns)
    return ActionResult.success(data=_to_conn_entity(conn), summary=f"Connected to {conn['console_url']}.")


@chat.function("list_connections", "List the connected SentinelOne tenants.", action_type="read", chain_callable=True, data_model=ProviderConnectionList, event="sentinelone-connector.list_connections")
async def list_connections(ctx, params: NoParams) -> ActionResult:
    """List the connected SentinelOne tenants."""
    conns = await _load_connections(ctx)
    out = ProviderConnectionList(items=[_to_conn_entity(c) for c in conns])
    return ActionResult.success(data=out, summary=f"{len(out.items)} connected tenant(s).")


@chat.function("disconnect_sentinelone", "Disconnect a SentinelOne tenant: deletes the saved console URL/API token. Nothing in SentinelOne itself is changed.", action_type="write", chain_callable=True, data_model=DeleteResult, event="sentinelone-connector.disconnect_sentinelone", effects=["sentinelone.connection.deleted"])
async def disconnect_sentinelone(ctx, params: DisconnectSentinelOneParams) -> ActionResult:
    """Disconnect a SentinelOne tenant."""
    conns = await _load_connections(ctx)
    remaining = [c for c in conns if c.get("id") != params.connection_id]
    if len(remaining) == len(conns):
        return ActionResult.error(f"Connection '{params.connection_id}' not found.")
    await _save_connections(ctx, remaining)
    return ActionResult.success(data=DeleteResult(deleted=True), summary="Disconnected.")
