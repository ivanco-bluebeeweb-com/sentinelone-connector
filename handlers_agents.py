"""Agents -- the endpoint fleet: list, network isolate/reconnect, and
initiate an on-demand scan.
"""
from __future__ import annotations

import sentinelone_client as sc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import (
    ListAgentsParams, SentinelOneAgent, AgentList,
    IsolateAgentParams, ReconnectAgentParams, InitiateScanParams,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No SentinelOne tenant is connected yet.")


def _to_agent(d: dict) -> SentinelOneAgent:
    return SentinelOneAgent(
        agent_id=str(d.get("id", "")),
        computer_name=d.get("computerName", "") or "",
        os_type=d.get("osType", "") or "",
        network_status=d.get("networkStatus", "") or "",
        is_infected=bool(d.get("infected", False)),
        is_active=bool(d.get("isActive", False)),
        last_active=str(d.get("lastActiveDate", "")),
    )


@chat.function("list_agents", "List agents (endpoints) enrolled in the connected SentinelOne tenant.", action_type="read", chain_callable=True, data_model=AgentList, event="sentinelone-connector.list_agents")
async def list_agents(ctx, params: ListAgentsParams) -> ActionResult:
    """List agents enrolled in the connected SentinelOne tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await sc.list_agents(ctx, conn, infected_only=params.infected_only, limit=params.limit)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("data", []) or []) if isinstance(body, dict) else []
    out = AgentList(items=[_to_agent(d) for d in items])
    return ActionResult.success(data=out, summary=f"Found {len(out.items)} agent(s).")


@chat.function("isolate_agent", "Isolate a SentinelOne agent from the network (network quarantine). The agent stays protected but loses almost all network access -- confirm the target host before running.", action_type="write", chain_callable=True, data_model=SentinelOneAgent, event="sentinelone-connector.isolate_agent", effects=["sentinelone.agent.isolated"])
async def isolate_agent(ctx, params: IsolateAgentParams) -> ActionResult:
    """Isolate a SentinelOne agent from the network."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        await sc.isolate_agent(ctx, conn, params.agent_id)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    return ActionResult.success(data=SentinelOneAgent(agent_id=params.agent_id, network_status="disconnected"), summary=f"Isolated agent {params.agent_id} from the network.")


@chat.function("reconnect_agent", "Reconnect a previously isolated SentinelOne agent back to the network.", action_type="write", chain_callable=True, data_model=SentinelOneAgent, event="sentinelone-connector.reconnect_agent", effects=["sentinelone.agent.reconnected"])
async def reconnect_agent(ctx, params: ReconnectAgentParams) -> ActionResult:
    """Reconnect a previously isolated SentinelOne agent."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        await sc.reconnect_agent(ctx, conn, params.agent_id)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    return ActionResult.success(data=SentinelOneAgent(agent_id=params.agent_id), summary=f"Reconnected agent {params.agent_id} to the network.")


@chat.function("initiate_scan", "Trigger an on-demand full disk scan on a SentinelOne agent.", action_type="write", chain_callable=True, data_model=SentinelOneAgent, event="sentinelone-connector.initiate_scan", effects=["sentinelone.agent.scanned"])
async def initiate_scan(ctx, params: InitiateScanParams) -> ActionResult:
    """Trigger an on-demand scan on a SentinelOne agent."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        await sc.initiate_scan(ctx, conn, params.agent_id)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    return ActionResult.success(data=SentinelOneAgent(agent_id=params.agent_id), summary=f"Scan initiated on agent {params.agent_id}.")
