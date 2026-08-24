"""Threats -- SentinelOne's core SOC triage queue. Mitigation actions
(kill/quarantine/remediate/rollback-remediation/un-quarantine) target the
threat, not the agent directly -- see app.py docstring for why.
"""
from __future__ import annotations

import sentinelone_client as sc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import (
    ListThreatsParams, GetThreatParams, MitigateThreatParams,
    SentinelOneThreat, ThreatList,
)

_VALID_ACTIONS = {"kill", "quarantine", "remediate", "rollback-remediation", "un-quarantine"}


def _no_conn() -> ActionResult:
    return ActionResult.error("No SentinelOne tenant is connected yet.")


def _to_threat(d: dict) -> SentinelOneThreat:
    ti = d.get("threatInfo", {}) or {}
    agent = d.get("agentRealtimeInfo", {}) or {}
    return SentinelOneThreat(
        threat_id=str(d.get("id", "")),
        filename=ti.get("threatName", "") or "",
        classification=ti.get("classification", "") or "",
        confidence_level=ti.get("confidenceLevel", "") or "",
        mitigation_status=ti.get("mitigationStatus", "") or "",
        agent_computer_name=agent.get("agentComputerName", "") or "",
        agent_id=agent.get("agentId", "") or "",
        created_at=str(ti.get("createdAt", "")),
    )


@chat.function("list_threats", "List SentinelOne threats on the connected tenant, optionally filtered to resolved/unresolved only.", action_type="read", chain_callable=True, data_model=ThreatList, event="sentinelone-connector.list_threats")
async def list_threats(ctx, params: ListThreatsParams) -> ActionResult:
    """List SentinelOne threats on the connected tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await sc.list_threats(ctx, conn, resolved=params.resolved, limit=params.limit)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("data", []) or []) if isinstance(body, dict) else []
    out = ThreatList(items=[_to_threat(d) for d in items])
    return ActionResult.success(data=out, summary=f"Found {len(out.items)} threat(s).")


@chat.function("get_threat", "Read one SentinelOne threat in full by id.", action_type="read", chain_callable=True, data_model=SentinelOneThreat, event="sentinelone-connector.get_threat")
async def get_threat(ctx, params: GetThreatParams) -> ActionResult:
    """Read one SentinelOne threat in full."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await sc.get_threat(ctx, conn, params.threat_id)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("data", []) or []) if isinstance(body, dict) else []
    if not items:
        return ActionResult.error(f"Threat '{params.threat_id}' not found.")
    threat = _to_threat(items[0])
    return ActionResult.success(data=threat, summary=f"Threat {threat.threat_id}: {threat.filename}")


@chat.function("mitigate_threat", "Apply a mitigation action to a SentinelOne threat: kill, quarantine, remediate, rollback-remediation, or un-quarantine. rollback-remediation is DESTRUCTIVE and irreversible -- it restores the affected filesystem to its state before infection.", action_type="write", chain_callable=True, data_model=SentinelOneThreat, event="sentinelone-connector.mitigate_threat", effects=["sentinelone.threat.mitigated"])
async def mitigate_threat(ctx, params: MitigateThreatParams) -> ActionResult:
    """Apply a mitigation action to a SentinelOne threat."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    if params.action not in _VALID_ACTIONS:
        return ActionResult.error(f"Invalid action '{params.action}'. Must be one of: {', '.join(sorted(_VALID_ACTIONS))}.")
    try:
        await sc.mitigate_threat(ctx, conn, params.threat_id, params.action)
        body = await sc.get_threat(ctx, conn, params.threat_id)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("data", []) or []) if isinstance(body, dict) else []
    threat = _to_threat(items[0]) if items else SentinelOneThreat(threat_id=params.threat_id)
    return ActionResult.success(data=threat, summary=f"Applied '{params.action}' to threat {params.threat_id}.")
