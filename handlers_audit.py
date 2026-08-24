"""One-call estate health audit -- active (unresolved) threats by
confidence, infected agents, and inactive agents, same value-add pattern
as audit_cortex_tenant / audit_tenant across this portfolio.
"""
from __future__ import annotations

import sentinelone_client as sc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import AuditSentinelOneTenantParams, AuditReport, AuditFinding


def _no_conn() -> ActionResult:
    return ActionResult.error("No SentinelOne tenant is connected yet.")


@chat.function("audit_sentinelone_tenant", "Build one aggregated health report across the connected SentinelOne tenant: active (unresolved) threats, infected agents, and inactive agents.", action_type="read", chain_callable=True, data_model=AuditReport, event="sentinelone-connector.audit_sentinelone_tenant")
async def audit_sentinelone_tenant(ctx, params: AuditSentinelOneTenantParams) -> ActionResult:
    """Build one aggregated health report across the connected SentinelOne tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    findings: list[AuditFinding] = []
    try:
        threats_body = await sc.list_threats(ctx, conn, resolved="false", limit=100)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    threats = (threats_body.get("data", []) or []) if isinstance(threats_body, dict) else []
    for t in threats[:20]:
        ti = t.get("threatInfo", {}) or {}
        findings.append(AuditFinding(
            kind="active_threat",
            detail=f"Threat '{ti.get('threatName', '')}' ({ti.get('confidenceLevel', '')}) not yet mitigated.",
            severity="high" if ti.get("confidenceLevel") == "malicious" else "medium",
        ))
    try:
        agents_body = await sc.list_agents(ctx, conn, infected_only=True, limit=100)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    infected = (agents_body.get("data", []) or []) if isinstance(agents_body, dict) else []
    for a in infected[:20]:
        findings.append(AuditFinding(
            kind="infected_agent",
            detail=f"Agent '{a.get('computerName', '')}' is flagged infected.",
            severity="high",
        ))
    out = AuditReport(
        connection_id=conn.get("id", ""),
        active_threats=len(threats),
        infected_agents=len(infected),
        findings=findings,
    )
    return ActionResult.success(data=out, summary=f"{len(threats)} active threat(s), {len(infected)} infected agent(s).")
