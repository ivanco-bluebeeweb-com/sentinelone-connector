"""SentinelOne Connector -- center panels for Threats, Agents, and
Exclusions, per UI_COMPONENT_PLAN.md.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections
import sentinelone_client as sc


def _confidence_badge(level: str) -> ui.UINode:
    s = (level or "").lower()
    variant = "error" if s == "malicious" else ("warning" if s == "suspicious" else "default")
    return ui.Badge(text=level or "unknown", variant=variant)


@ext.panel("sentinelone_threats", slot="center", title="Threats", center_overlay=True)
async def sentinelone_threats(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ShieldAlert")
    conn = connections[0]
    try:
        body = await sc.list_threats(ctx, conn, limit=100)
    except sc.ClientFail as e:
        return ui.Alert(type="error", message=str(e))
    items = (body.get("data", []) or []) if isinstance(body, dict) else []
    if not items:
        return ui.Empty(message="No threats found", icon="ShieldCheck")
    rows = []
    for t in items:
        ti = t.get("threatInfo", {}) or {}
        agent = t.get("agentRealtimeInfo", {}) or {}
        rows.append({
            "id": t.get("id", ""),
            "filename": ti.get("threatName", ""),
            "confidence": ti.get("confidenceLevel", ""),
            "status": ti.get("mitigationStatus", ""),
            "host": agent.get("agentComputerName", ""),
        })
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Threats", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="id", label="#"),
            ui.DataColumn(key="filename", label="Threat"),
            ui.DataColumn(key="confidence", label="Confidence"),
            ui.DataColumn(key="status", label="Status"),
            ui.DataColumn(key="host", label="Host"),
        ]),
    ])


@ext.panel("sentinelone_agents", slot="center", title="Agents", center_overlay=True)
async def sentinelone_agents(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Laptop")
    conn = connections[0]
    try:
        body = await sc.list_agents(ctx, conn, limit=100)
    except sc.ClientFail as e:
        return ui.Alert(type="error", message=str(e))
    items = (body.get("data", []) or []) if isinstance(body, dict) else []
    if not items:
        return ui.Empty(message="No agents found", icon="Laptop")
    rows = [{
        "computer_name": a.get("computerName", ""),
        "os_type": a.get("osType", ""),
        "network_status": a.get("networkStatus", ""),
        "infected": "Yes" if a.get("infected") else "No",
        "last_active": a.get("lastActiveDate", ""),
    } for a in items]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Agents", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="computer_name", label="Host"),
            ui.DataColumn(key="os_type", label="OS"),
            ui.DataColumn(key="network_status", label="Network"),
            ui.DataColumn(key="infected", label="Infected"),
            ui.DataColumn(key="last_active", label="Last active"),
        ]),
    ])


@ext.panel("sentinelone_exclusions", slot="center", title="Exclusions", center_overlay=True)
async def sentinelone_exclusions(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ListX")
    conn = connections[0]
    try:
        body = await sc.list_exclusions(ctx, conn, limit=100)
    except sc.ClientFail as e:
        return ui.Alert(type="error", message=str(e))
    items = (body.get("data", []) or []) if isinstance(body, dict) else []
    if not items:
        return ui.Empty(message="No exclusions configured", icon="ListX")
    rows = [{
        "type": x.get("type", ""),
        "value": x.get("value", ""),
        "os_type": x.get("osType", ""),
        "mode": x.get("mode", ""),
    } for x in items]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Exclusions", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="type", label="Type"),
            ui.DataColumn(key="value", label="Value"),
            ui.DataColumn(key="os_type", label="OS"),
            ui.DataColumn(key="mode", label="Mode"),
        ]),
    ])
