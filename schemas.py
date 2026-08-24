"""Pydantic params models + SDL entity contracts for SentinelOne Connector.
Module-scope (V17 federal invariant). Organized by domain to match
handlers_*.py split (connection, threats, agents, exclusions, audit).
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from imperal_sdk import sdl


class NoParams(BaseModel):
    """Explicit empty params model -- V17 disallows untyped handlers."""
    pass


# -- Connection ---------------------------------------------------------

class ConnectSentinelOneParams(BaseModel):
    label: str = Field("", description="Optional friendly name for this connection.")
    console_url: str = Field(..., description="Management Console URL, e.g. https://usea1-acme.sentinelone.net.")
    api_token: str = Field(..., description="API Token from Settings > Users > Generate API Token.")


class ProviderConnection(sdl.Entity):
    id: str = ""
    title: str = ""
    connected: bool = False
    detail: str = ""
    console_url: str = ""


class ProviderConnectionList(sdl.Entity):
    items: list[ProviderConnection] = []


class DisconnectSentinelOneParams(BaseModel):
    connection_id: str = Field(..., description="Connection id from list_connections.")


class DeleteResult(sdl.Entity):
    deleted: bool = False


# -- Threats --------------------------------------------------------------

class ListThreatsParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    resolved: str = Field("", description="Filter: 'true' (resolved/mitigated), 'false' (active). Empty = all.")
    limit: int = Field(50, description="Max threats to return (1-200).")


class SentinelOneThreat(sdl.Entity):
    threat_id: str = ""
    filename: str = ""
    classification: str = ""
    confidence_level: str = ""
    mitigation_status: str = ""
    agent_computer_name: str = ""
    agent_id: str = ""
    created_at: str = ""


class ThreatList(sdl.Entity):
    items: list[SentinelOneThreat] = []


class GetThreatParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    threat_id: str = Field(..., description="Threat id from list_threats.")


class MitigateThreatParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    threat_id: str = Field(..., description="Threat id to act on.")
    action: str = Field(..., description="One of: kill, quarantine, remediate, rollback-remediation, un-quarantine. rollback-remediation is DESTRUCTIVE and irreversible -- it restores the filesystem to its pre-infection state.")


# -- Agents ---------------------------------------------------------------

class ListAgentsParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    infected_only: bool = Field(False, description="If true, only return agents currently flagged infected.")
    limit: int = Field(50, description="Max agents to return (1-200).")


class SentinelOneAgent(sdl.Entity):
    agent_id: str = ""
    computer_name: str = ""
    os_type: str = ""
    network_status: str = ""
    is_infected: bool = False
    is_active: bool = False
    last_active: str = ""


class AgentList(sdl.Entity):
    items: list[SentinelOneAgent] = []


class IsolateAgentParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    agent_id: str = Field(..., description="Agent id from list_agents.")


class ReconnectAgentParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    agent_id: str = Field(..., description="Agent id from list_agents.")


class InitiateScanParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    agent_id: str = Field(..., description="Agent id from list_agents.")


# -- Exclusions -------------------------------------------------------------

class ListExclusionsParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    limit: int = Field(50, description="Max exclusions to return (1-200).")


class SentinelOneExclusion(sdl.Entity):
    exclusion_id: str = ""
    exclusion_type: str = ""
    value: str = ""
    mode: str = ""
    description: str = ""


class ExclusionList(sdl.Entity):
    items: list[SentinelOneExclusion] = []


class CreateExclusionParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    exclusion_type: str = Field(..., description="Exclusion type: file_type, path, certificate, hash, browser, white_hash.")
    value: str = Field(..., description="The value to exclude, e.g. a file path or hash.")
    mode: str = Field("suppress", description="Exclusion mode: suppress, disable_in_process_monitor_deep, disable_all_monitors, disable_all_monitors_deep.")
    description: str = Field("", description="Optional description of why this exclusion exists.")


class DeleteExclusionParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    exclusion_id: str = Field(..., description="Exclusion id from list_exclusions.")


# -- Deep Visibility hunting -----------------------------------------------

class RunDeepVisibilityQueryParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    query: str = Field(..., description="Deep Visibility query string, e.g. 'ProcessName contains \"powershell\"'.")
    from_date: str = Field("", description="ISO 8601 start of the query window. Empty = last 24h.")
    to_date: str = Field("", description="ISO 8601 end of the query window. Empty = now.")


class DeepVisibilityQueryRef(sdl.Entity):
    query_id: str = ""
    status: str = ""


class DeepVisibilityResultRow(sdl.Entity):
    fields_json: str = ""


class DeepVisibilityResult(sdl.Entity):
    query_id: str = ""
    status: str = ""
    rows: list[DeepVisibilityResultRow] = []


class GetDeepVisibilityResultsParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    query_id: str = Field(..., description="Query id from run_deep_visibility_query.")


# -- Audit ------------------------------------------------------------------

class AuditSentinelOneTenantParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")


class AuditFinding(sdl.Entity):
    kind: str = ""
    detail: str = ""
    severity: str = ""


class AuditReport(sdl.Entity):
    connection_id: str = ""
    active_threats: int = 0
    infected_agents: int = 0
    offline_agents: int = 0
    findings: list[AuditFinding] = []
