"""SentinelOne Connector extension declaration.

SentinelOne is a Singularity XDR platform reached through a per-tenant
Management Console REST API (https://{console}.sentinelone.net/web/api/v2.1/*)
secured by a static API Token. It covers Agents (the endpoint fleet:
isolate/reconnect network, initiate scan), Threats (SOC triage queue:
mitigate actions -- kill/quarantine/remediate/rollback), Exclusions (IOC
allowlisting), Sites/Groups (fleet scoping), and Deep Visibility (threat
hunting queries across telemetry).

WHY BYOK (bring-your-own API Token). SentinelOne lives inside the user's
own Management Console tenant -- Imperal cannot broker access to someone
else's endpoint estate centrally. The user generates an API Token in
Settings > Users > (their user) > Generate API Token (or a dedicated
service user), and pastes the console URL + token once, Vault-encrypted.

WHY CONSOLE URL IS A SEPARATE REQUIRED FIELD.
SentinelOne has no single shared API host -- every tenant's Management
Console gets its own subdomain (e.g. usea1-partners.sentinelone.net), shown
in the browser address bar when the user is logged in. There is no way to
derive it from the token alone, so console_url is a required field of
connect_sentinelone.

WHY MITIGATION ACTIONS TARGET threat_id, NOT agent_id DIRECTLY.
SentinelOne's response actions (kill/quarantine/remediate/rollback-remediation)
apply to a specific detected Threat record, which already carries the
affected agent(s) -- this mirrors SentinelOne's own console UX (you respond
to a threat, not to an agent in the abstract) and avoids accidentally
mitigating the wrong process on a host with multiple concurrent threats.
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "sentinelone-connector",
    version="0.1.0",
    display_name="SentinelOne",
    description=(
        "Connect your own SentinelOne Singularity tenant to manage Agents "
        "(isolate/reconnect, scan), Threats (mitigate: kill/quarantine/"
        "remediate/rollback), Exclusions, Sites/Groups, and Deep Visibility "
        "threat hunting queries."
    ),
    icon="icon.svg",
    capabilities=["sentinelone:read", "sentinelone:write"],
    actions_explicit=True,
    system=False,
)

chat = ChatExtension(
    ext,
    tool_name="sentinelone",
    description=(
        "SentinelOne Connector -- connect your own SentinelOne Singularity "
        "tenant via console URL plus API Token, then manage Agents "
        "(isolate/reconnect, scan), Threats (mitigate: kill/quarantine/"
        "remediate/rollback), Exclusions, Sites/Groups, and Deep Visibility "
        "threat hunting queries."
    ),
)


@ext.health_check
async def health_check(ctx) -> dict:
    """Report whether this extension's own state store is reachable --
    does not call out to SentinelOne itself (that would burn API quota on
    every platform health probe)."""
    return {"status": "ok"}
