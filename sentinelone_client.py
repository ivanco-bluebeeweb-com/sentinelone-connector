"""SentinelOne HTTP client -- static API Token auth (ApiToken header), per-
tenant console_url. Uses the platform's own `ctx.http` (async), never
`requests`. Same ClientFail/fail() shape as cortex_client.py/sentinel_client.py.
"""
from __future__ import annotations


class ClientFail(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.message = message
        self.status = status

    def __str__(self) -> str:
        return self.message


def fail(message: str, status: int = 0):
    raise ClientFail(message, status)


def _base_url(conn: dict) -> str:
    url = conn.get("console_url", "").strip().rstrip("/")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"
    return f"{url}/web/api/v2.1"


def _headers(conn: dict) -> dict:
    return {
        "Authorization": f"ApiToken {conn.get('api_token', '')}",
        "Content-Type": "application/json",
    }


async def api_request(ctx, conn: dict, method: str, path: str,
                       params: dict | None = None, json_body: dict | None = None) -> dict:
    url = f"{_base_url(conn)}{path}"
    try:
        resp = await ctx.http.request(method, url, headers=_headers(conn), params=params, json=json_body, timeout=45)
    except Exception as exc:
        fail(f"Request to SentinelOne failed: {exc}")
        return {}
    if resp.status_code == 401:
        fail("SentinelOne rejected the credentials (401) -- check the API token.", 401)
    if resp.status_code == 403:
        fail("Access denied (403) -- this API token's role lacks permission for this action.", 403)
    if resp.status_code == 404:
        fail(f"Not found (404): {resp.text[:300]}", 404)
    if resp.status_code >= 400:
        fail(f"SentinelOne API error ({resp.status_code}): {resp.text[:300]}", resp.status_code)
    try:
        return resp.json()
    except Exception:
        fail("SentinelOne API returned a non-JSON response.")
        return {}


# -- Threats ----------------------------------------------------------------

async def list_threats(ctx, conn: dict, resolved: str = "", limit: int = 50) -> dict:
    params: dict = {"limit": limit}
    if resolved:
        params["resolved"] = resolved
    return await api_request(ctx, conn, "GET", "/threats", params=params)


async def get_threat(ctx, conn: dict, threat_id: str) -> dict:
    return await api_request(ctx, conn, "GET", "/threats", params={"ids": threat_id})


async def mitigate_threat(ctx, conn: dict, threat_id: str, action: str) -> dict:
    return await api_request(ctx, conn, "POST", f"/threats/mitigate/{action}", json_body={"filter": {"ids": [threat_id]}})


# -- Agents -------------------------------------------------------------------

async def list_agents(ctx, conn: dict, infected_only: bool = False, limit: int = 50) -> dict:
    params: dict = {"limit": limit}
    if infected_only:
        params["infected"] = "true"
    return await api_request(ctx, conn, "GET", "/agents", params=params)


async def isolate_agent(ctx, conn: dict, agent_id: str) -> dict:
    return await api_request(ctx, conn, "POST", "/agents/actions/disconnect", json_body={"filter": {"ids": [agent_id]}})


async def reconnect_agent(ctx, conn: dict, agent_id: str) -> dict:
    return await api_request(ctx, conn, "POST", "/agents/actions/connect", json_body={"filter": {"ids": [agent_id]}})


async def initiate_scan(ctx, conn: dict, agent_id: str) -> dict:
    return await api_request(ctx, conn, "POST", "/agents/actions/initiate-scan", json_body={"filter": {"ids": [agent_id]}})


# -- Exclusions ---------------------------------------------------------------

async def list_exclusions(ctx, conn: dict, limit: int = 50) -> dict:
    return await api_request(ctx, conn, "GET", "/exclusions", params={"limit": limit})


async def create_exclusion(ctx, conn: dict, exclusion_type: str, value: str, os_type: str, mode: str, description: str = "") -> dict:
    body = {"data": {"type": exclusion_type, "value": value, "osType": os_type, "mode": mode, "description": description}}
    return await api_request(ctx, conn, "POST", "/exclusions", json_body=body)


async def delete_exclusion(ctx, conn: dict, exclusion_id: str) -> dict:
    return await api_request(ctx, conn, "DELETE", "/exclusions", json_body={"filter": {"ids": [exclusion_id]}})


# -- Deep Visibility ------------------------------------------------------

async def run_deep_visibility_query(ctx, conn: dict, query: str, from_date: str = "", to_date: str = "") -> dict:
    body: dict = {"query": query}
    if from_date:
        body["fromDate"] = from_date
    if to_date:
        body["toDate"] = to_date
    return await api_request(ctx, conn, "POST", "/dv/init-query", json_body=body)


async def get_deep_visibility_results(ctx, conn: dict, query_id: str) -> dict:
    return await api_request(ctx, conn, "GET", "/dv/events", params={"queryId": query_id})
