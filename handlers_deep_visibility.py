"""Deep Visibility -- SentinelOne's fleet-wide threat hunting query engine
(their equivalent of KQL/Advanced Hunting). Two-step: init the query to get a
query_id, then poll for results once it finishes running.
"""
from __future__ import annotations

import json

import sentinelone_client as sc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import (
    RunDeepVisibilityQueryParams, DeepVisibilityQueryRef,
    GetDeepVisibilityResultsParams, DeepVisibilityResult, DeepVisibilityResultRow,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No SentinelOne tenant is connected yet.")


@chat.function("run_deep_visibility_query", "Start a Deep Visibility query (SentinelOne's fleet-wide threat hunting engine) against the connected tenant's telemetry. Returns a query_id -- fetch results with get_deep_visibility_results once it finishes running.", action_type="read", chain_callable=True, data_model=DeepVisibilityQueryRef, event="sentinelone-connector.run_deep_visibility_query")
async def run_deep_visibility_query(ctx, params: RunDeepVisibilityQueryParams) -> ActionResult:
    """Start a Deep Visibility hunting query against the connected tenant's telemetry."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await sc.run_deep_visibility_query(ctx, conn, params.query, params.from_date, params.to_date)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    query_id = (body.get("data", {}) or {}).get("queryId", "") if isinstance(body, dict) else ""
    if not query_id:
        return ActionResult.error("SentinelOne did not return a query id for this Deep Visibility query.")
    return ActionResult.success(data=DeepVisibilityQueryRef(query_id=query_id, status="running"), summary=f"Deep Visibility query started (id={query_id}). Fetch results shortly with get_deep_visibility_results.")


@chat.function("get_deep_visibility_results", "Read the results of a previously started Deep Visibility query by its query_id.", action_type="read", chain_callable=True, data_model=DeepVisibilityResult, event="sentinelone-connector.get_deep_visibility_results")
async def get_deep_visibility_results(ctx, params: GetDeepVisibilityResultsParams) -> ActionResult:
    """Read the results of a previously started Deep Visibility query."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await sc.get_deep_visibility_results(ctx, conn, params.query_id)
    except sc.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    if not isinstance(body, dict):
        return ActionResult.success(data=DeepVisibilityResult(rows=[]), summary="No results yet.")
    pagination = body.get("pagination", {}) or {}
    status = "in_progress" if pagination.get("totalItems", 0) == 0 and not body.get("data") else "finished"
    rows = [DeepVisibilityResultRow(fields_json=json.dumps(r)) for r in (body.get("data", []) or [])]
    out = DeepVisibilityResult(rows=rows, status=status)
    return ActionResult.success(data=out, summary=f"Deep Visibility query {params.query_id}: {len(rows)} row(s), status={status}.")
