"""SentinelOne Connector panels -- left sidebar, no cards, per
UI_INTERFACE_STANDARD.md convention (same as Cortex XDR/Sentinel/Defender).
Every input carries its own label with a contextually specific placeholder;
the connect form is stretched to the full sidebar width; "where do I get an
API token?" instructions live ONLY in the help overlay, not duplicated here.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections


def _settings_button() -> ui.UINode:
    return ui.Button(
        "App settings", variant="secondary", size="sm", full_width=True,
        icon="Settings", on_click=ui.Call("__panel__sentinelone_settings"),
    )


@ext.panel("sentinelone_sidebar", slot="left", title="SentinelOne")
async def sentinelone_sidebar(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Stack(direction="v", gap=3, align="stretch", children=[
            ui.Button("Где взять API token?", variant="ghost", size="sm", icon="HelpCircle",
                      on_click=ui.Call("__panel__sentinelone_connect_help")),
            ui.Form(action="connect_sentinelone", submit_label="Подключить тенант", full_width=True, children=[
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Название (опционально)", variant="label"),
                    ui.Input(name="label", placeholder="Acme SOC Tenant"),
                ]),
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Console URL", variant="label"),
                    ui.Input(name="console_url", placeholder="https://usea1-acme.sentinelone.net"),
                ]),
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("API Token", variant="label"),
                    ui.Input(name="api_token", type="password", placeholder="Вставьте API token"),
                ]),
            ]),
        ])
    conn = connections[0]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text(conn.get("label") or conn.get("console_url", ""), variant="body"),
        ui.Text(conn.get("console_url", ""), variant="caption"),
        ui.Divider(),
        ui.Button("Threats", variant="ghost", full_width=True, icon="ShieldAlert",
                  on_click=ui.Call("__panel__sentinelone_threats")),
        ui.Button("Agents", variant="ghost", full_width=True, icon="Laptop",
                  on_click=ui.Call("__panel__sentinelone_agents")),
        ui.Button("Exclusions", variant="ghost", full_width=True, icon="ListX",
                  on_click=ui.Call("__panel__sentinelone_exclusions")),
        ui.Divider(),
        _settings_button(),
    ])


@ext.panel("sentinelone_connect_help", slot="overlay", title="Где взять API token?")
async def sentinelone_connect_help(ctx, **kwargs) -> ui.UINode:
    return ui.Markdown(text=(
        "**Как получить API Token SentinelOne:**\n\n"
        "1. Откройте Management Console вашего тенанта.\n"
        "2. Перейдите в **Settings > Users**.\n"
        "3. Выберите своего пользователя (или создайте отдельного сервисного) и нажмите **Generate API Token**.\n"
        "4. Скопируйте токен — он показывается только один раз.\n"
        "5. Скопируйте **Console URL** из адресной строки браузера (например `https://usea1-acme.sentinelone.net`) — "
        "у каждого тенанта свой поддомен, это обязательное отдельное поле.\n\n"
        "Standard-токен не требует подписи запросов — просто вставьте его сюда."
    ))
