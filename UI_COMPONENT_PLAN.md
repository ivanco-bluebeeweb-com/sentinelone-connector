# SentinelOne Connector — UI component plan

Источники: `Docs/session-notes/UI_COMPONENT_VOCABULARY.md`, `UI_INTERFACE_STANDARD.md`,
`concepts/panels.md`. Основано на функционале `sentinelone-connector` (Agents,
Threats/mitigation, Exclusions, Sites/Groups, Deep Visibility hunting).

## 0. Когда написан этот документ
Написан ДО `panels.py` — по правилу APP_PREPARATION_STANDARD.md §9: план
компонентов сначала, реализация строго по нему.

## 1. Компоненты

| Экран | Примитивы | Почему именно эти |
|---|---|---|
| Sidebar (left, not connected) | `ui.Stack`(v, align="stretch") + `ui.Button`("Где взять API token?" → help overlay) + `ui.Form`(connect_sentinelone) с лейблами на каждом `ui.Input` | Без карточек — паттерн Cortex XDR/Sentinel/Defender. Форма растянута на всю ширину сайдбара. |
| Connect form fields | labelled `ui.Input`(label, placeholder "Acme SOC Tenant") + labelled `ui.Input`(console_url, placeholder "https://usea1-acme.sentinelone.net") + labelled `ui.Input`(api_token, type="password") | console_url — отдельное обязательное поле, не выводимо из токена. |
| Help overlay | `ext.panel(slot="overlay")` + `ui.Markdown`(путь Settings > Users > Generate API Token) | Единственное место с инструкциями — не дублируется в сайдбаре. |
| Sidebar (connected) | `ui.Stack`(v) + `ui.Text`(console_url) + `ui.Divider` + `_settings_button()` последним | Disconnect живёт только в App settings. |
| Empty (center) | `ui.Empty`(message="Nothing to show here") | Канонический пустой центр, `center_overlay=True`. |
| Threats (center) | `ui.Stack` + `ui.Header` + `ui.DataTable`(threat_id, filename/classification, confidence Badge, mitigation_status, agent hostname, detected_at) | Таблица — рабочая очередь SOC, тот же паттерн, что Cortex/Sentinel. |
| Agents (center) | `ui.DataTable`(computer_name, os_type, network_status Badge, infected Badge, last_active) | Фleet-обзор состояния конечных точек. |
| Exclusions (center) | `ui.DataTable`(type, value, mode, description) | Список allowlist-правил. |
| Audit report (center) | `ui.Stat`(active threats / infected agents / offline >24h) + `ui.List`(findings) | Числа сразу дают статус estate, тот же value-add паттерн, что у остальных audit_* инструментов портфеля. |
| App settings (center) | `ui.Stack` + список подключений + `ui.Button`("Disconnect", variant="destructive") на каждый | Единственное место, где живёт disconnect — не дублируется в сайдбаре. |

## 2. User flow
Connect (форма в sidebar, с реальной проверкой токена) → Threats dashboard
(center, `center_overlay=True`, открывается автоматически после успешного
connect) → drill-down по конкретной угрозе (mitigate action через ChatFunction,
не отдельный экран) → Agents/Exclusions доступны через дополнительные
center-панели, открываемые через дальнейшую навигацию (chat-driven, не через
отдельные кнопки в sidebar — не дублируем инструкции).

## 3. Ограничения текущей версии SDK, повлиявшие на реализацию
- Модальное подтверждение перед mitigate/isolate реализовано не как
  отдельный UI-диалог, а через platform-level 2-step confirm на уровне
  `action_type="write"` — тот же паттерн, что у всех остальных connector'ов
  портфеля (Cortex XDR, Sentinel, CrowdStrike). Явный текст предупреждения
  о необратимости rollback-remediation вынесен в docstring/description
  соответствующего ChatFunction, видимый пользователю перед подтверждением.
