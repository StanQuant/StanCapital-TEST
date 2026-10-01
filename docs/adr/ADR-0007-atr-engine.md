# ADR-0007 · L10 Agent Threat Rules 引擎設計決策（ATR Engine）

- 狀態：Accepted（2026-06-22）
- 切片：S07 · atr-engine
- 相關：[[ADR-0005-audit-log]]（不可變稽核）、[[ADR-0006-abac]]（risk_score / risk_category 接點）
- Charter：L10 Security 子層 1（Architecture §L10 子層 1、§6 ATR 威脅模型框架）

---

## Context · 背景

S07 補上 L10 Agent Threat Rules（ATR）引擎，回答「這次 Agent 行為有多危險」。S04/S06
主要管「誰能不能做」，S07 管「AI 這次做的動作像不像攻擊」。Charter 紅線要求 MCP / 外部
呼叫必經 L10 / L11，因此 ATR 必須先提供純記憶體 fast path：每次 Agent 行為輸入
`AgentBehavior`，輸出 0-100 `ThreatScore`，再映射到 Allow / Log / Encrypt / Suspend /
Terminate 五級回應。

硬約束（決定設計）：
- **延遲**：rule fast path 不做 DB 往返，避免 S04/S05 已踩過的熱路徑延遲問題。
- **依賴方向**：`engine.py` / `rules.py` / `response.py` 不 import audit 或 governance guard；
  稽核與外部 sink 編排放 `AtrGuard`。
- **商業化可延伸**：規則權重、描述、啟用狀態需可版本化；Slack / Email、Agent registry、
  ML 模型、租戶覆寫先留 port，不在 S07 綁死。

---

## Decision · 決策（7 項）

### 1. 八類規則採「混合式」：matcher 在程式碼，rulebook 在 YAML（D1 · Stanley 裁定 C）

真正安全邏輯放 `src/security/atr/rules.py`，用測試鎖住 matcher；權重、分類、描述、版本、
啟用狀態放 `policies/atr/base.yaml`。`rulebook.py` 嚴格解析，缺 T001-T008、重複 code、
壞型別或壞值都 fail-closed。這比純程式碼更可營運，也比純 YAML 更不容易把安全邏輯做成
字串拼裝。

### 2. 評分先交 rule fast path + 上下文加權，ML slow path 留 disabled port（D2）

`AtrEngine` 先加總命中規則權重；若 `risk_level > 7`，乘 1.2；最後 clamp 到 100。
`RiskModelPort` 已存在，但預設 `ml_model_enabled=False`。未來若要 ML，不需要推翻 ATR 合約，
只要接入模型並另開資料治理 / 模型驗證切片。

### 3. Suspend / Terminate 先落成決策 + sink port，不自建 Agent registry（D3）

S07 沒有 Agent registry，因此 `AtrDecision` 先明確標示 `suspend_agent` /
`terminate_session`，再由 `AgentControlSink` 發出控制命令。測試用 in-memory sink 證明 demo
可暫停 / 終止；真 registry 放到 S24/S22 接。

### 4. Security Officer 通知用 sink port，Slack / Email 延後（D4 · Stanley 裁定 A）

`SecurityOfficerSink` 接收 `SecurityNotification`，包含 tenant、agent、decision、score、
level、action、triggered_rules、target、trace_id、timestamp。S07 不直連 Slack / Email，
避免早期綁死供應商；S09 接 observability/notification 時只需實作 sink。

### 5. ATR 先獨立 AtrGuard，與 RBAC/ABAC 全鏈整合延後 S22（D5）

`AtrGuard` 是 L10 編排入口，負責 score → response → agent control → notification →
audit metadata。S07 不直接改 `AbacAccessGuard`，避免 L10/L11 交纏；S22 API gateway 再把
RBAC / ABAC / ATR 串成完整攔截鏈。

### 6. 誤判處理採「五級漸進回應 + 受控 suppression」（D6）

`SuppressionRule` 最多降一級；多個 suppression 疊加仍最多降一級；High / Critical 不能被洗成
Safe。這讓商業化客戶可以做白名單降噪，但不能繞過高風險防線。

### 7. ATR 決策全部可稽核（D7 · Stanley 裁定 B）

`AtrDecision.audit_required=True` 目前覆蓋五級所有回應；`to_audit_metadata()` 輸出
decision_id、risk_score、risk_category、threat_level、atr_action、triggered_rules、trace_id。
S07 只產生稽核 metadata / context；真正寫入仍沿用 S05 `@audited` / `AuditContext` 編排層。

---

## Consequences · 後果

**正面**：
- L10 ATR 核心純記憶體、無 DB 往返，適合放在 MCP / 外部工具呼叫前的熱路徑。
- YAML rulebook 讓規則可版本化與未來租戶覆寫；matcher 留在程式碼，測試可精準殺安全變異。
- Sink port 讓 Slack / Email / Agent registry / SOC 都能在後續切片補齊，不綁死 S07。
- D6 suppression 保留商業化降噪能力，但高風險仍 fail-closed。

**代價 / 待辦**：
- ML slow path 只有介面與測試，未接真模型；需未來資料治理與模型驗證切片。
- Agent registry、真 Slack / Email、全鏈 RBAC→ABAC→ATR 接線延後 S22/S24/S09。
- mutmut 2.5.1 對型別別名、Protocol docstring、Noop sink、冗餘 keyword 仍會產生等價變異；
  本切片以行為測試 + 文件列明豁免。

**對未來 Phase 的影響**：S08/S22 可消費 `ThreatScore.risk_category` / `risk_score`；S09
實作 `SecurityOfficerSink`；S24 實作 `AgentControlSink`；S26 可把 rulebook 擴成租戶覆寫層。
