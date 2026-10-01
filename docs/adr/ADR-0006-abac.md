# ADR-0006 · L11 屬性式存取控制設計決策（ABAC / Policy DSL）

- 狀態：Accepted（2026-06-21）
- 切片：S06 · abac
- 相關：[[ADR-0004-rbac]]（粗門禁）、[[ADR-0005-audit-log]]（決策留稽核）
- Charter：L11 Governance 子層 2（Architecture §L11 子層 2）

---

## Context · 背景

S04 的 RBAC 回答「這個**角色**能不能做這件事」（粗門禁，看身分）。但商用量化系統需要
依「情境屬性」的細粒度門禁：同樣是經理，A 部門不該看 B 部門的單、台灣區的人不該動
受限區域的部位、敏感度 5 的資源只有特定流程能碰。S06 補上 ABAC（Attribute-Based
Access Control）：吃 `AccessRequest`（部門 / 區域 / 專案 / 敏感度 1-5 / 風險類別 /
資源 / 動作），比對 YAML 政策，回 **Allow / Deny / RequireApproval** 三態。

硬約束（決定設計）：
- **延遲**：Charter §14.2 規定 `RBAC + ABAC < 5ms`，RBAC 單趟快照查詢已吃掉大半
  （S04 三趟版 p99=9ms 撞牆過）→ ABAC 不得新增任何 DB 往返。
- **依賴方向**：import-linter 禁 `rbac → audit`；ABAC 評估器也須純淨（不碰 DB / audit），
  稽核編排統一放 `governance` 根的守門。

---

## Decision · 決策（6 項）

### 1. Policy DSL = YAML 基底 + 租戶 DB 覆寫（D1 · Stanley 裁定 d）

基底政策寫 `policies/abac/*.yaml`（法遵可讀、版控、可審），`dsl.py` 嚴格解析成凍結
`PolicyRule`；任何欄位不合法 → `PolicyLoadError`（fail-closed，啟動就炸，絕不帶半套
政策上線）。租戶覆寫存 DB 但**只能加嚴**（deny / require_approval，不能放寬），S06 交付
base-only；S26 起把「基底 + 租戶政策」合成一個清單餵給 `AbacEvaluator` 即可，評估器不需改。

### 2. RBAC 先、deny 短路、ABAC 只能更嚴（D2 · 裁定 a）

`AbacAccessGuard.require_abac`：先 RBAC（`authorize_snapshot`），**deny 直接上拋、短路
不進 ABAC**（省延遲且語義正確——ABAC 是細化，不該翻 RBAC 的 deny）。RBAC 過才進 ABAC，
ABAC 只能再 deny / 改 require_approval，**永遠不能把 RBAC 的 deny 變 allow**。

### 3. RequireApproval = 擋住 + 發事件 + 留稽核；工作流交 S08（D3 · 裁定 c）

語義是「先擋住、待批准」：守門拋 `ApprovalRequiredError`（動作不放行）、同時透過
`ApprovalEventSink`（port）發 `ApprovalRequestEvent` 給未來 HITL / S08 消費、並留稽核。
S06 只負責「擋住 + 發出去 + 留證據」；**審批工作流本體（誰批、逾時、升級）明確劃給 S08**。
事件發送失敗不可把「需審批」變「放行」（fail-closed：動作已被擋，僅 CRITICAL 警示佇列漏件）。

### 4. 屬性來源：使用者屬性擴 users 表搭同趟快照；資源屬性由請求帶（D4 · 裁定 a+c）

- **使用者屬性**（department / region / project）：擴充 `users` 表 + `User` 值物件，隨既有
  `AccessSnapshot` **同一趟查詢**載入（S04 §8 早把快照設計成可擴充）——零額外往返，保住
  5ms 預算，且為權威來源（呼叫端無法偽冒）。
- **資源屬性**（sensitivity_level / risk_category）：屬於被存取的資源本身，由
  `require_abac` 參數帶入（S22 由閘道從資源 metadata 填）。
- 守門載一趟快照即同時餵 RBAC（`authorize_snapshot`）與組 `AccessRequest`（取
  `snapshot.user` 的權威屬性），不重複查資料庫。

### 5. 衝突解析 deny-overrides，無命中 deny-by-default（D5 · 裁定 a）

多政策命中時優先級 **DENY > REQUIRE_APPROVAL > ALLOW**（業界 XACML deny-overrides）；
**完全無政策命中 → DENY**（deny-by-default）。這使 ABAC 成為**白名單**模型：RBAC 過後，
動作仍須有明確 allow 政策才放行——對齊 RBAC 的 deny-by-default 與「安全疑慮一律
fail-closed」總原則。代價：基底政策須把正常操作也用 allow 明列（`base.yaml` 已涵蓋）。

### 6. Deny / RequireApproval 一律留稽核；Allow 不另記（D6 · 裁定 b）

安全相關決策（Deny / RequireApproval）一律留不可變稽核（沿用 S05 `AccessGuard` 的獨立
交易拒絕稽核模式，新增 `abac.access.denied` / `abac.access.approval_required` 動作名）；
**Allow 不在 ABAC 層另記**——緊接著的業務寫操作已被 `@audited` 記過，每筆放行重複寫在
1M+ 規模會撞延遲與儲存。如此「每個有後果的 ABAC 決策都可追溯」又不犧牲熱路徑。

---

## Consequences · 後果

**正面**：
- ABAC 為純記憶體評估（`evaluator.py` 無 DB），單次 < 0.5ms，RBAC + ABAC 合計仍在 5ms 內。
- 評估器純函式 + DSL 嚴格驗證 → 100% 覆蓋、mutation 易達標、政策可被法遵審閱。
- 白名單 + deny-overrides → 最安全、可預測、fail-closed。
- 與 S04/S05 零回歸：新增 `AbacAccessGuard`（不動 S05 `AccessGuard`）、`RBACChecker` 僅
  做行為不變重構（拆 `load_snapshot` / `authorize_snapshot`，`_Decision` → 公開 `RbacDecision`）。

**代價 / 待辦**：
- 白名單模型要求基底政策涵蓋正常操作，否則被 deny-by-default 擋（fail-closed，安全方向）；
  政策隨真實操作上線逐步補齊。
- 審批工作流本體（S08）、租戶政策管理介面（商業化前端）、S22 閘道自動填屬性 → 後續切片。
- import-linter 新增契約 `abac-not-import-audit`，保評估器純淨。

**對未來 Phase 的影響**：S07 提供 `risk_category` / `risk_score`；S08 接管 RequireApproval
工作流；S22 閘道自動組權威 `AccessRequest`；S26 啟用租戶政策覆寫層。
