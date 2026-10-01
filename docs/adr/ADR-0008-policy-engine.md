# ADR-0008 · L10 Policy Engine 設計決策

- 狀態：Accepted（2026-06-23）
- 切片：S08 · policy-engine
- 相關：[[ADR-0006-abac]]（RequireApproval 接點）、[[ADR-0007-atr-engine]]（ATR risk 接點）
- Charter：L10 Security 子層 2（Architecture §L10 子層 2）

---

## Context · 背景

S06 ABAC 已回答「角色與情境是否允許」，S07 ATR 已回答「Agent 行為有多危險」。但商業化
SaaS 還需要一個公司級、租戶級、可版本化、可回滾、可追責的政策裁判，統一處理：

- 高風險工具與外部 API 呼叫。
- 真實下單與敏感資料操作。
- 多租戶 / 部門 / 專案 / Agent 層級政策。
- `DENY` / `REQUIRE_APPROVAL` / `ALLOW` 決策。
- 政策發佈、回滾、稽核證據。

S08 因此落地 L10 Policy Engine。它不取代 RBAC/ABAC/ATR，而是消費它們的結果，形成最後一層
可配置 policy enforcement。

---

## Decision · 決策（10 項）

### 1. DSL 採「YAML 結構 + 安全 expression AST」

政策檔用 YAML 表達可審閱結構；條件使用 rego-like expression 子集，但只解析成 AST 後由手寫
interpreter 執行。嚴禁 Python `eval` / `exec`。

### 2. Policy 儲存採 base YAML + version registry

S08 先落地 `policies/security/base.yaml` 與 append-only in-memory registry port。正式 tenant DB
覆寫留給 S26，但 S08 先把 `content_hash`、active pointer、rollback event 介面建立好。

### 3. Evaluator 支援三態 + 靜態 limits metadata

Policy effect 為 `ALLOW` / `DENY` / `REQUIRE_APPROVAL`。S08 先支援靜態 limits metadata；動態
quota / rate counter 留給 S26。

### 4. ATR 由 Guard 編排層餵入

`PolicyEvaluator` 不直接呼叫 `AtrEngine`。`PolicyRequest` 可帶 `atr_risk_score` /
`atr_risk_category`，由 S22 Gateway 或 S08 `PolicyGuard` 上游編排。這保留 L10 core 的純淨性。

### 5. Approval 採 B+：最小狀態機 + 完整商業化介面預留

S08 做 `PENDING → APPROVED / REJECTED / EXPIRED / ESCALATED` 與 approval token metadata，接住
S06 的 `RequireApproval`。完整 UI、通知、簽核矩陣、代理人委派、法遵報表留給 S22/S24/S25/S28。

### 6. 版本控制採 append-only registry + rollback event

政策發佈不可覆寫既有版本；rollback 只移動 active pointer，不刪歷史，並留下 rollback event。

### 7. 多層衝突採 deny 優先 + 細層只能加嚴

scope 合成順序為 tenant → department → project → agent。最終衝突解析：
`DENY > REQUIRE_APPROVAL > ALLOW`。完全無命中則 deny-by-default。

### 8. Expression 安全採手寫 interpreter

第一版只支援比較、集合、布林、欄位讀取與常數。未來可評估轉接 CEL / OPA，但 S08 不直接引入
外部 binary，避免部署與供應鏈面過早膨脹。

### 9. 稽核採分層全量 metadata

所有 policy decision 都產生 audit metadata。`DENY` / `REQUIRE_APPROVAL` / policy publish /
rollback 屬於強制稽核；高風險或受監管 `ALLOW` 若稽核 sink 失敗，必須 fail-closed。

### 10. 測試包含 Policy、ATR 條件與 Approval path

單元測試覆蓋核心 evaluator、DSL、expression、versioning、approval、guard；整合測試至少包含
ATR + Policy 與 ABAC RequireApproval → S08 approval path 的可接線場景。

---

## Consequences · 後果

**正面**：

- 政策可讀、可審、可版控，符合企業客戶與法遵期待。
- 核心 evaluator 無 DB / audit / ATR engine 依賴，適合熱路徑。
- 手寫 AST interpreter 降低 injection 與任意程式執行風險。
- append-only registry 與 rollback event 支援未來 SaaS 客戶追責。

**代價 / 待辦**：

- Expression 語言初期較小，需要後續 S26/S28 標準化。
- 完整 approval UI、通知、簽核矩陣尚未落地，需後續切片補齊。
- Allow 全量持久化稽核與報表留給 S09/S28，目前 S08 先輸出完整 metadata。

**對未來 Phase 的影響**：S22 串完整 Gateway；S09 接 SOC / notification；S24 接 Agent
registry；S26 啟用 tenant policy override 與動態 quota；S28 做法遵稽核報表。
