# ADR-0004 · L11 RBAC 設計決策（Role-Based Access Control）

> **狀態**：Accepted（2026-06-11/12 · 規格決定點 D1-D5 經 Stanley 簽核）
> **切片**：S04 rbac
> **對應 Layer**：L11 Governance（RBAC 子層）

---

## Context · 背景

S03 之前系統內任何程式碼都能呼叫任何功能。S04 建立門禁：8 個內建角色、
32 格權限（8 資源 × 4 動作）、RBACChecker 警衛（依賴注入）、
PostgreSQL 三張表（users / role_assignments / permission_overrides）。
這是 Agent-Native OS 的行為圍欄地基：AGENT 角色的權限邊界就是 AI Agent 的籠子。

**總原則裁示（Stanley，S04 簽核時）**：「按照未來一定要商業化的解決辦法開發——
複雜、安全、優化、完整」。本切片多項決策直接源於此。

## Decision · 決策（6 項）

### 1. 權限矩陣採混合式：程式碼基底 + 租戶覆寫層（D1 · Stanley 裁定，比原建議更完整）

Claude 原建議純程式碼常數；Stanley 裁定升級為混合式：「未來商業化會讓我很麻煩，
應該一部分需要改後台程式碼，但大部分低危險性的，給客戶用的時候他們在自己的
使用者介面就可以改」。落地：

- 每格權限有**風險分級**（規則只有兩條：治理類資源一律 HIGH、delete/manage 一律 HIGH）
- HIGH 只能改程式碼（程式碼審查級變更）；LOW 可走 `permission_overrides` 表
- **三道防線**：建構期拋錯 → 讀取期忽略+警告 → 合併期忽略+警告，
  連直插資料庫都繞不過
- OWNER 不可被削權（防租戶自鎖）
- 有效權限 = `(基底 ∪ 合法 grants) − revokes`，revoke 逐角色削

### 2. 一人多角色，權限取聯集（D2）

獨立 role_assignments 表（自然鍵 tenant+user+role），AWS IAM 同款語意。
Stanley：「像我需要的就是可以多方面的內容」——本人即多帽場景。

### 3. User 表不存密碼，認證外包 OIDC（D3 + 追加裁定）

S04 只管授權（你能做什麼），不管認證（你怎麼登入）。
使用者資料（名字/Email/狀態/角色）都在自己資料庫，未來 UI 直接管理；
僅「驗證密碼」外包。**追加裁定（2026-06-12）**：S22 採**自架 Keycloak** 起步
（零授權費、資料自主、OIDC 標準協定無遷移鎖定），記 BACKLOG B-109。

### 4. fail-closed：資料庫死掉一律拒絕（D4 · 熔斷思維）

Stanley：「有安全隱患或是疑慮就要拒絕，有點像是熔斷設定那種感覺」。
連不上資料來源 → 拋 `RBACUnavailableError`（不放行、也不偽裝成「沒權限」）。
混沌演練真停容器驗證：0.01s 內明確失敗、重啟自動復原。
不重試的理由：權限查核是 API 熱路徑，快速明確失敗優於卡住空等
（與 S02 資料庫寫入要重試的場景不同）。

### 5. 不加快取，改用單趟快照查詢過效能預算（D5 + 基準逼出的優化）

快取的「撤銷角色後 TTL 內仍有權限」是安全缺口，Stanley 裁定先不加、未來補強（B-108）。
第一版警衛分三趟查（使用者/角色/覆寫），基準實測 p99 = 9ms 超出 Charter §14.2
的 5ms 預算 → 就地優化為 `AccessSnapshotRepository` **單趟 JOIN 載入 AccessSnapshot**。
結果：程式淨成本 ~0.5ms（基準含 SELECT 1 底噪對照，把程式延遲與本機 Docker
環境抖動分開舉證），環境安靜時 p99 = 3.16ms 通過。

### 6. AGENT 角色圍欄：可發訊號、不可下單（Charter 紅線落地）

AGENT 有 strategy:write（發策略訊號）但無 order:write——訊號進事件匯流排後
須經風控（S07/S08）核可才轉成訂單，「Agent 不得跳過 L10/L11」的 Charter 紅線
在權限矩陣層面成立。Demo 腳本（DoD #12）驗證此圍欄。

## Consequences · 後果

**正面**：
- 425 測試全過、100% 覆蓋、256 格矩陣真 PG 逐格實測
- deny-by-default 在每一層成立（矩陣外角色 = 空權限；矩陣沒列 = 拒絕）
- S22 只需「建構 + 注入」即可用；PermissionDeniedError 欄位齊全可直轉 403
- 商業化路徑清晰：S26 租戶自訂角色加 DB 覆寫層即可，不用推翻

**負面 / 接受的代價**：
- 覆寫層比純程式碼矩陣多三張防線的複雜度（Stanley 裁定值得）
- 每次 check() 都打一次資料庫（無快取）；高 QPS 時於 Gateway 層補強（B-108）
- 風險分級規則寫死，分級調整需改程式碼（這是 feature 不是 bug）

**下游影響**：S05 稽核吃拒絕日誌與結構化錯誤；S06 ABAC 接在 RBAC 之後；
S24 Agent 執行期攔截器以本切片為權限底座。
