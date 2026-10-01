# ADR-0005 · L11 不可變稽核日誌設計決策（Audit Log / Hash Chain）

> **狀態**：Accepted（2026-06-12 · 規格決定點 D1-D6 經 Stanley 簽核）
> **切片**：S05 audit-log
> **對應 Layer**：L11 Governance（Audit 子層，Architecture §L11 子層 3）

---

## Context · 背景

S04 蓋好門禁（RBAC）但沒有存證：誰在何時對什麼做了什麼寫操作，系統沒有不可抵賴的
記錄。S05 落地 Charter 紅線「所有寫操作必須留下不可變稽核記錄」與 ATR 威脅 T008
（Agent 試圖刪 audit log）的防線。**總原則裁示（Stanley）**：「我只有一個人，
做到最好，避免未來升級困難」——D1/D2 因此採比 Claude 原建議更深的方案。

## Decision · 決策（6 項）

### 1. 逐租戶雜湊鏈 + Merkle checkpoint 雙層（D1 · Stanley 裁定 c 案一步到位）

- 記錄層：每租戶一條鏈，`record_hash = SHA256(prev_hash + canonical(欄位))`，
  創世 prev = 64 個 0。租戶間零耦合（多租戶 Day-1 紅線）、寫入互不搶鎖。
- Checkpoint 層：每滿 1,000 筆對該批 record_hash 建 Merkle 樹，樹根寫進
  `audit_checkpoints`，封印之間再串成第二條鏈。抓「整批換掉重算」的進階攻擊，
  常規驗證走封印層（量是記錄層的 1/1000），並提供單筆存在證明
  （Merkle proof，S28 法遵 / 外部稽核用）。
- 正規化序列化（鍵排序、Decimal/datetime 走字串、UTC 統一）保證指紋決定性。

### 2. 不可變四層防禦（D2 · Stanley 裁定 c 案做到最深）

1. API 層：`AuditLogRepository` 沒有 update / delete 方法
2. DB 權限層：應用程式執行帳號 `stanquant_app` 對稽核兩表只有 SELECT / INSERT
   （鏈頭表可 UPDATE 不可 DELETE；帳號由部署腳本 / 測試 fixture 建立，
   migration 只在角色存在時設權限——密碼不進版本庫）
3. DB 觸發器層：UPDATE / DELETE / TRUNCATE 直接 RAISE EXCEPTION（owner 也擋）
4. 偵測層：superuser 暫停觸發器硬改，雜湊鏈驗證也會當場抓到 + CRITICAL 警報

### 3. fail-closed：稽核寫不進去 = 業務操作失敗（D3）

「系統裡不存在沒有稽核的寫操作」是嚴格不變量。混沌演練真停容器驗證：
業務操作明確失敗、不默默成功。可用性正解是資料庫高可用（S25/S26，記 BACKLOG），
不是弱化稽核。讀路徑不受影響。

### 4. 成功稽核與業務同一交易；失敗證據走獨立交易（D4 + 實作期發現）

- 成功路徑：`@audited` 裝飾器把稽核 append 進業務同一個 session，
  「操作成功 ⟺ 稽核存在」由交易原子性保證，回滾零幽靈記錄。
- **失敗路徑修正**：業務拋錯時呼叫端會 rollback，FAILED 證據若同交易會一起蒸發
  ——改走 `audit_session_factory` 獨立交易立即提交，「試圖做壞事」的痕跡必留。
- 效能先算往返（S04 教訓）：append = 鏈頭行鎖 UPDATE + INSERT 同交易 2 語句，
  實測遠低於 Charter §14.2 的 20ms 預算。同租戶寫入因鏈頭鎖序列化；
  HFT 熱路徑（L2/L3）不經過本層，量大時可加組提交（BACKLOG 觀察項）。

### 5. 單表 + 複合索引；分割綁封存切片再評估（D5）

(tenant_id, sequence) 唯一鍵 = 鏈不分叉的資料庫級保證 + keyset 分頁索引；
三種查詢模式各配複合索引。1M 實測 < 500ms（DoD 硬指標）。線上表體積由
未來「每日封存 S3/GCS」切片封頂；partitioning 屆時一併評估（BACKLOG）。

### 6. 警報用 alert_sink 回呼，不直發 L4 事件（實作期架構修正）

原規格寫「驗證器發 EventBus 事件」，但 L4 `EventType` 是純市場概念
（market/signal/order/fill），塞「稽核篡改」會污染核心層——
ADR-0001「AgentRiskLevel 不入 L4」同款判例。改為 CRITICAL 結構化日誌 +
可注入 `AlertSink` 回呼，S09 observability 把回呼接上通知通道，防護力相同。

## Consequences · 後果

**正面**：
- 篡改三態（改內容 / 刪記錄 / 動鏈頭）在「攻擊者受低權帳號 + 觸發器約束」前提下可偵測，
  真 PG 實彈測試（觸發器 / 低權帳號 / 並行行鎖 / 篡改偵測）通過

> ⚠️ **偵測能力邊界（2026-06-18 修正先前過度宣稱「進階攻擊全數可偵測」）**：本層定位為
> **tamper-evident（可偵測竄改）**，**非 tamper-proof（不可竄改）**。對能繞過所有 DB
> 防線的超級權限者（內部 DBA / 備份還原 / 高權 SQL injection），因記錄雜湊為無金鑰公開
> SHA256、且鏈頭與證據同庫，攻擊者可一致重算整條鏈使驗證器仍報 `intact`；「尾端截斷 +
> 回捲鏈頭」亦無法被記錄層深掃偵測（見 `verifier.py` 限制聲明與對應釘住測試）。
> 根治需 **DB 外簽章金鑰（HMAC）** 或 **外部錨定（WORM，S28 / H04）**。
> **S28 落地前，對外文案一律不得使用「不可篡改 / 不可抵賴 / tamper-proof」等絕對字眼，
> 只能用「tamper-evident / 不可變地基」。** 參見 [[Glossary]] tamper-evident vs tamper-proof。
- `@audited` 一行裝飾器即自動稽核，S22 中介層與 S24 Agent 攔截器直接複用
- 失敗操作也留證據（RBAC 拒絕 → FAILED 記錄），S07 ATR 的 risk_score 欄位已預留

**負面 / 接受的代價**：
- 同租戶寫入序列化（鏈的本質）；Merkle 層多一個模組的維護成本（Stanley 裁定值得）
- 雙 DB 帳號使本機 / CI 建置多一步（已自動化進測試 fixture 與 migration）
- 法遵保存義務：稽核表 downgrade 會刪資料，生產環境禁止（migration docstring 註明）

**下游影響**：S07 atr-engine 填 risk_score 並消費拒絕稽核；S09 接 alert_sink；
S22 gateway 自動填 ip/user_agent 與 AuditContext；S28 用 Merkle proof 出法遵報表。
