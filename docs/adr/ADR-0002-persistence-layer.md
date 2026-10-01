# ADR-0002 · L5 持久化層設計決策（Persistence Layer）

> **狀態**：Accepted（2026-06-11 · 規格決定點 D1-D4 經 Stanley 簽核）
> **切片**：S02 persistence
> **對應 Layer**：L5 Persistence / Cache（本切片只做 PostgreSQL OLTP）

---

## Context · 背景

S01 定義了核心型別，但程式結束資料即消失。S02 建立「倉庫 + 唯一存取窗口」：
PostgreSQL 存放訂單/持倉/成交/交易，上層模組一律經 Repository 存取，
並從第一天就內建多租戶隔離（Charter Multi-Tenant Day 1 要求）。

## Decision · 決策（6 項）

### 1. SQLAlchemy 2.x async + asyncpg 驅動

理由：(a) 業界 Python ORM 事實標準，nautilus_trader / freqtrade 同路線；
(b) 2.x 的 `Mapped[]` 型別宣告能過 mypy strict；(c) async 配合未來 L3/L6 的
事件驅動架構，不會在 IO 上卡住事件迴圈。

### 2. Repository pattern · 所有方法強制 `tenant_id`

進出都是 L4 領域物件（呼叫端不知道資料庫存在），且**刻意不提供**
「查全部租戶」的方法——租戶洩漏在 API 層面就不可能發生，
而不是靠呼叫端自律。save() 採 upsert 語意（同自然鍵 = 更新）。

### 3. ORM 列與 L4 dataclass 嚴格分離（mappers 雙向轉換）

L4 是業務語意、ORM 列是資料庫形狀。分離後換資料庫不動 L4。
`*_columns()` 回傳 dict 供 insert / update 共用，欄位清單永不分叉。

### 4. 自訂欄位型別 PreciseDecimal / UTCDateTime

- PreciseDecimal：PostgreSQL 存 NUMERIC(20,8)、SQLite 存字串——SQLite 的
  NUMERIC 底層是浮點，金額直接存會失真（量化系統不可接受）。
- UTCDateTime：寫入前統一轉 UTC、讀出補回時區；**naive 時間直接擋下**，
  寧可立刻報錯也不默默猜時區。

### 5. 兩層測試：SQLite in-memory（單元）+ 真 PostgreSQL（整合）

單元測試秒跑、不依賴 Docker；PostgreSQL 特有行為（唯一鍵、server_default、
migration 升降級）由整合測試守住。本機 PG 未啟動時整合測試自動跳過，
**CI 中不准跳過**（防默默漏測）。

### 6. 韌性 = tenacity 重試 + 自寫輕量熔斷器

- 重試只針對連線類錯誤（OperationalError / InterfaceError），指數退避最多 3 次；
  資料類錯誤（IntegrityError）代表程式問題，重試只會重複失敗，直接拋出。
- 熔斷器連續失敗 5 次開路 30 秒、冷卻後半開試探。自寫約 50 行並注入假時鐘
  （clock 參數）使測試不需真等待。

## Consequences · 後果

- ✅ 136+ 測試、100% line+branch 覆蓋率、mutation 97.3%（唯一存活為等價變異）
- ✅ 租戶隔離由型別簽章強制，S26 Multi-Tenant SaaS 的地基已就緒
- ⚠️ Alembic autogenerate 會把自訂型別名寫進 migration 而不加 import——
  每次產生 migration 後必須手動換成 `sa.Numeric` / `sa.DateTime`（已記 專案教訓紀錄）
- ⚠️ mutation testing 必須用 mutmut 2.5.1（3.x 與 `import src.` 佈局不相容，
  指令見 pyproject.toml [tool.mutmut] 註解）
- ⏭️ Redis cache（L5 另一半）在 S03+；BigQuery OLAP 在 S15
