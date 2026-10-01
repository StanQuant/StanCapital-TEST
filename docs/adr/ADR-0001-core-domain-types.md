# ADR-0001 · L4 核心型別設計決策（Core Domain Types）

> **狀態**：Accepted（2026-06-10 Stanley 簽核）
> **切片**：S01 core-types
> **對應 Layer**：L4 Core Domain

---

## Context · 背景

S01 是第一個業務切片，定義全系統依賴的不可變值物件與事件型別。
L4 是所有層的最底層依賴——這裡的每個決定都會影響後續 29 個切片，
錯了就是全面返工，因此五個關鍵決策都經 Stanley 親自裁決。

## Decision · 決策（5 項）

### 1. `AgentRiskLevel` 不放 L4，移到 S07（方案 C · 事件分離）

風險評估屬 L10 Security 概念，放 L4 違反 Layer 分離。
比較三方案後採**方案 C**：S07 未來實作獨立 `RiskAssessmentEvent`，
靠 `BaseEvent.trace_id` + `target_event_id` 與 L4 事件聚合。
L4 唯一的責任是 `BaseEvent` 保留 `trace_id` 欄位作為接合點。
（對齊 nautilus_trader / FIX Protocol 的事件分離慣例）

### 2. `Trade` 留在 L4，但只當「資料容器」

Claude 原建議移到 S19（衍生型別純粹主義），Stanley 裁決保留，理由成立：
- 下游切片（S02 持久化 / S15 BigQuery / S16 回測）寫測試就需要 Trade 物件
- 不在 Core 定義會導致型別分裂（各切片自造 BacktestTrade / UITrade）

折衷：S01 的 Trade **不含任何計算邏輯**，`pnl` / `duration_ms`
由 S19 portfolio-risk 計算後填入（FIFO / 平均成本等方法屬 S19 決策）。

### 3. 識別符用 ULID（加依賴 `python-ulid`），不用 UUID4

ULID = 時間戳前綴 + 隨機尾，天然可排序：
- S02 PostgreSQL index 友善（插入不會隨機打散 B-tree）
- HFT 延遲分析需要時序可排序的 ID
- 量化系統業界主流做法

### 4. Enum 全部 StrEnum + 沿襲「雙核心命名」

- `StrategyKind` 沿用 StanQuant-Platform 的 `LF_TREND` / `LF_MEAN_REVERSION` /
  `LF_FUNDAMENTAL` / `LF_ML`（LF=低頻；未來高頻加 HF_ 前綴）
- StrEnum 使 `OrderSide.BUY == "buy"` 成立，JSON 序列化零摩擦
- 吸取 專案教訓紀錄 2026-05-23 教訓：拒絕 `momentum` 等舊命名

### 5. Dataclass 全部 `frozen=True + slots=True`、`tenant_id` 不給預設值

- frozen：值物件不可變，天然執行緒安全
- slots：高頻產生事件時省記憶體
- `tenant_id` 強制每個建構點明寫（multi-tenant Day-1 設計；
  吸取 專案教訓紀錄 2026-06-01「schema 變動漏改構造點」教訓——
  沒有預設值，漏寫會立刻 TypeError，不會默默吃掉錯誤）

## Consequences · 後果

**正面**：
- L4 零第三方框架依賴（僅 stdlib + python-ulid），由 `.importlinter` 強制
- 100% line + branch 覆蓋率、mypy --strict 全綠、67 個測試
- S07 / S19 的接合點（trace_id / pnl 容器欄位）已預留，未來不需改 L4 schema

**負面 / 限制**：
- Mutation testing 對純宣告型別產生 0 個有效 mutant，DoD #3 標 N/A
  （業界慣例；S03+ 含業務邏輯切片起恢復 ≥ 95% 門檻）
- `OrderEvent.action` / `MarketEvent.market_event_type` 暫用 str 而非 enum，
  若未來誤打字串風險升高，S03 event-bus 切片可再評估收緊為 StrEnum

---

> 📎 相關：`docs/slices/S01-規格.md` §2.1（方案 C 圖解）· `專案教訓紀錄.md` 2026-06-10 三條教訓
