# ADR-0003 · L4 事件匯流排設計決策（Event Bus）

> **狀態**：Accepted（2026-06-11 · 規格決定點 D1-D5 經 Stanley 簽核）
> **切片**：S03 event-bus
> **對應 Layer**：L4 Core Domain（介面）+ 實作層 src/messaging/

---

## Context · 背景

S01 定義了 4 種事件，但模組之間沒有「郵差」：行情進來策略不知道、策略發訊號下單模組聽不到。
S03 建立內部事件匯流排：topic 三段制 `{tenant_id}.{layer}.{event_type}`、租戶 Day-1 隔離、
死信佇列（DLQ）、效能門檻 >10K events/sec。

## Decision · 決策（6 項）

### 1. Redis Streams 而非 Pub/Sub（D1 · Stanley 主動裁定採複雜方案）

Pub/Sub「沒人在聽訊息就蒸發」，金融事件蒸發 = 錯帳。Streams 提供持久化、
consumer group、ack 機制，DLQ 才能乾淨實作。代價是複雜度 +30%，
Stanley 裁定：「需要比較複雜，未來才不會出問題」。

### 2. JSON 序列化 + 可插拔 EventSerializer 介面（D2）

Decimal 走字串不經 float（精度保真）、datetime 帶時區 ISO-8601、中文不逃脫
（DLQ 落地人類可讀）。HFT 熱路徑（L2 C++ / L3 Rust，tick-to-order <50μs）
不經過本匯流排，L4-L8 應用層事件 JSON 綽綽有餘（實測見下）。
量大時換 msgpack 只換 serializer 零件，匯流排不動。

### 3. async API（D3）+ 介面/實作分離（D4)

全專案 S02 起即 async 生態。`EventBus` Protocol 放 `src/core/event_bus.py`
（L4 零第三方依賴，import-linter 雙契約守門），InMemory / Redis 實作放
`src/messaging/`（可 import redis 套件）。

### 4. 共用投遞邏輯（delivery.py）保證雙實作行為一致

重試規則（D5：3 次、指數退避 0.1/0.2/0.4s）抽成 `deliver_with_retry()`，
InMemory 與 Redis 共用——行為一致是程式碼上的必然，不是測試出來的巧合。

### 5. 訂閱語義：只收「訂閱之後」的事件

- subscribe 當下已存在的 topic → consumer group 從 `$` 起讀（只收新）
- 訂閱後才出現的 topic → group 從 `0` 起讀（整條 stream 都是訂閱後的事件）
- 萬用字元訂閱靠「租戶 topic 目錄 set」每 0.5s 重掃發現新 topic
- tenant 段禁止萬用字元（防跨租戶監聽）；publish 時 topic 與事件的
  tenant / event_type 雙向驗證（防跨租戶投遞）

### 6. 效能熱路徑三件套（基準實測逼出來的）

第一輪基準 3,267 events/sec 不及格，修正後 23,602：
1. **整批 ack**：逐筆 ack 每筆多一次網路往返
2. **topic 目錄登記快取**：同 topic 只 SADD 一次
3. **publish_many 微批次**：一次往返送整批（行情本來就成批進來）

## Consequences · 後果

**正面**：105+ 測試雙實作行為一致；效能 2.3 倍於門檻；混沌演練（真停容器）通過：
重試 3 次 0.31s 明確失敗、重啟自動復原；DLQ 跨進程可讀、持久化。

**已知限制（記錄為技術債，可接受）**：
1. **at-least-once 語義**：DLQ 落地與 ack 之間若進程崩潰，重啟後該事件會重複投遞
   （死信可能重複落地）。需要 exactly-once 時由 handler 以 event_id 冪等處理。
2. 萬用字元訂閱對「訂閱後才出現的 topic」有最長 0.5s 發現延遲（_refresh_s 可調）。
3. DLQ stream 未設修剪策略（maxlen），維運週期清理屬 S09 observability 範圍。
4. mutation 豁免 2 個等價變異：delivery.py 的 `last_error` 初始值
   （成功路徑回 None、失敗路徑必先賦值，初始值不可觀察）。
