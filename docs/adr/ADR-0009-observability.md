# ADR-0009 · L9 Observability 設計決策

- 狀態：Accepted（2026-06-29）
- 切片：S09 · observability
- 相關：[[ADR-0005-audit-log]]（兩平面分離邊界）、[[ADR-0007-atr-engine]]（SecurityOfficerSink 接點）、[[ADR-0008-policy-engine]]（AuditMetadataSink 接點）
- Charter：L9 Observability（Architecture §L9 + §10 Observability Stack）

---

## Context · 背景

S08 完成本地安全核心後，M2「安全就緒」還缺「可觀測性三大支柱齊全」。商業化 SaaS 必須能即時
回答：系統健不健康、一筆請求跨層走到哪、出事時看得到也證明得了。需要一層統一的 logs / metrics /
traces，並把 S07/S08 的安全事件接進來，同時不破壞 S05 不可變稽核證據鏈。

決策依 Stanley 2026-06-28 對 D1–D10 的裁示（規格 §15）。商業化方向：核心先穩、介面留好、未來可擴；
安全疑慮一律 fail-closed；遙測不得反害業務。

## Decision · 決策（10 項）

1. **logging：structlog + OTEL log bridge（D1）**
   JSON 輸出；每筆 log 自動帶當前 span 的 `trace_id`/`span_id`（log↔trace 互跳）；橋接既有
   stdlib `logging`（約 20 處呼叫點不改）；contextvars 綁 `tenant_id`（無預設）。

2. **trace SDK 初始化：ObservabilityProvider + DI + no-op fallback（D2，B∪C 合體）**
   封裝三支柱生命週期於可注入物件（乾淨、可測、無隱藏全域）；無 OTLP endpoint 時匯出自動
   no-op；`noop()` 供測試/未接線環境當預設。

3. **metrics：registry + exporter + domain helper（D3）**
   三原語（counter/histogram/gauge）+ 儀器快取（同名只建一次 = registry）+ 現有模組 domain
   helper（policy/ATR/audit/request）。未來模組的領域指標隨各自切片用本工廠註冊，**不回頭改 S09**。

4. **W3C trace context：工具函式 + 邊界自動掛載（D4 混合）**
   `inject_context` / `extract_context` 工具 + `attached_context` 在邊界自動還原上游 context。

5. **S07/S08 安全事件入口：log + metrics + trace event + SOC notification port（D5）**
   `ObservabilitySecurityOfficerSink`（S07）/ `ObservabilityAuditMetadataSink`（S08）三支柱全帶，
   並留 SOC notification port（真送 S22/S24/S25）。

6. **Grafana：6 份 dashboard + provisioning（D6）**
   System Overview / ATR / Policy / Audit / Tracing / Multi-Tenant SLO，compose 起來即自動掛載。

7. **infra：compose + 完整 config（D7）**
   `infra/observability/`：OTEL Collector + Prometheus(+alerts) + Loki + Tempo + Grafana 本機一鍵起停；
   K8s/Helm 留 BACKLOG。統一管線：App → OTLP/HTTP → Collector → Tempo/Prometheus/Loki。

8. **audit/log 邊界：兩平面分離（D8）**
   S05 audit = 不可變證據鏈（PG 兩表，刪不掉）；S09 logs = 維運觀測（可丟）。S09 只記「稽核寫入
   延遲」這類觀測指標，**不複製證據內容、不碰 audit 兩表、不搶其 sink**。

9. **測試：unit + fake exporter + compose 整合（D9）**
   單元 100% 覆蓋；fake exporter 驗 5 層單一 trace；docker compose 整合測試標記 `integration`
   （需 `STANQUANT_OBS_STACK=1` 才跑，向 Tempo 查回 trace）。

10. **告警：metrics + alert rules + SOC/Security Officer port（D10）**
    Prometheus alert rules（ATR critical / policy deny spike / SLO 破線 / 稽核延遲）+ SOC port。

## 架構不變量

- **遙測 fail-open**：logs/metrics/traces 匯出失敗不可害死業務；安全 sink 內部 emit 失敗自己吞錯 +
  記 CRITICAL，絕不往上拋。
- **零密鑰外漏**：`redaction` 在序列化前遮蔽 key/secret/PII；Collector 端再擋一層（縱深防禦）。
- **observability 為最底層**：核心不 import 任何上層 app 模組（接線用 duck-typing Protocol），
  import-linter 契約 `s09-observability-bottom-layer` 強制。
- **多租戶 Day-1**：所有遙測帶 `tenant_id`，無預設。audit sink 缺 `tenant_id` 時**不建立 `unknown` 租戶桶**
  （記 WARNING、不發 per-tenant 指標），避免污染多租戶指標基數。
- **指標高基數守門**：metric label 經 `safe_labels` 丟棄 `*_id`（`tenant_id` 除外）/ email / ip 等高基數鍵，
  防 Prometheus series 爆量（SaaS 成本/效能）。高基數識別碼仍可進 log / trace（非 metric label）。
- **infra 安全預設**：compose 各埠只綁 `127.0.0.1`、Grafana 關匿名改帳密登入（本機 dev；正式走 K8s secret）。

## Consequences · 影響

**正面**：三支柱齊全，M2 推進；S07/S08 安全事件可即時觀測與告警；未來 SaaS/SOC/SLA/法遵/事故應變
有地基；分層乾淨，未來模組只疊不改。

**代價 / BACKLOG**：
- K8s/Helm 部署未做（本機 compose only）。
- SOC/Slack/Email/PagerDuty 真通道未接（只到 port）。
- 既有模組尚未全面改用 structlog binding / provider 注入（過渡期 stdlib log 已透過 bridge 走 JSON）；
  逐模組接線隨後續切片進行。
- domain 指標僅涵蓋現有模組；新模組指標由各自切片補。
