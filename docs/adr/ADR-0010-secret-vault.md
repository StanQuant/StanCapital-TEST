# ADR-0010 · L10 Secret Vault 設計決策

- 狀態：Accepted for implementation（2026-07-01，Stanley 裁決 D1-D10）
- 切片：S10 · secret-vault
- 相關：[[ADR-0005-audit-log]]、[[ADR-0007-atr-engine]]、[[ADR-0008-policy-engine]]、[[ADR-0009-observability]]
- Charter：L10 Security 子層 3（Architecture §L10 Vault、§13.2 密鑰生命週期）

---

## Context · 背景

S08 Policy 與 S09 Observability 完成後，M2 安全就緒仍缺最後一塊：密鑰生命週期管理。
S10 的目的不是做 `.env` 讀取工具，而是建立企業級 Secret Vault 子層，支撐 SaaS、多租戶、
SOC、金融法遵、incident response 與客戶資安稽核。

硬約束：

- 不碰真 `.env`、真 API key、真 OS Keychain、真 `pass`、真 Vault，除非 Stanley 明確同意。
- `tenant_id` 不給預設；缺 tenant 直接 fail-closed。
- secret 原文不得進 logs / metrics / traces / audit metadata / demo output。
- S10 不反向破壞 S05 audit log 的 tamper-evident 證據鏈。
- 授權與風險評估由 S07 / S08 / 未來 Gateway 編排，provider 專注保管 secret。

---

## Decision · 決策（10 項）

1. **SecretProvider Protocol 加 rotation / version / audit metadata**
   S10 第一版提供 CRUD、exists、metadata、list、rotate contract。正式排程、UI 與報表留 S26/S28。

2. **SecretValue 採 redacted repr + explicit reveal()**
   secret 原文只存在 `SecretValue`，`repr()` / `str()` 永遠遮蔽，取原文必須明確呼叫 `reveal()`。

3. **macOS Keychain 採 `security` CLI adapter，真 Keychain opt-in**
   S10 用 fake runner 測 command mapping 與 CRUD，不碰 Stanley 真 Keychain。

4. **Linux pass 採 `pass` + GPG 狀態檢查**
   每次操作前檢查 `pass --version` 與 `gpg --version`，不可用時 fail-closed。

5. **生產 provider 採 Vault + AWS/GCP Secret Manager 抽象 adapter**
   S10 做共同 client contract 與 fake client 測試，不接真雲、不放真 token。未來依部署選 Vault/AWS/GCP。

6. **SecretName 強制值物件 + validator**
   密鑰名稱必含 tenant / service / purpose / environment；禁止自由字串路徑與路徑符號。

7. **provider 層強制 tenant namespace**
   沒有 `tenant_id` 不可存取 secret。未來 S22/S24 從 request context / Agent identity 自動注入。

8. **create / read / rotate / delete 都產生 audit metadata**
   metadata 只含 action、actor、trace、provider、fingerprint、structured name，不含 secret 原文。

9. **observability 採 log + metrics + trace event，全 redacted**
   S10 提供 `SecretObservabilitySink`，重用 S09 redaction，發送 redacted log / metric / trace / SOC alert；真 Slack / PagerDuty / dashboard 留 S23/S25/S26。

10. **secret scanning 採 detect-secrets + gitleaks + baseline / allowlist 管理**
    S10 提供 demo，證明 detect-secrets 會阻擋假 API key；allowlist 必須逐條有理由。

---

## Consequences · 後果

**正面**：

- S10 建立了未來 broker / LLM / prediction-market / audit HMAC key 的統一密鑰邊界。
- 多租戶隔離在命名與 provider 層同時強制，不會偷用預設 tenant。
- Redaction 與 S09 共用，避免 logs / metrics / traces 出現第二套遮蔽規則。
- Provider adapter 都可用 fake runner / fake client 測試，避免碰真 OS 或真雲。

**代價 / 延後**：

- 真 Keychain、真 `pass`、真 Vault / AWS / GCP integration 預設不跑，需 Stanley 或未來部署切片同意。
- 真 SOC / Slack / PagerDuty、法遵報表、tenant context 自動注入留給 S22/S23/S24/S25/S26/S28。
- `keyring` 類跨平台本機 backend 暫不引入，避免供應鏈與行為不透明風險。

**下游影響**：

- S05 可透過 S10 取得 HMAC signing key，但 key 不進 DB。
- S07 / S08 / S22 可把 secret access 當敏感行為與 policy resource。
- S09 / S23 可觀測 secret provider failure / rotation failure / denied access，但只能看 redacted signal。
- S28 可把 secret lifecycle metadata 做成客戶稽核報表。
