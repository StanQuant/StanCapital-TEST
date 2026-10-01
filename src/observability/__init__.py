"""L9 Observability · 可觀測性三大支柱（logs / metrics / traces）。

S09 切片。核心設計：
- 遙測壞掉不可反害業務（fail-open for telemetry）；安全通知失敗則留 CRITICAL log。
- 一切遙測強制帶 tenant_id（多租戶 Day-1，無預設）。
- logs / metrics / traces 不得記錄 API key / secret / PII 原文（見 redaction）。
- 不碰 S05 audit 不可變證據鏈（兩平面分離）。
"""
