"""L11 Governance · Audit 子層(S05) · 不可變稽核日誌。

四層防禦:
1. API 層: AuditLogRepository 沒有 update / delete 方法
2. DB 權限層: 應用程式執行帳號對稽核表只有 SELECT / INSERT(D2 裁決 c)
3. DB 觸發器層: UPDATE / DELETE 直接 RAISE EXCEPTION
4. 偵測層: 逐租戶雜湊鏈 + Merkle checkpoint(D1 裁決 c)，事後篡改必被抓
"""
