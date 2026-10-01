"""L2 raw capture 與重放(S11 · D5)。

雙軌保存：raw JSONL(原始 payload 留底、稽核對帳)+ 正規化 JSONL(重放吃這份、
回測可重現)。兩軌都 append-only + manifest 雜湊。
"""
