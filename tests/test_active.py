"""主動測試模組的單元測試:用假 ScanContext 模擬有漏洞的目標,驗證偵測邏輯。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks import active
from pentest.checks.base import Severity


class FakeResp:
    def __init__(self, text="", status=200, content_type="text/html", location=None):
        self.text = text
        self.status_code = status
        self.headers = {"Content-Type": content_type}
        if location is not None:
            self.headers["Location"] = location


INDEX = """<html><body>
<a href="/item?id=1">item</a>
<a href="/go?next=/home">go</a>
<form method="get" action="/search"><input type="text" name="q"></form>
</body></html>"""


class FakeContext:
    """模擬一個有 SQLi / XSS / 開放轉址的目標,僅供測試。"""

    target = "http://victim.test/"
    aggressive = False
    crawl_result = None          # 未啟用整站爬取 → 走 single_page 後備

    def root(self):
        return FakeResp(INDEX)

    def send(self, method, url, *, params=None, data=None, allow_redirects=True):
        p = params or data or {}
        path = url.replace("http://victim.test", "").split("?")[0]

        if path.endswith("/item"):
            v = str(p.get("id", ""))
            if "'" in v:                              # 錯誤型 SQLi
                return FakeResp("You have an error in your SQL syntax")
            if "1=2" in v.replace(" ", ""):           # 布林假值 → 不同頁
                return FakeResp("<html>no rows</html>")
            return FakeResp("<html>item gadget widget gizmo</html>")

        if path.endswith("/search"):                  # 反射型 XSS
            v = str(p.get("q", ""))
            return FakeResp(f"<html>results for {v}</html>")

        if path.endswith("/go"):                      # 開放轉址
            return FakeResp("", status=302, location=str(p.get("next", "")))

        return FakeResp("<html>ok</html>")


def test_active_detects_all_three():
    findings = active.run(FakeContext())
    kinds = {f.check_id.split("-")[1] for f in findings if f.check_id.startswith("active-")
             and f.severity != Severity.INFO}
    assert "sqli" in kinds
    assert "xss" in kinds
    assert "openredirect" in kinds


def test_sqli_marked_critical():
    findings = active.run(FakeContext())
    sqli = [f for f in findings if f.check_id.startswith("active-sqli")]
    assert sqli and sqli[0].severity == Severity.CRITICAL
    # 報告應點出「竄改資料的可能」,但不應宣稱實際更動了資料
    assert "竄改" in sqli[0].description


def test_clean_target_reports_no_vuln():
    class CleanContext(FakeContext):
        def send(self, method, url, *, params=None, data=None, allow_redirects=True):
            # 所有輸入都安全跳脫、無 SQL 錯誤、無轉址
            return FakeResp("<html>safe static page</html>")

    findings = active.run(CleanContext())
    real = [f for f in findings if f.severity != Severity.INFO]
    assert real == []
