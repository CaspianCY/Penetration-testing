"""已認證存取控制測試:登入後對內部 API 比對『帶 / 不帶 session』是否強制授權。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks import access_control
from pentest.checks.base import ScanContext, Severity
from pentest.crawler import CrawlResult, InjectionPoint


def _server(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _ctx_with_api(base, paths, cookies=None):
    ctx = ScanContext(target=base + "/", polite=False, cookies=cookies or {"sid": "abc"})
    cr = CrawlResult(pages=[base + p for p in paths])
    ctx.crawl_result = cr
    return ctx


def test_unauthenticated_returns_empty():
    ctx = ScanContext(target="http://t/", polite=False)   # 沒有 session
    ctx.crawl_result = CrawlResult(pages=["http://t/api/data"])
    assert access_control.run(ctx) == []


def test_broken_access_control_detected():
    """內部 API 不帶 session 仍回同份 JSON → 缺少授權驗證(High)。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            # 無論有沒有帶 Cookie 都回同一份資料(= 缺少授權)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"records":[{"id":1,"amount":9999},{"id":2,"amount":8888}]}')

    srv = _server(H)
    try:
        ctx = _ctx_with_api(f"http://127.0.0.1:{srv.server_port}", ["/api/daily"])
        res = access_control.run(ctx)
    finally:
        srv.shutdown()
    bac = [f for f in res if f.check_id.startswith("authz-bac-")]
    assert bac and bac[0].severity == Severity.HIGH
    assert bac[0].owasp.startswith("A01")          # Broken Access Control
    assert "未登入即可存取" in bac[0].title


def test_properly_protected_api_no_finding():
    """帶 session 回資料、不帶回 401 → 授權正確,只記 INFO 佐證已測。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if "sid=abc" in (self.headers.get("Cookie", "") or ""):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"records":[{"id":1}]}')
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"unauthorized"}')

    srv = _server(H)
    try:
        ctx = _ctx_with_api(f"http://127.0.0.1:{srv.server_port}", ["/api/secure"])
        res = access_control.run(ctx)
    finally:
        srv.shutdown()
    assert not any(f.check_id.startswith("authz-bac-") for f in res)
    assert any(f.check_id == "authz-enforced-ok" for f in res)   # 有做測試的佐證
    # 覆蓋摘要應反映「實際測試的端點數」(而非 finding 筆數)
    assert ctx.notes.get("authz_tested") == 1 and ctx.notes.get("authz_bac") == 0


def test_spa_shell_for_anon_is_not_false_positive():
    """不帶 session 回的是 SPA HTML 空殼(非 JSON 資料)→ 不應誤報為 BAC。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if "sid=abc" in (self.headers.get("Cookie", "") or ""):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"records":[{"id":1,"amount":9999}]}')
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><div id='root'></div>please login</body></html>")

    srv = _server(H)
    try:
        ctx = _ctx_with_api(f"http://127.0.0.1:{srv.server_port}", ["/api/daily"])
        res = access_control.run(ctx)
    finally:
        srv.shutdown()
    assert not any(f.check_id.startswith("authz-bac-") for f in res)


def test_no_internal_api_yields_actionable_info():
    """已登入但站點地圖沒有 /api/ 端點 → 回 INFO 指出該怎麼補(瀏覽器爬取 / 手動指定)。"""
    ctx = ScanContext(target="http://t/", polite=False, cookies={"sid": "abc"})
    ctx.crawl_result = CrawlResult(pages=["http://t/", "http://t/about.html"])
    res = access_control.run(ctx)
    assert any(f.check_id == "authz-no-internal-api" for f in res)
