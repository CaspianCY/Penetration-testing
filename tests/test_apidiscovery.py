"""從前端 JS 探出 API 端點(SPA 的攻擊面)。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks import apidiscovery
from pentest.checks.base import ScanContext


def _serve():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.endswith(".js"):
                body = (b"fetch('/api/daily?period=202606');"
                        b"axios.get('/api/income-breakdown?period=202606');"
                        b"fetch('/api/users/me');")
                ctype = "application/javascript"
            else:
                body = (b"<html><body><div id='root'></div>"
                        b"<script src='/static/main.abc.js'></script></body></html>")
                ctype = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_extracts_api_endpoints_from_js():
    srv = _serve()
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        res = apidiscovery.run(ctx)
    finally:
        srv.shutdown()
    assert res and "API 端點" in res[0].title
    assert "/api/daily" in res[0].evidence and "/api/users/me" in res[0].evidence
    # 帶參數的端點變成注入點;/api/users/me(無參數)不會
    points = ctx.crawl_result.injection_points
    params = {p.target_param for p in points}
    assert "period" in params
    assert any("/api/daily" in p.url for p in points)
    # 端點也納入站點地圖頁面(供敏感資料檢查掃回應)
    assert any("/api/users/me" in pg for pg in ctx.crawl_result.pages)


def test_no_js_no_endpoints():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>plain site</body></html>")
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        assert apidiscovery.run(ctx) == []
    finally:
        srv.shutdown()
