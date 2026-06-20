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


def test_discovers_html_pages_via_js_nav():
    """多頁式 + JS 導覽:從 JS 探出 .html 頁面並抓取(含頁面註解裡的 API)。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/nav.js":
                b = "const pages=['/performance.html','/factories.html'];"
                ct = "application/javascript"
            elif self.path.startswith("/performance.html"):
                b = ("<html><body><!-- API: /api/stats/performance, /api/revenue-targets?period=1 -->"
                     "<form action='/api/upload' method='post'><input name='file' type='file'></form>"
                     "</body></html>")
                ct = "text/html"
            elif self.path.startswith("/factories.html"):
                b, ct = "<html><body>factories</body></html>", "text/html"
            else:
                b = "<html><body><div class='nav'></div><script src='/nav.js'></script></body></html>"
                ct = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.end_headers()
            self.wfile.write(b.encode())

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        apidiscovery.run(ctx)
    finally:
        srv.shutdown()
    from urllib.parse import urlparse
    paths = {urlparse(p).path for p in ctx.crawl_result.pages}
    assert "/performance.html" in paths and "/factories.html" in paths   # JS 導覽頁被探出
    assert "/api/stats/performance" in paths                              # 頁面註解裡的 API
    assert any(f.action.endswith("/api/upload") for f in ctx.crawl_result.forms)  # 上傳表單被抓到
    assert any(p.target_param == "period" for p in ctx.crawl_result.injection_points)


def _api_server(live_paths):
    """模擬後端 API:live_paths 回 JSON 200,其餘回 404(含基準探測路徑)。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path.lstrip("/") in live_paths:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"data":[{"id":1},{"id":2}]}')
            else:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"not found"}')
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_backend_api_content_discovery_when_authenticated():
    """已認證 → 自動探出 JS 沒明寫的後端端點(/api/users、/api/me)。"""
    srv = _api_server({"api/users", "api/me"})
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False,
                          cookies={"sid": "abc"})
        res = apidiscovery.run(ctx)
    finally:
        srv.shutdown()
    pages = " ".join(p for p in ctx.crawl_result.pages)
    assert "/api/users" in pages
    assert "/api/me" in pages


def test_backend_probe_no_false_positive_on_spa_catchall():
    """SPA 對任意路徑都回 200 HTML 空殼 → 內容探索不得誤判出端點。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><div id='root'></div></body></html>")
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False,
                          cookies={"sid": "abc"})
        apidiscovery.run(ctx)
    finally:
        srv.shutdown()
    api_pages = [p for p in ctx.crawl_result.pages if "/api/" in p]
    assert api_pages == []        # 全是 SPA 空殼 → 不應探出任何 API 端點


def test_no_backend_probe_when_unauthenticated_and_no_api():
    """未認證、且 JS 也沒露出任何 /api/ → 不做後端內容探索(避免黑箱噪音)。"""
    class H(BaseHTTPRequestHandler):
        hits = []

        def log_message(self, *a):
            pass

        def do_GET(self):
            H.hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>plain site, no js, no api</body></html>")
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        apidiscovery.run(ctx)
    finally:
        srv.shutdown()
    assert not any("zz_sentinel_none" in h for h in H.hits)   # 沒有觸發內容探索基準探測
