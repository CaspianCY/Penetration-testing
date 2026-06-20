"""動態判斷:JS 應用 + 靜態爬取抓不到頁面 → 自動改用瀏覽器引擎(或在無引擎時說明原因)。

對應使用者情境:給了管理者帳密、登入成功,但站點地圖只有 2 頁——因為頁面由 JS 渲染,
靜態爬蟲看不到 JS 產生的選單/路由。平台應自動偵測並改用 headless 瀏覽器執行 JS。
"""

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import browser_crawl
from pentest.authorization import ScopeRecord
from pentest.scanner import ScanManager


def _js_app_server():
    """只回 React 空殼(id='root')、無 <a> 連結、無 <form> → 靜態爬蟲只會抓到 1 頁。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><div id='root'></div>"
                             b"<script src='/static/js/main.abc123.js'></script></body></html>")

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _await(job):
    for _ in range(120):
        if job.status in ("done", "error"):
            return
        time.sleep(0.2)


def test_auto_switches_to_browser_when_js_app_and_few_pages(monkeypatch):
    srv = _js_app_server()
    base = f"http://127.0.0.1:{srv.server_port}"
    intercepted = {
        "pages": [base + "/dashboard"],
        "api_calls": [base + "/api/daily?period=202606"],
        "html_by_page": {base + "/dashboard": "<html><body>後台</body></html>"},
    }
    monkeypatch.setattr(browser_crawl, "available", lambda: True)
    called = {"n": 0}

    def _fake_bc(*a, **k):
        called["n"] += 1
        return intercepted

    monkeypatch.setattr(browser_crawl, "browser_crawl", _fake_bc)

    scope = ScopeRecord(target=base + "/", host="127.0.0.1", authorized_by="self", attested=True)
    # 注意:browser=False(使用者沒勾)→ 平台應「自動」啟用
    job = ScanManager().start(scope, polite=False, crawl=True, active=False, browser=False)
    try:
        _await(job)
    finally:
        srv.shutdown()

    assert called["n"] == 1                                          # 自動呼叫了瀏覽器引擎
    assert any("自動改用瀏覽器動態爬取" in e["text"] for e in job.timeline)
    # 瀏覽器攔截到的後台頁 / API 已併入站點地圖
    paths = set(job.crawl_summary.get("pages") or [])
    assert "/dashboard" in paths
    assert "/api/daily" in paths


def test_explains_why_when_browser_engine_unavailable(monkeypatch):
    srv = _js_app_server()
    base = f"http://127.0.0.1:{srv.server_port}"
    monkeypatch.setattr(browser_crawl, "available", lambda: False)

    scope = ScopeRecord(target=base + "/", host="127.0.0.1", authorized_by="self", attested=True)
    job = ScanManager().start(scope, polite=False, crawl=True, active=False, browser=False)
    try:
        _await(job)
    finally:
        srv.shutdown()

    # 無瀏覽器引擎時,至少要在報告/時間軸說明「為什麼只有少數頁面」
    assert any(f.check_id == "crawl-js-app-static-only" for f in job.findings)
    assert any("JavaScript 動態渲染" in e["text"] for e in job.timeline)


def test_no_auto_browser_for_plain_html_site(monkeypatch):
    """純 HTML 站(非 JS 框架)即使頁面少,也不該自動觸發瀏覽器引擎。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>hello</h1></body></html>")

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    monkeypatch.setattr(browser_crawl, "available", lambda: True)
    called = {"n": 0}
    monkeypatch.setattr(browser_crawl, "browser_crawl",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})

    scope = ScopeRecord(target=base + "/", host="127.0.0.1", authorized_by="self", attested=True)
    job = ScanManager().start(scope, polite=False, crawl=True, active=False, browser=False)
    try:
        _await(job)
    finally:
        srv.shutdown()
    assert called["n"] == 0                                          # 非 JS 框架 → 不自動觸發
