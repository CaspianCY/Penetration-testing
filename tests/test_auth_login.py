"""灰箱登入、登入韌性測試、流量側錄(含密碼遮罩)測試。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import auth_login, crawler
from pentest.auth_login import LoginSpec
from pentest.checks.base import ScanContext, Severity

_LOGIN = (b"<html><body><form action='/login' method='post'>"
          b"<input name='username' type='text'><input name='password' type='password'>"
          b"<input name='csrf' type='hidden' value='tok'></form></body></html>")


def _handler(accept):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self._send(_LOGIN)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            f = parse_qs(self.rfile.read(n).decode())
            u, p = f.get("username", [""])[0], f.get("password", [""])[0]
            if u == "alice" and p in accept:
                self.send_response(302)
                self.send_header("Location", "/account")
                self.send_header("Set-Cookie", "sessionid=ZZ; HttpOnly")
                self.end_headers()
                return
            self._send(b"<html><body>invalid credentials"
                       b"<form><input type='password'></form></body></html>")

        def _send(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
    return H


def _serve(accept):
    srv = HTTPServer(("127.0.0.1", 0), _handler(accept))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def test_establish_session_success_and_masks_password():
    srv, base = _serve({"s3cret"})
    try:
        ctx = ScanContext(target=base + "/", polite=False, capture=True)
        spec = LoginSpec(url=base + "/login", username="alice", password="s3cret")
        ok, cookies, detail, landing = auth_login.establish_session(ctx, spec)
    finally:
        srv.shutdown()
    assert ok and "sessionid" in cookies
    assert "/account" in landing            # 落地頁可作為後台爬取起點
    # 流量側錄有記錄,且密碼以 **** 呈現、不外洩明文
    assert ctx.transcript
    blob = str(ctx.transcript)
    assert "****" in blob and "s3cret" not in blob


def test_resilience_detects_weak_password():
    srv, base = _serve({"s3cret", "password"})          # password 屬弱密碼清單
    try:
        ctx = ScanContext(target=base + "/", polite=False)
        spec = LoginSpec(url=base + "/login", username="alice", password="s3cret")
        res = auth_login.resilience_test(ctx, spec)
    finally:
        srv.shutdown()
    weak = [f for f in res if f.check_id.startswith("auth-weak-password")]
    assert weak and weak[0].severity == Severity.CRITICAL


def test_resilience_flags_missing_rate_limit():
    srv, base = _serve({"s3cret"})                       # 弱密碼皆不通、且不鎖定
    try:
        ctx = ScanContext(target=base + "/", polite=False)
        spec = LoginSpec(url=base + "/login", username="alice", password="s3cret")
        res = auth_login.resilience_test(ctx, spec)
    finally:
        srv.shutdown()
    rl = [f for f in res if f.check_id.startswith("auth-no-rate-limit")]
    assert rl and rl[0].severity == Severity.MEDIUM


def test_capture_masks_sensitive_query_values():
    ctx = ScanContext(target="http://t/", capture=True)
    ctx.record("GET", "http://t/login?user=alice&password=secret&csrf=xyz&token=abc",
               200, content_type="text/html", resp_len=12)
    url = ctx.transcript[0]["url"]
    assert "user=alice" in url                            # 非敏感保留
    assert "password=%2A%2A%2A" in url or "password=***" in url
    assert "secret" not in url and "xyz" not in url and "abc" not in url


def test_capture_off_records_nothing():
    ctx = ScanContext(target="http://t/", capture=False)
    ctx.record("GET", "http://t/", 200)
    assert ctx.transcript == []


def test_pasted_cookie_authenticates_scan():
    """SPA/JS 登入時改貼已登入 Cookie → 掃描以該工作階段進行(看得到登入後內容)。"""
    import time

    from pentest.authorization import ScopeRecord
    from pentest.scanner import ScanManager

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            authed = "sessionid=XYZ" in self.headers.get("Cookie", "")
            body = (b"<html><body><form action='/s' method='post'><input name='q' type='text'>"
                    b"</form></body></html>") if authed else b"<html><body>please login</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    scope = ScopeRecord(target=base + "/", host="127.0.0.1", authorized_by="self", attested=True)
    job = ScanManager().start(scope, polite=False, crawl=True, active=False,
                              cookies={"sessionid": "XYZ"})
    try:
        for _ in range(120):
            if job.status in ("done", "error"):
                break
            time.sleep(0.2)
    finally:
        srv.shutdown()
    assert job.crawl_summary.get("form_count") == 1               # 已認證 → 看得到表單
    assert any(f.check_id == "auth-session-provided" for f in job.findings)


def test_crawl_reaches_pages_only_via_seed():
    """登入後的後台(未從首頁連出)需靠 seed 才爬得到 → 驗證已認證掃描的深入。"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/admin"):
                body = (b"<html><body><form action='/admin/save' method='post'>"
                        b"<input name='q' type='text'></form></body></html>")
            else:                                   # 首頁只連到 /public,完全不提 /admin
                body = b"<html><body><a href='/public'>p</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        no_seed = crawler.crawl(ScanContext(target=base + "/", polite=False), max_pages=10)
        seeded = crawler.crawl(ScanContext(target=base + "/", polite=False),
                               max_pages=10, seeds=[base + "/admin"])
    finally:
        srv.shutdown()
    assert not any("/admin" in p for p in no_seed.pages)          # 沒 seed → 爬不到後台
    assert any("/admin" in p for p in seeded.pages)               # 有 seed → 爬到後台
    assert any(pt.target_param == "q" for pt in seeded.injection_points)
