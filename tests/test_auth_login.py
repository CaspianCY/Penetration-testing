"""灰箱登入、登入韌性測試、流量側錄(含密碼遮罩)測試。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import auth_login
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
        ok, cookies, detail = auth_login.establish_session(ctx, spec)
    finally:
        srv.shutdown()
    assert ok and "sessionid" in cookies
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
