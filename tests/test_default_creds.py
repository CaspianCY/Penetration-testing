"""預設帳密測試模組 + 攻擊流程整合測試。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import attackflow
from pentest.checks import default_creds
from pentest.checks.base import Finding, ScanContext, Severity

_LOGIN = (b"<html><body><form action='/login' method='post'>"
          b"<input name='username' type='text'><input name='password' type='password'>"
          b"<input name='csrf' type='hidden' value='x'></form></body></html>")


def _make_handler(mode):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/dashboard"):
                self._send(b"<html><body>Welcome admin! control panel</body></html>")
            else:
                self._send(_LOGIN)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            f = parse_qs(self.rfile.read(n).decode())
            u, p = f.get("username", [""])[0], f.get("password", [""])[0]
            if mode == "vuln" and u == "admin" and p == "admin":
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", "sessionid=abc; HttpOnly")
                self.end_headers()
                return
            self._send(b"<html><body>incorrect password."
                       b"<form><input name='password' type='password'></form></body></html>")

        def _send(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
    return H


def _serve(mode):
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/"


def test_detects_default_credentials():
    srv, url = _serve("vuln")
    try:
        ctx = ScanContext(target=url, polite=False)
        res = default_creds.run(ctx)
    finally:
        srv.shutdown()
    crit = [f for f in res if f.severity == Severity.CRITICAL]
    assert crit, [f.title for f in res]
    f = crit[0]
    assert f.check_id.startswith("defaultcreds-login")
    assert "admin" in f.title
    assert f.cwe == "CWE-1392" and f.wstg == "WSTG-ATHN-02"


def test_flags_missing_rate_limit_when_hardened():
    srv, url = _serve("hardened")
    try:
        ctx = ScanContext(target=url, polite=False)
        res = default_creds.run(ctx)
    finally:
        srv.shutdown()
    rl = [f for f in res if f.check_id.startswith("auth-no-rate-limit")]
    assert rl and rl[0].severity == Severity.MEDIUM
    assert rl[0].cwe == "CWE-307"


def test_no_login_form_is_info():
    # 沒有爬取結果、目標無表單 → INFO(不誤報)
    ctx = ScanContext(target="http://127.0.0.1:9/", polite=False)
    ctx.crawl_result = type("R", (), {"forms": []})()
    res = default_creds.run(ctx)
    assert len(res) == 1 and res[0].severity == Severity.INFO


def test_default_creds_drives_attack_flow_to_exploit():
    f = Finding("defaultcreds-login-admin", "預設帳密可登入 — admin/admin",
                Severity.CRITICAL, "d", "r")
    flow = attackflow.build([f])
    reached = {s["key"]: s["reached"] for s in flow["stages"]}
    assert reached["exploit"] and reached["impact"]      # 預設帳密 = 直接打進來
    names = " ".join(c["name"] for c in flow["chains"])
    assert "預設帳密" in names


def test_api_based_default_creds_when_login_api_present():
    """有登入 API 時,預設帳密改打真正的 API(不打沒作用的 JS 表單)。"""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from pentest.checks.base import ScanContext

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            try:
                b = _json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                b = {}
            if (b.get("username") or b.get("account")) == "admin" and b.get("password") == "admin":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"token":"tok1234567890abc"}')
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"{}")

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        ctx = ScanContext(target=base + "/", polite=False)
        ctx.login_api_url = base + "/api/users/login"
        res = default_creds.run(ctx)
    finally:
        srv.shutdown()
    assert any(f.check_id == "defaultcreds-api" and f.severity == Severity.CRITICAL for f in res)
