"""技術架構指紋:判斷框架 / 後端 / SPA / 登入型態,並給認證建議。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks import techstack
from pentest.checks.base import ScanContext


def _serve(html: bytes, headers: dict):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html)
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(html, headers):
    srv = _serve(html, headers)
    try:
        return techstack.run(ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False))
    finally:
        srv.shutdown()


def test_react_spa_express_recommends_token():
    res = _run(b"<html><body><div id='root'></div>"
               b"<script src='/static/js/main.a1b2c3d4.js'></script></body></html>",
               {"X-Powered-By": "Express"})
    fp = res[0]
    assert "React" in fp.description and "Express" in fp.description
    assert "SPA" in fp.description
    # 應額外給 Token 認證指引
    assert any(f.check_id == "techstack-auth-guidance" for f in res)
    assert "Token" in res[1].remediation


def test_traditional_php_form_detected():
    res = _run(b"<html><body><form action='/login.php' method='post'>"
               b"<input type='password' name='pw'></form></body></html>",
               {"X-Powered-By": "PHP/8.1", "Set-Cookie": "PHPSESSID=abc; path=/"})
    fp = res[0]
    assert "PHP" in fp.description
    assert "伺服器渲染" in fp.description or "傳統" in fp.remediation
    # 傳統表單 → 不需要 Token 指引
    assert not any(f.check_id == "techstack-auth-guidance" for f in res)


def test_js_onsubmit_form_flagged_as_js_login():
    res = _run(b"<html><body><form onsubmit='handleLogin(event)'>"
               b"<input type='password' name='pw'></form></body></html>",
               {"X-Powered-By": "Express"})
    assert any(f.check_id == "techstack-auth-guidance" for f in res)
