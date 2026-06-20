"""新增的滲透測試檢查:CORS、JWT、HTTP 方法、IDOR。"""

import base64
import hashlib
import hmac
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks import cors, jwt_check, http_methods, idor
from pentest.checks.base import ScanContext, Severity
from pentest.crawler import CrawlResult


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------- CORS ----------------
def test_cors_reflect_with_credentials_is_high():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)   # 反射任意 Origin
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b'{"ok":1}')

    srv = _serve(H)
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        res = cors.run(ctx)
    finally:
        srv.shutdown()
    assert any(f.check_id.startswith("cors-reflect-credentials") and f.severity == Severity.HIGH
               for f in res)
    assert all(f.owasp.startswith("A05") for f in res)


def test_cors_clean_no_finding():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":1}')          # 不回任何 CORS 標頭

    srv = _serve(H)
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        res = cors.run(ctx)
    finally:
        srv.shutdown()
    assert res == []


# ---------------- JWT ----------------
def _make_jwt(header, payload, secret=None):
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    signing = seg(header) + "." + seg(payload)
    if secret is None:
        sig = ""
    else:
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return signing + "." + sig


def test_jwt_alg_none_critical():
    tok = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "mandy", "role": "admin"})
    ctx = ScanContext(target="http://t/", auth_headers={"Authorization": f"Bearer {tok}"})
    res = jwt_check.run(ctx)
    assert any(f.check_id == "jwt-alg-none" and f.severity == Severity.CRITICAL for f in res)


def test_jwt_weak_secret_detected_offline():
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "mandy", "exp": 9999999999},
                    secret="secret")
    ctx = ScanContext(target="http://t/", cookies={"token": tok})
    res = jwt_check.run(ctx)
    assert any(f.check_id == "jwt-weak-secret" and f.severity == Severity.CRITICAL for f in res)


def test_jwt_strong_secret_and_exp_clean():
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x", "exp": 9999999999},
                    secret="J8s!9aZ_q3V#longRandom256bitKeyXYZ")
    ctx = ScanContext(target="http://t/", auth_headers={"Authorization": f"Bearer {tok}"})
    res = jwt_check.run(ctx)
    assert not any(f.check_id in ("jwt-weak-secret", "jwt-alg-none", "jwt-no-expiry") for f in res)


def test_jwt_sensitive_claims_and_no_exp():
    tok = _make_jwt({"alg": "HS256"}, {"sub": "x", "password": "p@ss"},
                    secret="J8s!9aZ_q3V#longRandom256bitKeyXYZ")
    ctx = ScanContext(target="http://t/", auth_headers={"Authorization": f"Bearer {tok}"})
    res = jwt_check.run(ctx)
    assert any(f.check_id == "jwt-sensitive-claims" for f in res)
    assert any(f.check_id == "jwt-no-expiry" for f in res)


# ---------------- HTTP methods ----------------
def test_http_trace_and_write_methods():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS, TRACE")
            self.end_headers()

    srv = _serve(H)
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        res = http_methods.run(ctx)
    finally:
        srv.shutdown()
    ids = {f.check_id for f in res}
    assert "http-method-trace" in ids
    assert "http-method-write" in ids


def test_http_methods_safe_no_finding():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Allow", "GET, POST, OPTIONS")
            self.end_headers()

    srv = _serve(H)
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        res = http_methods.run(ctx)
    finally:
        srv.shutdown()
    assert res == []


# ---------------- IDOR ----------------
def test_idor_suspected_on_neighbor_id():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            # /api/users/5 與 /api/users/6 都回 200,但內容不同 → 疑似 IDOR
            uid = self.path.rstrip("/").split("/")[-1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"id":{uid},"name":"user{uid}","salary":{1000+int(uid)}}}'.encode())

    srv = _serve(H)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        ctx = ScanContext(target=base + "/", polite=False, cookies={"sid": "abc"})
        ctx.crawl_result = CrawlResult(pages=[base + "/api/users/5"])
        res = idor.run(ctx)
    finally:
        srv.shutdown()
    assert any(f.check_id.startswith("idor-") and f.severity == Severity.HIGH for f in res)
    assert all(f.owasp.startswith("A01") for f in res)


def test_idor_skipped_when_unauthenticated():
    ctx = ScanContext(target="http://t/", polite=False)      # 無 session
    ctx.crawl_result = CrawlResult(pages=["http://t/api/users/5"])
    assert idor.run(ctx) == []


def test_idor_no_fp_when_neighbor_404():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            uid = self.path.rstrip("/").split("/")[-1]
            if uid == "5":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"id":5,"name":"me"}')
            else:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"not found"}')

    srv = _serve(H)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        ctx = ScanContext(target=base + "/", polite=False, cookies={"sid": "abc"})
        ctx.crawl_result = CrawlResult(pages=[base + "/api/users/5"])
        res = idor.run(ctx)
    finally:
        srv.shutdown()
    assert res == []      # 相鄰 ID 回 404 → 有做物件層級授權,不誤報
