"""出口 Proxy / VPN:格式驗證、遮罩、流量確實經 proxy、require-proxy 閘。"""

import importlib
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import netcfg
from pentest.checks.base import ScanContext


def test_valid_proxy_and_mask():
    assert netcfg.valid_proxy("http://h:3128")
    assert netcfg.valid_proxy("https://h:3128")
    assert netcfg.valid_proxy("socks5://127.0.0.1:1080")
    assert not netcfg.valid_proxy("ftp://x")
    assert not netcfg.valid_proxy("")
    assert netcfg.mask_proxy("http://user:s3cret@host:3128") == "http://user:***@host:3128"
    assert netcfg.mask_proxy("socks5://127.0.0.1:1080") == "socks5://127.0.0.1:1080"


def _proxy_server():
    class P(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):                      # http proxy 收到絕對 URI
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(("VIA " + self.path).encode())
    srv = HTTPServer(("127.0.0.1", 0), P)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_context_routes_through_proxy():
    srv = _proxy_server()
    try:
        ctx = ScanContext(target="http://example.org/",
                          proxy=f"http://127.0.0.1:{srv.server_port}")
        r = ctx.get("http://example.org/")
    finally:
        srv.shutdown()
    # 回應來自 proxy,且 proxy 收到的是對 example.org 的請求 → 流量確實改走 proxy
    assert r.text.startswith("VIA") and "example.org" in r.text


# ---- app 層:require-proxy 閘與格式拒絕(以 sqlite 重載,不觸發外部連線)----

_KEYS = ("SENTINEL_REQUIRE_PROXY", "SENTINEL_PROXY", "HTTPS_PROXY", "ALL_PROXY",
         "SENTINEL_PASSWORD", "PASSWORD", "DATABASE_URL")


def _reload(monkeypatch, env, tmp_path):
    for k in _KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/p.db")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import app
    return importlib.reload(app)


def test_require_proxy_blocks_without_proxy(monkeypatch, tmp_path):
    app = _reload(monkeypatch, {"SENTINEL_REQUIRE_PROXY": "1"}, tmp_path)
    r = app.app.test_client().post("/scan", data={"target": "https://example.com", "attested": "on"})
    assert r.status_code == 400 and "Proxy" in r.data.decode()
    _reload(monkeypatch, {}, tmp_path)                     # 還原模組狀態(清掉 require-proxy)


def test_invalid_proxy_format_rejected(monkeypatch, tmp_path):
    app = _reload(monkeypatch, {}, tmp_path)
    r = app.app.test_client().post(
        "/scan", data={"target": "https://example.com", "attested": "on", "proxy": "ftp://nope"})
    assert r.status_code == 400


def test_resolve_proxy_prefers_form_then_env(monkeypatch, tmp_path):
    app = _reload(monkeypatch, {"SENTINEL_PROXY": "socks5://127.0.0.1:1080"}, tmp_path)
    assert app._resolve_proxy("") == "socks5://127.0.0.1:1080"          # 環境變數預設
    assert app._resolve_proxy("http://override:3128") == "http://override:3128"  # 表單優先
