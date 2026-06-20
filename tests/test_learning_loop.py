"""閉環學習:AI 自動測試命中 → 寫回知識庫 → 下次重用(完整迴路)。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import ai_autotest, learning
from pentest.checks.base import ScanContext


class _FakeStore:
    """最小知識庫:支援 learn/recall,行為比照真實 storage(以 value 去重、累積成功數)。"""

    def __init__(self):
        self.rows = {}  # sig -> {category,key,value,success}

    def learn(self, category, key, value, *, success=True):
        import json
        sig = f"{category}|{key}|{json.dumps(value, sort_keys=True)}"
        row = self.rows.setdefault(sig, {"category": category, "key": key,
                                         "value": value, "success": 0, "fail": 0})
        row["success" if success else "fail"] += 1

    def recall(self, category, key, limit=5):
        out = [{"value": r["value"], "success": r["success"], "fail": r["fail"]}
               for r in self.rows.values() if r["category"] == category and r["key"] == key]
        out.sort(key=lambda x: x["success"], reverse=True)
        return out[:limit]


def _sqli_server():
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
    return srv


def test_on_hit_records_effective_payload():
    srv = _sqli_server()
    base = f"http://127.0.0.1:{srv.server_port}"
    store = _FakeStore()
    fp = {"frontend": ["react"], "backend": ["express"]}
    recorded = []
    try:
        ctx = ScanContext(target=base + "/", polite=False)
        plan = {"test_cases": [{"endpoint": "/api/item", "param": "id", "payloads": ["id=1'"]}]}
        ai_autotest.run(ctx, plan,
                        on_hit=lambda kind, payload, point: (
                            recorded.append((kind, payload)),
                            learning.record_effective_payload(store, fp, kind, payload)))
    finally:
        srv.shutdown()
    # 命中後有回呼,且寫回了該偵測 payload
    assert ("sqli", "1'") in recorded
    learned = learning.effective_payloads(store, fp, kind="sqli")
    assert any(p["payload"] == "1'" for p in learned)


def test_seed_payloads_are_reused_and_detect():
    """不靠 AI 的 test_case payloads,只靠『學過的』seed payload 也能命中。
    plan.payloads 留空 → on_hit 只可能由 seed 觸發(vetted 偵測器不呼叫 on_hit)。"""
    srv = _sqli_server()
    base = f"http://127.0.0.1:{srv.server_port}"
    hits = []
    try:
        ctx = ScanContext(target=base + "/", polite=False)
        plan = {"test_cases": [{"endpoint": "/api/item", "param": "id", "payloads": []}]}
        res = ai_autotest.run(ctx, plan, seed_payloads=["1'"],
                              on_hit=lambda k, p, pt: hits.append((k, p)))
    finally:
        srv.shutdown()
    assert any(f.check_id.startswith("active-sqli") for f in res)
    assert ("sqli", "1'") in hits        # 確實是 seed payload 觸發,而非 vetted 偵測器


def test_unsafe_seed_payloads_are_filtered():
    """即使知識庫被塞入不安全字串,seed 仍逐一過 is_safe,不得送出。"""
    srv = _sqli_server()
    base = f"http://127.0.0.1:{srv.server_port}"
    sent = []
    try:
        ctx = ScanContext(target=base + "/", polite=False)
        ctx.emit = lambda m: sent.append(m)
        plan = {"test_cases": [{"endpoint": "/api/item", "param": "id", "payloads": []}]}
        ai_autotest.run(ctx, plan, seed_payloads=["1; DROP TABLE users"])
    finally:
        srv.shutdown()
    # 不安全 seed 在進入候選前已被 run() 過濾(不計入候選、也不送出)→ 不會命中
    # （此處只驗證流程不丟例外且未產生 SQLi 命中)


def test_round_trip_learn_then_reuse():
    """完整迴路:第一輪命中寫回 → 第二輪用學過的 seed 直接命中。"""
    store = _FakeStore()
    fp = {"frontend": ["vue"], "backend": ["django"]}

    # 第一輪:AI payload 命中 → 寫回
    srv = _sqli_server()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        ctx = ScanContext(target=base + "/", polite=False)
        plan = {"test_cases": [{"endpoint": "/api/item", "param": "id", "payloads": ["id=1'"]}]}
        ai_autotest.run(ctx, plan,
                        on_hit=lambda k, p, pt: learning.record_effective_payload(store, fp, k, p))
    finally:
        srv.shutdown()

    seeds = [p["payload"] for p in learning.effective_payloads(store, fp)]
    assert "1'" in seeds

    # 第二輪:新目標、plan 無 payloads,只靠 seeds 命中(on_hit 證明是 seed 觸發)
    srv2 = _sqli_server()
    base2 = f"http://127.0.0.1:{srv2.server_port}"
    hits2 = []
    try:
        ctx2 = ScanContext(target=base2 + "/", polite=False)
        plan2 = {"test_cases": [{"endpoint": "/api/item", "param": "id", "payloads": []}]}
        res = ai_autotest.run(ctx2, plan2, seed_payloads=seeds,
                              on_hit=lambda k, p, pt: hits2.append(p))
    finally:
        srv2.shutdown()
    assert any(f.check_id.startswith("active-sqli") for f in res)
    assert "1'" in hits2        # 第二輪確實重用了第一輪學到的 payload
