"""檔案上傳攻擊面 + 敏感資料暴露檢查。"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks import sensitive, upload
from pentest.checks.base import ScanContext, Severity
from pentest.crawler import CrawlResult, FormInfo


def test_upload_endpoint_detected():
    ctx = ScanContext(target="http://t/", polite=False)
    ctx.crawl_result = CrawlResult(
        pages=["http://t/"],
        forms=[FormInfo(page="http://t/u", method="post", action="http://t/upload",
                        inputs=[{"type": "file", "name": "avatar", "value": "", "accept": "image/*"}])],
        injection_points=[])
    res = upload.run(ctx)
    assert res and res[0].severity == Severity.MEDIUM
    assert res[0].cwe == "CWE-434" and "upload" in res[0].check_id


def test_upload_ignores_forms_without_file_input():
    ctx = ScanContext(target="http://t/", polite=False)
    ctx.crawl_result = CrawlResult(
        pages=["http://t/"],
        forms=[FormInfo(page="http://t/", method="post", action="http://t/x",
                        inputs=[{"type": "text", "name": "q", "value": ""}])],
        injection_points=[])
    assert upload.run(ctx) == []


def _serve(body: bytes):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_sensitive_data_exposure_detected():
    srv = _serve(b'{"user":"mandy","password":"S3cretP@ss","api_key":"AKIAABCDEFGHIJKLMNOP"}')
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        res = sensitive.run(ctx)
    finally:
        srv.shutdown()
    titles = " ".join(f.title for f in res)
    assert "AWS Access Key" in titles
    assert "明文密碼" in titles
    assert any(f.severity == Severity.CRITICAL for f in res)
    # 證據不應把超長機密整段寫出(有截斷保護)
    assert all(len(f.evidence) < 200 for f in res)


def test_sensitive_clean_response_no_findings():
    srv = _serve(b'{"data":[1,2,3],"ok":true}')
    try:
        ctx = ScanContext(target=f"http://127.0.0.1:{srv.server_port}/", polite=False)
        res = sensitive.run(ctx)
    finally:
        srv.shutdown()
    assert res == []
