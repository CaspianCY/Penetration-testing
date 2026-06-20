"""瀏覽器動態爬取:結果併入 crawl_result 的整合邏輯(以 mock 取代真實瀏覽器)。"""

import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import browser_crawl
from pentest.authorization import ScopeRecord
from pentest.checks.base import ScanContext
from pentest.scanner import ScanJob, ScanManager


def test_browser_results_merged_into_crawl(monkeypatch):
    fake = {
        "pages": ["http://t/perf.html"],
        "api_calls": ["http://t/api/daily?period=202606", "http://t/api/users/me"],
        "html_by_page": {
            "http://t/perf.html": ("<html><body><form action='/api/upload' method='post'>"
                                   "<input name='f' type='file'></form></body></html>"),
        },
    }
    monkeypatch.setattr(browser_crawl, "available", lambda: True)
    monkeypatch.setattr(browser_crawl, "browser_crawl", lambda *a, **k: fake)

    scope = ScopeRecord(target="http://t/", host="t", authorized_by="s", attested=True)
    job = ScanJob(id="j", scope=scope, polite=True, browser=True)
    ctx = ScanContext(target="http://t/")
    job._ctx = ctx
    ScanManager()._browser_crawl(job, ctx)

    page_paths = {urlparse(p).path for p in ctx.crawl_result.pages}
    assert "/perf.html" in page_paths                       # 瀏覽器爬到的頁面
    assert "/api/daily" in page_paths                       # 攔截到的 API 呼叫
    # 帶參數的 API → 注入點
    assert any(pt.target_param == "period" for pt in ctx.crawl_result.injection_points)
    # 渲染後頁面的上傳表單 → 表單清單
    assert any(f.action.endswith("/api/upload") for f in ctx.crawl_result.forms)
    # 站點地圖摘要已更新
    assert job.crawl_summary.get("page_count", 0) >= 2


def test_browser_unavailable_is_graceful(monkeypatch):
    monkeypatch.setattr(browser_crawl, "available", lambda: False)
    scope = ScopeRecord(target="http://t/", host="t", authorized_by="s", attested=True)
    job = ScanJob(id="j", scope=scope, polite=True, browser=True)
    ctx = ScanContext(target="http://t/")
    job._ctx = ctx
    ScanManager()._browser_crawl(job, ctx)                   # 不應拋例外
    assert any("瀏覽器引擎" in e["text"] for e in job.timeline)
