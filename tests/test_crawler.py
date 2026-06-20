"""整站爬蟲測試:多頁探索、同網域限制、注入點蒐集。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import crawler

SITE = {
    "http://t.test/": "<a href='/a'>a</a> <a href='/b?id=1'>b</a> "
                      "<a href='http://other.test/x'>ext</a> "
                      "<form method=post action='/login'><input name=u></form>",
    "http://t.test/a": "<a href='/c'>c</a> <a href='/a'>self</a>",
    "http://t.test/b": "<html>b page</html>",
    "http://t.test/c": "<a href='/a'>back</a>",
}


class FakeResp:
    def __init__(self, text):
        self.text = text
        self.status_code = 200
        self.headers = {"Content-Type": "text/html"}


class FakeCtx:
    target = "http://t.test/"

    def send(self, method, url, *, params=None, data=None, allow_redirects=True):
        base = url.split("?")[0]
        return FakeResp(SITE.get(base, SITE.get(url, "")))

    def root(self):
        return FakeResp(SITE["http://t.test/"])


def test_crawl_discovers_multiple_pages():
    res = crawler.crawl(FakeCtx(), max_pages=20, max_depth=3)
    paths = {p.replace("http://t.test", "") for p in res.pages}
    assert "/" in paths
    assert "/a" in paths and "/c" in paths   # 深層頁面也被爬到


def test_crawl_stays_same_host():
    res = crawler.crawl(FakeCtx(), max_pages=20)
    assert all("other.test" not in p for p in res.pages)


def test_crawl_collects_injection_points():
    res = crawler.crawl(FakeCtx(), max_pages=20)
    params = {(p.target_param) for p in res.injection_points}
    assert "id" in params      # /b?id=1 的查詢參數
    assert "u" in params       # /login 表單欄位


def test_crawl_respects_max_pages():
    res = crawler.crawl(FakeCtx(), max_pages=2)
    assert len(res.pages) <= 2


def test_single_page_includes_link_params():
    res = crawler.single_page(FakeCtx())
    params = {p.target_param for p in res.injection_points}
    assert "id" in params and "u" in params
    assert len(res.pages) == 1     # 只種子頁
