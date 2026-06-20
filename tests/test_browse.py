"""瀏覽用查詢測試:全部掃描 / 全部案件 / 案件詳情。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.authorization import ScopeRecord
from pentest.checks.base import Finding, Severity
from pentest.engagement import Engagement
from pentest.scanner import ScanJob
from pentest.storage import Storage


def _store(tmp_path):
    return Storage(f"sqlite:///{tmp_path}/b.db")


def _seed_scan(st, sid="s1"):
    scope = ScopeRecord(target="https://a.test", host="a.test", authorized_by="t", attested=True)
    job = ScanJob(id=sid, scope=scope, polite=True, total_checks=2, completed_checks=2, status="done")
    st.create_scan(job)
    st.add_findings(sid, [
        Finding("active-sqli", "SQLi", Severity.CRITICAL, "d", "r"),
        Finding("header-csp", "CSP", Severity.MEDIUM, "d", "r"),
    ])
    st.update_scan(job)


def test_list_and_count_scans(tmp_path):
    st = _store(tmp_path)
    _seed_scan(st, "s1")
    _seed_scan(st, "s2")
    assert st.count_scans() == 2
    rows = st.list_scans()
    assert len(rows) == 2
    r = rows[0]
    assert r["findings"] == 2                 # critical + medium(排除 info)
    assert r["severity"][Severity.CRITICAL] == 1
    assert "created" in r and r["progress"] == 100


def test_list_scans_pagination(tmp_path):
    st = _store(tmp_path)
    for i in range(5):
        _seed_scan(st, f"s{i}")
    assert len(st.list_scans(limit=2, offset=0)) == 2
    assert len(st.list_scans(limit=2, offset=4)) == 1


def test_list_and_load_engagement(tmp_path):
    st = _store(tmp_path)
    eng = Engagement(target="https://b.test", name="B", methodology="white-box", test_type="SAST")
    st.save_engagement(eng, [
        Finding("sast-sqli-x", "SQLi", Severity.CRITICAL, "desc", "fix",
                owasp="A03 — Injection", cwe="CWE-89", cvss=9.1, location="a.js:5",
                stable_id="b::sqli::a"),
    ])
    assert st.count_engagements() == 1
    rows = st.list_engagements()
    assert rows[0]["name"] == "B"
    assert rows[0]["findings"] == 1

    detail = st.load_engagement(eng.id)
    assert detail is not None
    assert detail["severity"][Severity.CRITICAL] == 1
    f = detail["findings"][0]
    assert f["owasp"].startswith("A03")
    assert f["cwe"] == "CWE-89"
    assert f["location"] == "a.js:5"


def test_load_missing_engagement(tmp_path):
    assert _store(tmp_path).load_engagement("nope") is None
