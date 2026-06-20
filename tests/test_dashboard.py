"""總覽儀表板彙總查詢測試。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks.base import Finding, Severity
from pentest.engagement import Engagement
from pentest.scanner import ScanJob
from pentest.authorization import ScopeRecord
from pentest.storage import Storage


def _store(tmp_path):
    return Storage(f"sqlite:///{tmp_path}/d.db")


def test_empty_dashboard(tmp_path):
    d = _store(tmp_path).dashboard_data()
    assert d["scans_total"] == 0
    assert d["engagements_total"] == 0
    assert d["findings_total"] == 0
    assert len(d["trend"]) == 14
    assert set(d["owasp"].keys()) >= {"A01", "A03", "A06"}


def test_dashboard_aggregates_scan_and_engagement(tmp_path):
    st = _store(tmp_path)

    # 一個掃描 + findings
    scope = ScopeRecord(target="https://a.test", host="a.test", authorized_by="t", attested=True)
    job = ScanJob(id="s1", scope=scope, polite=True, total_checks=2, completed_checks=2, status="done")
    st.create_scan(job)
    st.add_findings("s1", [
        Finding("active-sqli-id", "SQLi", Severity.CRITICAL, "d", "r"),
        Finding("header-missing-csp", "CSP", Severity.MEDIUM, "d", "r"),
    ])
    st.update_scan(job)

    # 一個案件
    eng = Engagement(target="https://b.test", name="B", methodology="white-box", test_type="SAST")
    st.save_engagement(eng, [
        Finding("sast-xss-x", "XSS", Severity.HIGH, "d", "r", owasp="A03 — Injection", stable_id="b::xss::x"),
    ])

    d = st.dashboard_data()
    assert d["scans_total"] == 1
    assert d["engagements_total"] == 1
    assert d["findings_total"] == 3                # critical + medium + high(排除 info)
    assert d["severity"][Severity.CRITICAL] == 1
    assert d["severity"][Severity.HIGH] == 1
    assert d["owasp"]["A03"] >= 2                  # SQLi + XSS 皆 A03
    assert d["recent_scans"][0]["id"] == "s1"
    assert d["recent_engagements"][0]["name"] == "B"
