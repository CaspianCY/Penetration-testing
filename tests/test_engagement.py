"""白箱 SAST、標準對應、案件報告與跨次追蹤的測試。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from docx import Document

from pentest import docx_report, sast
from pentest.checks.base import Finding, Severity
from pentest.engagement import Engagement
from pentest.standards import enrich, kind_from_check_id, owasp_coverage

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "examples", "vulnerable_app")


def test_sast_finds_volvo_style_vulns():
    findings = sast.scan_path(SAMPLE, target_name="demo")
    kinds = {f.check_id.split("-")[1] for f in findings if f.severity != Severity.INFO}
    for expected in ("sqli", "xss", "secret", "dep", "cmdi"):
        assert expected in kinds, f"未偵測到 {expected};實得 {kinds}"


def test_sast_findings_are_enriched_with_standards():
    findings = sast.scan_path(SAMPLE, target_name="demo")
    sqli = [f for f in findings if "sqli" in f.check_id and f.severity == Severity.CRITICAL]
    assert sqli
    f = sqli[0]
    assert f.owasp.startswith("A03")
    assert f.cwe == "CWE-89"
    assert f.cvss and f.cvss >= 9.0
    assert ":" in f.location          # 檔案:行號
    assert f.stable_id                # 有穩定 ID


def test_kind_from_check_id():
    assert kind_from_check_id("active-sqli-id") == "sqli"
    assert kind_from_check_id("header-missing-csp") == "header"
    assert kind_from_check_id("active-openredirect-next") == "openredirect"


def test_owasp_coverage_matrix():
    findings = sast.scan_path(SAMPLE, target_name="demo")
    cov = owasp_coverage(findings)
    assert cov["A03"]      # Injection 應被涵蓋
    assert cov["A06"]      # Vulnerable Components(xlsx CVE)


def test_enrich_sets_cvss_band():
    f = enrich(Finding("x", "t", Severity.HIGH, "d", "r"), "xss")
    assert f.cvss == 7.5
    assert f.cwe == "CWE-79"


def test_report_generation(tmp_path):
    findings = sast.scan_path(SAMPLE, target_name="demo")
    eng = Engagement(target="demo-app", name="Demo", methodology="white-box",
                     test_type="SAST", tester="tester")
    out = str(tmp_path / "report.docx")
    docx_report.generate(eng, findings, out)
    assert os.path.exists(out)
    doc = Document(out)
    heads = [p.text for p in doc.paragraphs]
    joined = "\n".join(heads)
    assert "滲透測試報告書" in joined
    assert "OWASP Top 10" in joined
    assert "修補路線圖" in joined
    assert "測試整合性與清理聲明" in joined


def test_new_recurring_fixed_status(tmp_path):
    # 上次稽核有 a,b;這次有 b,c → b=recurring, c=new, a=fixed
    findings = [
        Finding("sast-sqli-x", "T-B", Severity.HIGH, "d", "r", stable_id="t::sqli::b"),
        Finding("sast-xss-x", "T-C", Severity.MEDIUM, "d", "r", stable_id="t::xss::c"),
    ]
    eng = Engagement(target="t", name="T", methodology="white-box", test_type="SAST")
    out = str(tmp_path / "r.docx")
    docx_report.generate(eng, findings, out,
                         previous_stable_ids={"t::sqli::b", "t::sqli::a"})
    status = {f.stable_id: f.status for f in findings}
    assert status["t::sqli::b"] == "recurring"
    assert status["t::xss::c"] == "new"
    # 報告應列出已修復的 a
    joined = "\n".join(p.text for p in Document(out).paragraphs)
    assert "t::sqli::a" in joined


def test_cleanup_attestation_no_artifacts():
    eng = Engagement(target="t", name="T")
    report = eng.cleanup_report()
    assert report["persistent_changes"] is False
    assert "反鑑識" in report["note"]
