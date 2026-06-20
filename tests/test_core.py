"""不依賴網路的核心邏輯測試:授權關卡、嚴重度排序、報告產生。"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.authorization import AuthorizationError, authorize, normalize_target
from pentest.authorization import ScopeRecord
from pentest.checks import Finding, Severity
from pentest import report
from pentest.scanner import ScanJob


def test_normalize_adds_scheme():
    assert normalize_target("example.com").startswith("http://")
    assert normalize_target("https://example.com") == "https://example.com"


def test_normalize_rejects_bad_scheme():
    with pytest.raises(AuthorizationError):
        normalize_target("ftp://example.com")


def test_authorize_requires_attestation():
    with pytest.raises(AuthorizationError):
        authorize("https://example.com", attested=False)


def test_authorize_blocks_metadata_endpoint():
    with pytest.raises(AuthorizationError):
        authorize("http://169.254.169.254/", attested=True)


def test_authorize_respects_allowlist(monkeypatch):
    monkeypatch.setenv("SENTINEL_ALLOWED_HOSTS", "allowed.test")
    with pytest.raises(AuthorizationError):
        authorize("http://denied.test", attested=True)
    scope = authorize("http://allowed.test", attested=True)
    assert scope.host == "allowed.test"


def test_severity_rank_orders_critical_first():
    assert Severity.rank(Severity.CRITICAL) < Severity.rank(Severity.HIGH)
    assert Severity.rank(Severity.HIGH) < Severity.rank(Severity.INFO)


def _sample_job():
    scope = ScopeRecord(target="https://example.com", host="example.com",
                        authorized_by="tester", attested=True)
    job = ScanJob(id="testjob01", scope=scope, polite=True, total_checks=1, completed_checks=1,
                  status="done")
    job.findings = [
        Finding("h1", "缺少安全標頭:CSP", Severity.MEDIUM, "說明", "加上 CSP", "evidence", ["http://ref"]),
        Finding("h2", "TLS 正常", Severity.INFO, "說明", "維持"),
        Finding("h3", "暴露的 .env", Severity.CRITICAL, "說明", "下架"),
    ]
    return job


def test_severity_counts():
    job = _sample_job()
    counts = job.severity_counts()
    assert counts["critical"] == 1
    assert counts["medium"] == 1
    assert counts["info"] == 1


def test_report_markdown_orders_critical_first():
    md = report.to_markdown(_sample_job())
    assert "弱點掃描報告" in md
    # critical 的標題應出現在 medium 之前
    assert md.index("暴露的 .env") < md.index("缺少安全標頭:CSP")


def test_report_json_and_html():
    job = _sample_job()
    assert '"target": "https://example.com"' in report.to_json(job)
    html = report.to_html(job)
    assert "<html" in html and "暴露的 .env" in html


def test_snapshot_shape():
    snap = _sample_job().snapshot()
    for key in ("id", "target", "status", "progress", "severity_counts", "findings"):
        assert key in snap
