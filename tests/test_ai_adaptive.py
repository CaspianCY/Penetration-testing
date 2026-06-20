"""LLM 適應性測試建議(規則式後備路徑,確保無金鑰也可用且 payload 為偵測型)。"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import ai_adaptive
from pentest.authorization import ScopeRecord
from pentest.checks.base import Finding, ScanContext, Severity
from pentest.crawler import CrawlResult, InjectionPoint
from pentest.scanner import ScanJob


def _job_with_point():
    scope = ScopeRecord(target="https://t/", host="t", authorized_by="self", attested=True)
    job = ScanJob(id="j", scope=scope, polite=True)
    job.findings = [Finding("header-csp", "缺 CSP", Severity.MEDIUM, "d", "r")]
    ctx = ScanContext(target="https://t/")
    ctx.crawl_result = CrawlResult(
        pages=["https://t/"],
        injection_points=[InjectionPoint(method="GET", url="https://t/api/daily",
                                         params={"period": "202606"}, target_param="period")])
    job._ctx = ctx
    return job


def test_adaptive_rule_based_targets_discovered_endpoint(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = ai_adaptive.analyze(_job_with_point())
    assert out["model"] == "rule-based"
    assert out["test_cases"], "應對已發現端點產生測試案例"
    tc = out["test_cases"][0]
    assert tc["endpoint"] == "/api/daily" and tc["param"] == "period"
    assert tc["payloads"]


def test_adaptive_payloads_are_detection_only(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = ai_adaptive.analyze(_job_with_point())
    blob = json.dumps(out, ensure_ascii=False).lower()
    for bad in ("drop ", "delete ", "update ", "insert ", "os-shell", "--os-shell", "; rm "):
        assert bad not in blob                       # 不得含破壞性 / RCE 內容


def test_adaptive_handles_no_endpoints(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    scope = ScopeRecord(target="https://t/", host="t", authorized_by="self", attested=True)
    job = ScanJob(id="j2", scope=scope, polite=True)
    out = ai_adaptive.analyze(job)                   # 無 ctx / 無端點 → 仍給方向,不崩
    assert "model" in out and isinstance(out["focus"], list)
