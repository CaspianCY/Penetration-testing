"""攻擊流程(kill-chain)推導測試。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import attackflow
from pentest.checks.base import Finding, Severity


def _f(check_id, sev):
    return Finding(check_id, check_id, sev, "d", "r")


def test_depth_reaches_impact_with_exploit():
    flow = attackflow.build([
        _f("sast-sqli-x", Severity.CRITICAL),
        _f("header-missing-csp", Severity.MEDIUM),
    ])
    assert flow["depth_key"] == "impact"          # SQLi → 可造成影響
    assert flow["depth_label"] == "造成影響"
    # 偵察與漏洞利用都觸及,權限提升未觸及
    reached = {s["key"]: s["reached"] for s in flow["stages"]}
    assert reached["recon"] and reached["exploit"]
    assert not reached["escalate"]


def test_depth_only_recon_when_no_exploit():
    flow = attackflow.build([
        _f("header-missing-csp", Severity.MEDIUM),
        _f("cookie-flags-sid", Severity.MEDIUM),
    ])
    assert flow["depth_key"] == "recon"
    impact_stage = next(s for s in flow["stages"] if s["key"] == "impact")
    assert impact_stage["reached"] is False


def test_escalate_reached_with_idor():
    flow = attackflow.build([_f("active-idor-id", Severity.HIGH)])
    reached = {s["key"]: s["reached"] for s in flow["stages"]}
    assert reached["escalate"]
    assert reached["impact"]                       # IDOR → 可造成影響


def test_info_only_yields_no_path():
    flow = attackflow.build([_f("tls-ok", Severity.INFO), _f("info-none", Severity.INFO)])
    assert flow["depth_label"] == "未發現可利用路徑"
    assert flow["reached_count"] == 0


def test_chains_generated():
    flow = attackflow.build([
        _f("sast-sqli-x", Severity.CRITICAL),
        _f("active-xss-q", Severity.HIGH),
        _f("sast-secret-dburi", Severity.CRITICAL),
    ])
    names = " ".join(c["name"] for c in flow["chains"])
    assert "SQL Injection" in names
    assert "XSS" in names
    assert "憑證外洩" in names


def test_impact_findings_listed():
    flow = attackflow.build([_f("sast-cmdi-exec", Severity.CRITICAL)])
    impact = next(s for s in flow["stages"] if s["key"] == "impact")
    titles = [f["title"] for f in impact["findings"]]
    assert any("RCE" in t for t in titles)
