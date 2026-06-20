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


def test_weak_credential_reaches_exploitation():
    """回歸:密碼=帳號 / 弱憑證(可直接登入)應計入『漏洞利用 / 取得進入點』,
    不可再出現『有 Critical 卻卡在偵察』的矛盾。"""
    flow = attackflow.build([_f("auth-password-equals-username", Severity.CRITICAL)])
    reached = {s["key"]: s["reached"] for s in flow["stages"]}
    assert reached["exploit"]                       # 取得進入點(初始存取)
    assert flow["depth_key"] != "recon"             # 不再卡在偵察


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


# ---- 「為什麼打不進去 / 卡在哪」 ----

def _exploit_block(flow):
    return next(s for s in flow["stages"] if s["key"] == "exploit")["block"]


def test_blocked_when_active_not_run():
    flow = attackflow.build([_f("header-missing-csp", Severity.MEDIUM)],
                            context={"active_tested": False})
    assert flow["wall_key"] == "exploit"
    assert "未啟用主動測試" in _exploit_block(flow)["reason"]
    assert "卡在" in flow["blocked_summary"]


def test_blocked_by_waf():
    flow = attackflow.build([_f("header-missing-csp", Severity.MEDIUM)],
                            context={"active_tested": True, "waf": True, "injection_points": 5})
    assert "WAF" in _exploit_block(flow)["reason"]


def test_blocked_no_injectable_surface():
    flow = attackflow.build([_f("header-missing-csp", Severity.MEDIUM)],
                            context={"active_tested": True, "injection_points": 0, "form_count": 0})
    assert "找不到可注入" in _exploit_block(flow)["reason"]


def test_blocked_inputs_handled():
    flow = attackflow.build([_f("header-missing-csp", Severity.MEDIUM)],
                            context={"active_tested": True, "injection_points": 7})
    blk = _exploit_block(flow)
    assert "注入未成立" in blk["reason"]
    assert "7" in blk["detail"]


def test_reached_stage_has_no_block():
    flow = attackflow.build([_f("sast-sqli-x", Severity.CRITICAL)])
    exploit = next(s for s in flow["stages"] if s["key"] == "exploit")
    assert exploit["reached"] and exploit["block"] is None


def test_fully_breached_flag():
    flow = attackflow.build([_f("sast-sqli-x", Severity.CRITICAL)])
    assert flow["fully_breached"] is True
    assert flow["wall_key"] == ""
    assert "貫穿" in flow["blocked_summary"]


def test_signal_inferred_from_surface_finding():
    surface = Finding("surface-coverage", "攻擊面盤點", Severity.INFO,
                      "涵蓋頁面 10 個、表單 0 個、可注入端點 0 個。", "r")
    active = Finding("active-probe-done", "主動測試", Severity.INFO, "d", "r")
    flow = attackflow.build([surface, active,
                             _f("header-missing-csp", Severity.MEDIUM)])
    # 反推:跑過主動測試(有 active-*)、可注入端點 0 → 找不到輸入點
    assert "找不到可注入" in _exploit_block(flow)["reason"]
