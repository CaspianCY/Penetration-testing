"""Web 路由:從掃描歸檔為案件並產生 .docx(補上 web 端產報告的缺口)。"""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_app(monkeypatch, tmp_path):
    for k in ("DATABASE_URL", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
              "SENTINEL_PASSWORD", "PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/web.db")
    import app as _app
    return importlib.reload(_app)


def _done_job(app_mod, sid="webjob01"):
    from pentest.authorization import ScopeRecord
    from pentest.checks.base import Finding, Severity
    from pentest.scanner import ScanJob
    from pentest.standards import enrich

    scope = ScopeRecord(target="https://example.com", host="example.com",
                        authorized_by="self", attested=True)
    job = ScanJob(id=sid, scope=scope, polite=True, active=True, status="done")
    job.findings = [
        enrich(Finding("active-sqli-id", "SQLi 注入點", Severity.CRITICAL, "d", "r"), "sqli"),
        enrich(Finding("header-missing-csp", "缺少 CSP", Severity.MEDIUM, "d", "r"), "header"),
    ]
    app_mod.manager._jobs[job.id] = job
    app_mod.storage.create_scan(job)
    return job


def test_scan_to_engagement_creates_docx(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path)
    job = _done_job(app)
    c = app.app.test_client()

    r = c.post(f"/scan/{job.id}/engagement", data={"name": "Demo", "tester": "T"})
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert "/engagements/" in loc
    eng_id = loc.rstrip("/").split("/")[-1]

    assert c.get(f"/engagements/{eng_id}").status_code == 200
    rep = c.get(f"/engagements/{eng_id}/report.docx")
    assert rep.status_code == 200
    assert len(rep.data) > 10000          # 確實產出非空 .docx

    importlib.reload(app)                  # 還原全域 app 狀態(避免影響其他模組)


def test_scan_to_engagement_requires_done(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path)
    job = _done_job(app, "webjob02")
    job.status = "running"                 # 未完成 → 不建立案件,導回掃描頁
    c = app.app.test_client()
    r = c.post(f"/scan/{job.id}/engagement")
    assert r.status_code == 302
    assert f"/scan/{job.id}" in r.headers["Location"]
    importlib.reload(app)
