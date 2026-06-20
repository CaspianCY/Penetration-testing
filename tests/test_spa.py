"""新版 Vue SPA(/app)外殼與其 JSON 端點的回歸測試。

SPA 本身在瀏覽器執行(無法在此跑 Vue),這裡只鎖定 Flask 端的契約:
/app 提供外殼、靜態資產可取、JSON 端點回傳預期結構,
以及 /scan、/sast 在帶 Accept: application/json 時走 JSON 分支。
"""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_app(monkeypatch, tmp_path):
    for k in ("DATABASE_URL", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
              "SENTINEL_PASSWORD", "PASSWORD", "SENTINEL_REQUIRE_PROXY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/spa.db")
    import app as _app
    return importlib.reload(_app)


def test_app_shell_is_homepage(monkeypatch, tmp_path):
    app_mod = _fresh_app(monkeypatch, tmp_path)
    client = app_mod.app.test_client()
    # 首頁(/)與 /app、/app/ 都應提供 SPA 外殼
    for path in ("/", "/app", "/app/"):
        r = client.get(path)
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert "spa.css" in html and "spa.js" in html
        assert "vue.global.prod.js" in html      # 本地自帶 Vue,不依賴外部 CDN
        assert 'id="app"' in html


def test_classic_ui_still_reachable(monkeypatch, tmp_path):
    app_mod = _fresh_app(monkeypatch, tmp_path)
    client = app_mod.app.test_client()
    r = client.get("/classic")
    assert r.status_code == 200
    assert "開始新掃描" in r.get_data(as_text=True)


def test_spa_static_assets(monkeypatch, tmp_path):
    app_mod = _fresh_app(monkeypatch, tmp_path)
    client = app_mod.app.test_client()
    css = client.get("/static/spa.css")
    js = client.get("/static/spa.js")
    vue = client.get("/static/vue.global.prod.js")
    assert css.status_code == 200 and len(css.get_data()) > 1000
    assert js.status_code == 200 and b"createApp" in js.get_data()
    assert vue.status_code == 200 and b"Vue" in vue.get_data()


def test_json_endpoints(monkeypatch, tmp_path):
    app_mod = _fresh_app(monkeypatch, tmp_path)
    client = app_mod.app.test_client()

    tools = client.get("/api/tools").get_json()
    assert "tools" in tools and isinstance(tools["tools"], dict)

    scans = client.get("/api/scans").get_json()
    assert "scans" in scans and isinstance(scans["scans"], list)

    learning = client.get("/api/learning").get_json()
    assert "total" in learning  # learning_summary 或錯誤回退皆含 total


def test_scan_json_branch_rejects_unauthorized(monkeypatch, tmp_path):
    app_mod = _fresh_app(monkeypatch, tmp_path)
    client = app_mod.app.test_client()
    # 未勾授權 → JSON 分支回 400 + error,而非重導 HTML
    r = client.post("/scan", data={"target": "https://example.com"},
                    headers={"Accept": "application/json"})
    assert r.status_code == 400
    body = r.get_json()
    assert body is not None and "error" in body


def test_scan_json_branch_starts_job(monkeypatch, tmp_path):
    app_mod = _fresh_app(monkeypatch, tmp_path)
    client = app_mod.app.test_client()
    r = client.post("/scan",
                    data={"target": "https://example.com", "attested": "on",
                          "crawl": "", "active": "", "polite": "on"},
                    headers={"Accept": "application/json"})
    assert r.status_code == 200
    body = r.get_json()
    assert body and "id" in body and "url" in body
    # 新建的 job 應可由 /api/scan/<id> 取得快照
    snap = client.get(f"/api/scan/{body['id']}").get_json()
    assert snap["id"] == body["id"]
    assert snap["target"] == "https://example.com"
    assert "phase_steps" in snap and "war" in snap and "attack_flow" in snap


def test_sast_json_branch_requires_attest(monkeypatch, tmp_path):
    app_mod = _fresh_app(monkeypatch, tmp_path)
    client = app_mod.app.test_client()
    # 未勾授權的白箱 → 仍回 HTML 400(JSON 分支只在成功/例外時觸發)
    r = client.post("/sast", data={"source_code": "x = 1"},
                    headers={"Accept": "application/json"})
    assert r.status_code == 400


def test_scan_print_and_docx_report_routes(monkeypatch, tmp_path):
    """掃描層級的列印(PDF)與 .docx 報告路由皆可用(修掉 SPA 先前 docx 連結 404)。"""
    app_mod = _fresh_app(monkeypatch, tmp_path)
    from pentest.authorization import ScopeRecord
    from pentest.checks.base import Finding, Severity
    from pentest.scanner import ScanJob
    scope = ScopeRecord(target="https://x/", host="x", authorized_by="self", attested=True)
    job = ScanJob(id="rep1", scope=scope, polite=True, _cookies={"sid": "1"})
    job.status = "done"
    job.findings = [Finding("auth-password-equals-username", "密碼與帳號相同", Severity.CRITICAL, "d", "r")]
    app_mod.manager._jobs["rep1"] = job
    client = app_mod.app.test_client()

    pr = client.get("/scan/rep1/report.print")
    assert pr.status_code == 200 and "滲透測試報告書" in pr.get_data(as_text=True)
    assert "另存 PDF" in pr.get_data(as_text=True)        # 列印頁含匯出引導

    dx = client.get("/scan/rep1/report.docx")
    assert dx.status_code == 200
    assert "wordprocessingml" in dx.content_type
