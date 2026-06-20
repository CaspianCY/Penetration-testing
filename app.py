"""Sentinel — Flask 進入點與路由。

僅供授權安全測試使用。詳見 AUTHORIZATION.md。
"""

from __future__ import annotations

import os

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from pentest import ai_advisor, report
from pentest.authorization import AuthorizationError, authorize
from pentest.scanner import ScanManager
from pentest.storage import Storage

app = Flask(__name__)

# 正式部署請設定 DATABASE_URL 指向 PostgreSQL,例如:
#   postgresql+psycopg://user:pass@localhost:5432/sentinel
#
# 未設定時退回單檔 SQLite。注意:SQLite 檔是本機檔案,且被 .gitignore 忽略,
# 在會被回收/重新 clone 的臨時環境(如雲端容器)中無法長期保存——要持久請用
# PostgreSQL。預設路徑採「絕對路徑」(錨定在本檔所在目錄),避免從不同工作目錄
# 啟動時各自產生不同的空白資料庫。
_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB = "sqlite:///" + os.path.join(_HERE, "sentinel.db")
_DB_URL = os.environ.get("DATABASE_URL", _DEFAULT_DB)
storage = Storage(_DB_URL)
manager = ScanManager(storage=storage)


@app.route("/")
def index():
    return render_template("index.html", jobs=manager.list_jobs())


@app.route("/dashboard")
def dashboard():
    try:
        data = storage.dashboard_data()
    except Exception as exc:
        data = {"error": str(exc)}
    return render_template("dashboard.html", d=data)


@app.route("/scans")
def scans_list():
    page = max(int(request.args.get("page", 1)), 1)
    per = 25
    rows = storage.list_scans(limit=per, offset=(page - 1) * per)
    total = storage.count_scans()
    return render_template("scans.html", rows=rows, page=page, per=per, total=total)


@app.route("/engagements")
def engagements_list():
    page = max(int(request.args.get("page", 1)), 1)
    per = 25
    rows = storage.list_engagements(limit=per, offset=(page - 1) * per)
    total = storage.count_engagements()
    return render_template("engagements.html", rows=rows, page=page, per=per, total=total)


@app.route("/engagements/<eng_id>")
def engagement_view(eng_id: str):
    from pentest import attackflow

    e = storage.load_engagement(eng_id)
    if not e:
        abort(404)
    flow = attackflow.build(e["findings"])
    return render_template("engagement.html", e=e, flow=flow)


@app.route("/engagements/<eng_id>/report.docx")
def engagement_report(eng_id: str):
    import tempfile

    from pentest import docx_report
    from pentest.checks.base import Finding
    from pentest.engagement import Engagement

    e = storage.load_engagement(eng_id)
    if not e:
        abort(404)
    eng = Engagement(
        target=e["target"], name=e["name"], methodology=e["methodology"],
        test_type=e["test_type"], tester=e["tester"], id=e["id"], created_at=e["created_at"],
    )
    findings = [Finding(**f) for f in e["findings"]]
    tmp = tempfile.NamedTemporaryFile(suffix=".docx", delete=False)
    tmp.close()
    docx_report.generate(eng, findings, tmp.name)
    return send_file(
        tmp.name, as_attachment=True, download_name=f"{eng_id}.docx",
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


@app.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "")
    attested = request.form.get("attested") == "on"
    polite = request.form.get("polite", "on") == "on"
    active = request.form.get("active") == "on"
    aggressive = request.form.get("aggressive") == "on"
    crawl = request.form.get("crawl", "on") == "on"
    try:
        max_pages = max(1, min(int(request.form.get("max_pages", 40)), 100))
    except (TypeError, ValueError):
        max_pages = 40
    # 主動測試需額外確認
    if active and request.form.get("active_attested") != "on":
        err = "啟用主動測試需另外確認你已獲授權對目標送出測試 payload。"
        return render_template("index.html", jobs=manager.list_jobs(), error=err), 400
    try:
        scope = authorize(target, attested=attested)
    except AuthorizationError as exc:
        return render_template("index.html", jobs=manager.list_jobs(), error=str(exc)), 400

    job = manager.start(scope, polite=polite, active=active, aggressive=aggressive,
                        crawl=crawl, max_pages=max_pages)
    return redirect(url_for("scan_view", job_id=job.id))


@app.route("/scan/<job_id>")
def scan_view(job_id: str):
    job = manager.get(job_id)
    if not job:
        abort(404)
    return render_template("scan.html", job=job)


@app.route("/api/scan/<job_id>")
def api_scan(job_id: str):
    job = manager.get(job_id)
    if not job:
        abort(404)
    return jsonify(job.snapshot())


@app.route("/api/scan/<job_id>/ai", methods=["POST"])
def api_scan_ai(job_id: str):
    job = manager.get(job_id)
    if not job:
        abort(404)
    if job.status != "done":
        return jsonify({"error": "掃描尚未完成,無法進行 AI 分析。"}), 409
    job.ai_summary = ai_advisor.analyze(job)
    try:
        storage.save_ai(job.id, job.ai_summary, ai_advisor.model_name())
    except Exception:
        pass
    return jsonify({"ai_summary": job.ai_summary})


@app.route("/scan/<job_id>/report.<fmt>")
def download_report(job_id: str, fmt: str):
    job = manager.get(job_id)
    if not job:
        abort(404)
    if fmt == "json":
        return Response(report.to_json(job), mimetype="application/json")
    if fmt == "md":
        return Response(report.to_markdown(job), mimetype="text/markdown")
    if fmt == "html":
        return Response(report.to_html(job), mimetype="text/html")
    abort(404)


def _startup_banner() -> None:
    """印出資料庫位置與現有筆數,讓使用者一眼看出資料存到哪、是否讀到空 DB。"""
    print(f"[Sentinel] 資料庫:{_DB_URL}")
    if _DB_URL.startswith("sqlite"):
        path = _DB_URL.replace("sqlite:///", "")
        exists = os.path.exists(path)
        print(f"[Sentinel] SQLite 檔:{path}（{'已存在' if exists else '將新建'}）")
        if not os.environ.get("DATABASE_URL"):
            print("[Sentinel] ⚠ 使用預設 SQLite。臨時環境(雲端容器)重啟會清空,"
                  "要長期保存請設定 DATABASE_URL 指向 PostgreSQL。")
    try:
        dd = storage.dashboard_data()
        print(f"[Sentinel] 現有資料:掃描 {dd['scans_total']} 筆、案件 {dd['engagements_total']} 筆、"
              f"弱點 {dd['findings_total']} 項")
    except Exception as exc:
        print(f"[Sentinel] (無法讀取現有資料:{exc})")


if __name__ == "__main__":
    host = os.environ.get("SENTINEL_HOST", "127.0.0.1")
    port = int(os.environ.get("SENTINEL_PORT", "5000"))
    _startup_banner()
    app.run(host=host, port=port, debug=False)
