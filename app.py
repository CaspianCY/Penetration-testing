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
# 未設定時退回單檔 SQLite,方便本機開發。
_DB_URL = os.environ.get("DATABASE_URL", "sqlite:///sentinel.db")
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
    # 主動測試需額外確認
    if active and request.form.get("active_attested") != "on":
        err = "啟用主動測試需另外確認你已獲授權對目標送出測試 payload。"
        return render_template("index.html", jobs=manager.list_jobs(), error=err), 400
    try:
        scope = authorize(target, attested=attested)
    except AuthorizationError as exc:
        return render_template("index.html", jobs=manager.list_jobs(), error=str(exc)), 400

    job = manager.start(scope, polite=polite, active=active, aggressive=aggressive)
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


if __name__ == "__main__":
    host = os.environ.get("SENTINEL_HOST", "127.0.0.1")
    port = int(os.environ.get("SENTINEL_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
