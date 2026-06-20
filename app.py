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
    url_for,
)

from pentest import ai_advisor, report
from pentest.authorization import AuthorizationError, authorize
from pentest.scanner import ScanManager

app = Flask(__name__)
manager = ScanManager()


@app.route("/")
def index():
    return render_template("index.html", jobs=manager.list_jobs())


@app.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "")
    attested = request.form.get("attested") == "on"
    polite = request.form.get("polite", "on") == "on"
    try:
        scope = authorize(target, attested=attested)
    except AuthorizationError as exc:
        return render_template("index.html", jobs=manager.list_jobs(), error=str(exc)), 400

    job = manager.start(scope, polite=polite)
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
