"""Sentinel — Flask 進入點與路由。

僅供授權安全測試使用。詳見 AUTHORIZATION.md。
"""

from __future__ import annotations

import hmac
import os
import re
from urllib.parse import quote_plus

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

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB = "sqlite:///" + os.path.join(_HERE, "sentinel.db")


def _resolve_database_url() -> str:
    """決定資料庫連線字串。

    優先 DATABASE_URL;否則由 POSTGRES_* 環境變數組合(適配 Zeabur 等平台);
    都沒有時退回本機 SQLite。
    """
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    user = os.environ.get("POSTGRES_USER")
    pw = os.environ.get("POSTGRES_PASSWORD")
    db = os.environ.get("POSTGRES_DB")
    if user and pw and db:
        host = (os.environ.get("POSTGRES_HOST")
                or os.environ.get("POSTGRESQL_HOST") or "postgresql")
        port = os.environ.get("POSTGRES_PORT", "5432")
        return f"postgresql+psycopg://{quote_plus(user)}:{quote_plus(pw)}@{host}:{port}/{db}"
    return _DEFAULT_DB


def _mask(url: str) -> str:
    return re.sub(r"://([^:/]+):([^@]+)@", r"://\1:***@", url or "")


def _resolve_port() -> int:
    for key in ("PORT", "SENTINEL_PORT"):
        v = os.environ.get(key, "")
        if v.isdigit():
            return int(v)
    return 5000


_DB_URL = _resolve_database_url()
storage = Storage(_DB_URL)
manager = ScanManager(storage=storage)

# 選用的 HTTP Basic 登入保護(公開部署強烈建議)。
# 設定 SENTINEL_PASSWORD(或 PASSWORD)即啟用;未設定則不啟用(本機方便用)。
_AUTH_USER = os.environ.get("SENTINEL_USER", "sentinel")
_AUTH_PASSWORD = os.environ.get("SENTINEL_PASSWORD") or os.environ.get("PASSWORD")


@app.before_request
def _require_login():
    if not _AUTH_PASSWORD:
        return None
    auth = request.authorization
    if (auth and auth.username == _AUTH_USER
            and hmac.compare_digest(auth.password or "", _AUTH_PASSWORD)):
        return None
    return Response(
        "需要登入。", 401,
        {"WWW-Authenticate": 'Basic realm="Sentinel"'},
    )


def _tools_summary() -> dict:
    try:
        from pentest.tools import installed_summary
        return installed_summary()
    except Exception:
        return {}


@app.route("/")
def index():
    return render_template("index.html", jobs=manager.list_jobs(), tools=_tools_summary())


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
    deep = request.form.get("deep") == "on"
    crawl = request.form.get("crawl", "on") == "on"
    try:
        max_pages = max(1, min(int(request.form.get("max_pages", 40)), 100))
    except (TypeError, ValueError):
        max_pages = 40
    # 主動測試 / 深度掃描皆會主動送出流量,需額外授權確認
    if (active or deep) and request.form.get("active_attested") != "on":
        err = "啟用主動測試 / 深度掃描需另外確認你已獲授權對目標送出測試流量。"
        return render_template("index.html", jobs=manager.list_jobs(), tools=_tools_summary(), error=err), 400
    try:
        scope = authorize(target, attested=attested)
    except AuthorizationError as exc:
        return render_template("index.html", jobs=manager.list_jobs(), tools=_tools_summary(), error=str(exc)), 400

    job = manager.start(scope, polite=polite, active=active, aggressive=aggressive,
                        crawl=crawl, max_pages=max_pages, deep=deep)
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


@app.route("/scan/<job_id>/engagement", methods=["POST"])
def scan_to_engagement(job_id: str):
    """把一次掃描歸檔為正式案件,並產出專業 .docx 報告。

    補上「網站只能跑掃描、無法產出 .docx」的缺口:web 使用者也能一鍵
    從掃描結果建立 Engagement 並下載 Volvo 規模的報告書。
    """
    from pentest.engagement import Engagement

    job = manager.get(job_id)
    if not job:
        abort(404)
    if job.status != "done":
        return redirect(url_for("scan_view", job_id=job_id))

    # 依掃描設定推導方法論 / 測試類型
    test_type = "DAST"
    methodology = "grey-box" if (job.scope.__dict__.get("auth_headers") or
                                 job.scope.__dict__.get("cookies")) else "black-box"
    name = (request.form.get("name") or "").strip() or f"{job.scope.target} 滲透測試"
    tester = (request.form.get("tester") or "").strip() or "Sentinel 平台"
    client = (request.form.get("client") or "").strip()

    eng = Engagement(
        target=job.scope.target, name=name, methodology=methodology,
        test_type=test_type, tester=tester, client=client,
        scope=[job.scope.target],
    )
    eng.log_action(f"由掃描任務 {job.id} 歸檔建立案件(模式:{'主動' if job.active else '被動'}"
                   f"{'+工具編排' if job.deep else ''})")
    try:
        storage.save_engagement(eng, job.findings)
    except Exception as exc:
        return render_template("scan.html", job=job,
                               error=f"建立案件失敗:{exc}"), 500
    return redirect(url_for("engagement_view", eng_id=eng.id))


def _startup_banner() -> None:
    """印出資料庫位置與現有筆數(密碼遮罩),讓使用者確認設定。"""
    print(f"[Sentinel] 資料庫:{_mask(_DB_URL)}")
    print(f"[Sentinel] 登入保護:{'啟用(HTTP Basic)' if _AUTH_PASSWORD else '未啟用 — 公開部署請設定 SENTINEL_PASSWORD'}")
    if _DB_URL.startswith("sqlite"):
        path = _DB_URL.replace("sqlite:///", "")
        exists = os.path.exists(path)
        print(f"[Sentinel] SQLite 檔:{path}（{'已存在' if exists else '將新建'}）")
        if not os.environ.get("DATABASE_URL"):
            print("[Sentinel] ⚠ 使用本機 SQLite。臨時/雲端環境重啟會清空,"
                  "要長期保存請設定 DATABASE_URL 或 POSTGRES_* 指向 PostgreSQL。")
    try:
        dd = storage.dashboard_data()
        print(f"[Sentinel] 現有資料:掃描 {dd['scans_total']} 筆、案件 {dd['engagements_total']} 筆、"
              f"弱點 {dd['findings_total']} 項")
    except Exception as exc:
        print(f"[Sentinel] (無法讀取現有資料:{exc})")


if __name__ == "__main__":
    host = os.environ.get("SENTINEL_HOST", "127.0.0.1")
    port = _resolve_port()
    _startup_banner()
    app.run(host=host, port=port, debug=False)
