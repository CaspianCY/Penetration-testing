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
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024   # 白箱原始碼上傳上限 25MB

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


# 出口控管:設定 SENTINEL_REQUIRE_PROXY 後,沒有 Proxy/VPN 就不准掃描(避免用本機 IP)
_REQUIRE_PROXY = os.environ.get("SENTINEL_REQUIRE_PROXY", "").lower() in ("1", "true", "yes", "on")


def _parse_cookie_header(raw: str) -> dict:
    """把瀏覽器複製來的 Cookie 字串(k=v; k2=v2)解析成 dict。"""
    out: dict = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            if k:
                out[k] = v.strip()
    return out


def _resolve_proxy(form_val: str | None) -> str:
    """決定出口 Proxy:表單欄位優先,否則用環境變數(部署層可設固定 VPN 出口)。"""
    v = (form_val or "").strip()
    if v:
        return v
    return (os.environ.get("SENTINEL_PROXY") or os.environ.get("HTTPS_PROXY")
            or os.environ.get("ALL_PROXY") or "").strip()


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
@app.route("/app")
@app.route("/app/")
def index():
    """首頁 = 新版 Vue SPA(方法論分頁:黑/灰/白箱)。"""
    return render_template("app.html")


@app.route("/classic")
def classic_index():
    """舊版(經典)伺服器渲染介面,作為 SPA 的後備。"""
    return render_template("index.html", jobs=manager.list_jobs(), tools=_tools_summary())


@app.route("/api/tools")
def api_tools():
    return jsonify({"tools": _tools_summary()})


@app.route("/api/scans")
def api_scans():
    rows = [{"id": j.id, "target": j.scope.target, "status": j.status,
             "progress": j.progress} for j in manager.list_jobs()[:25]]
    return jsonify({"scans": rows})


@app.route("/api/learning")
def api_learning():
    try:
        return jsonify(storage.learning_summary())
    except Exception as exc:
        return jsonify({"error": str(exc), "total": 0})


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


def _safe_extract(zf, dest: str) -> int:
    """安全解壓(防 zip-slip),回傳解出的檔案數。"""
    import os as _os
    dest_abs = _os.path.abspath(dest)
    n = 0
    for member in zf.infolist()[:3000]:
        target = _os.path.abspath(_os.path.join(dest, member.filename))
        if target == dest_abs or target.startswith(dest_abs + _os.sep):
            zf.extract(member, dest)
            n += 1
    return n


@app.route("/sast", methods=["GET", "POST"])
def sast_view():
    """白箱:原始碼靜態分析(SAST)。貼上程式碼或上傳 .zip,產出 white-box 案件報告。"""
    if request.method == "GET":
        return render_template("sast.html")

    import shutil
    import tempfile
    import zipfile

    name = (request.form.get("name", "") or "").strip() or "白箱原始碼分析"
    tester = (request.form.get("tester", "") or "").strip() or "Sentinel 平台"
    if request.form.get("attested") != "on":
        return render_template("sast.html", error="請先確認你有權分析這份原始碼。"), 400

    tmp = tempfile.mkdtemp(prefix="sentinel_sast_")
    try:
        wrote = False
        up = request.files.get("source_zip")
        if up and up.filename:
            zpath = os.path.join(tmp, "_upload.zip")
            up.save(zpath)
            try:
                with zipfile.ZipFile(zpath) as zf:
                    wrote = _safe_extract(zf, tmp) > 0
            except zipfile.BadZipFile:
                return render_template("sast.html", error="上傳的不是有效的 .zip 檔。"), 400
            finally:
                if os.path.exists(zpath):
                    os.remove(zpath)
        code = request.form.get("source_code", "")
        if code.strip():
            fname = os.path.basename((request.form.get("filename", "") or "snippet.txt").strip()) or "snippet.txt"
            with open(os.path.join(tmp, fname), "w", encoding="utf-8") as fh:
                fh.write(code)
            wrote = True
        if not wrote:
            return render_template("sast.html", error="請貼上原始碼,或上傳 .zip 原始碼壓縮檔。"), 400

        from pentest.engagement import Engagement
        from pentest.sast import scan_path
        findings = scan_path(tmp, target_name=name)
        eng = Engagement(target=name, name=name, methodology="white-box",
                         test_type="SAST", tester=tester)
        eng.log_action("白箱 SAST 原始碼分析(由網站上傳)")
        storage.save_engagement(eng, findings)
        if "application/json" in request.headers.get("Accept", ""):
            return jsonify({"engagement_id": eng.id,
                            "url": url_for("engagement_view", eng_id=eng.id)})
        return redirect(url_for("engagement_view", eng_id=eng.id))
    except Exception as exc:
        if "application/json" in request.headers.get("Accept", ""):
            return jsonify({"error": f"分析失敗:{exc}"}), 500
        return render_template("sast.html", error=f"分析失敗:{exc}"), 500
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.route("/learning")
def learning_view():
    """自我學習中樞:平台從歷次掃描累積了哪些經驗。"""
    try:
        data = storage.learning_summary()
    except Exception as exc:
        data = {"total": 0, "categories": {}, "stacks": [], "login_profiles": [],
                "stack_findings": [], "error": str(exc)}
    return render_template("learning.html", data=data)


@app.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "")
    attested = request.form.get("attested") == "on"
    polite = request.form.get("polite", "on") == "on"
    active = request.form.get("active") == "on"
    aggressive = request.form.get("aggressive") == "on"
    deep = request.form.get("deep") == "on"
    crawl = request.form.get("crawl", "on") == "on"
    capture = request.form.get("capture") == "on"
    resilience = request.form.get("resilience") == "on"
    browser = request.form.get("browser") == "on"
    ai_autotest = request.form.get("ai_autotest") == "on"
    try:
        max_pages = max(1, min(int(request.form.get("max_pages", 40)), 100))
    except (TypeError, ValueError):
        max_pages = 40

    # 灰箱已認證掃描:使用者提供「自己的」帳密(僅對已授權目標)
    login = None
    login_url = request.form.get("login_url", "").strip()
    login_user = request.form.get("login_user", "").strip()
    login_pass = request.form.get("login_pass", "")
    if login_user and login_pass:          # 登入頁網址留空 → 由掃描器自動尋找登入頁 / 探測登入 API
        from pentest.auth_login import LoginSpec
        login = LoginSpec(
            url=login_url, username=login_user, password=login_pass,
            user_field=request.form.get("login_user_field", "").strip(),
            pass_field=request.form.get("login_pass_field", "").strip(),
            api_url=request.form.get("login_api", "").strip(),
        )
    resilience = resilience and login is not None

    # SPA / JS 登入無法自動處理時:直接貼上瀏覽器已登入的 Cookie / Authorization 權杖
    cookies = _parse_cookie_header(request.form.get("login_cookie", ""))
    auth_header = request.form.get("auth_header", "").strip()
    auth_headers = {"Authorization": auth_header} if auth_header else {}

    # SPA 的真正攻擊面:直接指定要主動測試的 API 端點(每行一個 URL)
    api_endpoints = [ln.strip() for ln in request.form.get("api_endpoints", "").splitlines()
                     if ln.strip().lower().startswith(("http://", "https://"))]

    wants_json = "application/json" in request.headers.get("Accept", "")

    def _err(msg):
        if wants_json:
            return jsonify({"error": msg}), 400
        return render_template("index.html", jobs=manager.list_jobs(),
                               tools=_tools_summary(), error=msg), 400

    # 出口控管:走指定的 Proxy / VPN 出口,而非平台本機 IP
    proxy = _resolve_proxy(request.form.get("proxy"))
    if proxy:
        from pentest.netcfg import valid_proxy
        if not valid_proxy(proxy):
            return _err("Proxy 格式不支援,請以 http://、https:// 或 socks5:// 開頭。")
    if _REQUIRE_PROXY and not proxy:
        return _err("本平台已設定必須經由 Proxy / VPN 出口(SENTINEL_REQUIRE_PROXY),"
                    "請填入出口 Proxy 後再掃描,以避免使用本機 IP。")

    # 主動測試 / 深度掃描 / 登入韌性測試 / AI 自動測試皆會主動送出測試流量,需額外授權確認
    if (active or deep or resilience or ai_autotest) and request.form.get("active_attested") != "on":
        return _err("啟用主動測試 / 深度掃描 / 登入韌性測試 / AI 自動測試需另外確認你已獲授權對目標送出測試流量。")
    if ai_autotest and not active:
        return _err("AI 閉環自動測試需同時勾選『主動測試』(它會自動送出偵測型探測)。")
    if resilience and login is None:
        return _err("登入韌性測試需要先填入登入網址與你自己的帳號/密碼。")
    if api_endpoints and not active:
        return _err("已指定 API 端點,但要對它們送出注入探測需同時勾選『主動測試』(並完成授權確認)。")
    try:
        scope = authorize(target, attested=attested)
    except AuthorizationError as exc:
        return _err(str(exc))

    job = manager.start(scope, polite=polite, active=active, aggressive=aggressive,
                        crawl=crawl, max_pages=max_pages, deep=deep,
                        login=login, capture=capture, resilience=resilience, proxy=proxy,
                        cookies=cookies, auth_headers=auth_headers, api_endpoints=api_endpoints,
                        browser=browser, ai_autotest=ai_autotest)
    if wants_json:
        return jsonify({"id": job.id, "url": url_for("scan_view", job_id=job.id)})
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


@app.route("/api/scan/<job_id>/adaptive", methods=["POST"])
def api_scan_adaptive(job_id: str):
    """LLM 適應性測試建議:看即時回應 → 動態建議下一步 + 針對性測試案例。"""
    from pentest import ai_adaptive

    job = manager.get(job_id)
    if not job:
        abort(404)
    try:
        result = ai_adaptive.analyze(job)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    result["model_name"] = ai_adaptive.model_name()
    return jsonify(result)


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

    # 依掃描設定推導方法論 / 測試類型(認證資訊在 job 上,不在 scope 上)
    test_type = "DAST"
    authenticated = bool(getattr(job, "_login", None) or getattr(job, "_cookies", None)
                         or getattr(job, "_auth_headers", None))
    methodology = "grey-box" if authenticated else "black-box"
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
