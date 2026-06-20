"""白箱(SAST)網站介面:貼碼 / 上傳 zip → 產生 white-box 案件 + .docx。"""

import importlib
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_app(monkeypatch, tmp_path):
    for k in ("DATABASE_URL", "SENTINEL_PASSWORD", "PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/sast.db")
    import app as _app
    return importlib.reload(_app)


def test_sast_page_renders(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path)
    r = app.app.test_client().get("/sast")
    assert r.status_code == 200 and "白箱" in r.data.decode()
    importlib.reload(app)


def test_sast_paste_code_creates_whitebox_engagement(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path)
    c = app.app.test_client()
    vuln = 'cur.execute("SELECT * FROM users WHERE id = " + uid)\n'
    r = c.post("/sast", data={"name": "demo", "attested": "on",
                              "source_code": vuln, "filename": "db.py"})
    assert r.status_code == 302 and "/engagements/" in r.headers["Location"]
    eng_id = r.headers["Location"].rstrip("/").split("/")[-1]
    assert c.get(f"/engagements/{eng_id}").status_code == 200
    assert c.get(f"/engagements/{eng_id}/report.docx").status_code == 200
    importlib.reload(app)


def test_sast_requires_attestation(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path)
    r = app.app.test_client().post("/sast", data={"source_code": "x=1", "filename": "a.py"})
    assert r.status_code == 400
    importlib.reload(app)


def test_sast_zip_upload(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app/cfg.py", 'PASSWORD = "hardcoded-secret-123"\n')
        z.writestr("../evil.py", "x=1")          # zip-slip 嘗試,應被安全略過
    buf.seek(0)
    r = app.app.test_client().post(
        "/sast", data={"name": "zipapp", "attested": "on", "source_zip": (buf, "src.zip")},
        content_type="multipart/form-data")
    assert r.status_code == 302 and "/engagements/" in r.headers["Location"]
    # zip-slip 的檔案不該被寫到專案外
    assert not os.path.exists(os.path.join(os.path.dirname(tmp_path), "evil.py"))
    importlib.reload(app)
