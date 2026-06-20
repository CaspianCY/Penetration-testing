"""部署設定測試:DATABASE_URL 解析、密碼遮罩、登入保護。"""

import base64
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as _app  # 預設環境(sqlite),用來測純函式

_ENV_KEYS = ("DATABASE_URL", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
             "POSTGRES_HOST", "POSTGRES_PORT", "SENTINEL_PASSWORD", "PASSWORD",
             "PORT", "SENTINEL_PORT")


def _set_env(monkeypatch, env):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)


# ---- 純函式:不需重載 app(不會觸發 DB 連線)----

def test_database_url_from_postgres_components(monkeypatch):
    _set_env(monkeypatch, {
        "POSTGRES_USER": "root", "POSTGRES_PASSWORD": "p@ss/w0rd",
        "POSTGRES_DB": "zeabur", "POSTGRES_HOST": "db.internal", "POSTGRES_PORT": "5432",
    })
    url = _app._resolve_database_url()
    assert url.startswith("postgresql+psycopg://root:")
    assert "@db.internal:5432/zeabur" in url
    assert "p%40ss%2Fw0rd" in url            # 特殊字元已 URL-encode


def test_database_url_prefers_explicit(monkeypatch):
    _set_env(monkeypatch, {
        "DATABASE_URL": "postgresql+psycopg://u:pw@h/d",
        "POSTGRES_USER": "x", "POSTGRES_PASSWORD": "y", "POSTGRES_DB": "z",
    })
    assert _app._resolve_database_url() == "postgresql+psycopg://u:pw@h/d"


def test_database_url_falls_back_to_sqlite(monkeypatch):
    _set_env(monkeypatch, {})
    assert _app._resolve_database_url().startswith("sqlite:///")


def test_mask_hides_password():
    assert _app._mask("postgresql+psycopg://root:secret@h:5432/db") == \
        "postgresql+psycopg://root:***@h:5432/db"


def test_resolve_port_handles_non_numeric(monkeypatch):
    _set_env(monkeypatch, {"PORT": "${WEB_PORT}", "SENTINEL_PORT": "8080"})
    assert _app._resolve_port() == 8080      # PORT 非數字 → 退回 SENTINEL_PORT


def test_resolve_port_prefers_numeric_port(monkeypatch):
    _set_env(monkeypatch, {"PORT": "9000", "SENTINEL_PORT": "8080"})
    assert _app._resolve_port() == 9000


# ---- 登入保護:需重載 app(以 sqlite,不觸發外部 DB)----

def _reload_with(monkeypatch, env):
    _set_env(monkeypatch, env)
    return importlib.reload(_app)


def test_no_auth_when_password_unset(monkeypatch):
    app = _reload_with(monkeypatch, {})
    assert app.app.test_client().get("/").status_code == 200


def test_basic_auth_enforced(monkeypatch):
    app = _reload_with(monkeypatch, {"SENTINEL_PASSWORD": "letmein"})
    c = app.app.test_client()
    assert c.get("/").status_code == 401                         # 無認證 → 擋
    tok = base64.b64encode(b"sentinel:letmein").decode()
    assert c.get("/", headers={"Authorization": "Basic " + tok}).status_code == 200
    bad = base64.b64encode(b"sentinel:wrong").decode()
    assert c.get("/", headers={"Authorization": "Basic " + bad}).status_code == 401
    # 還原(避免影響其他測試模組)
    _reload_with(monkeypatch, {})
