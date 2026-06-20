"""持久化層測試:使用暫存 SQLite 驗證寫入/讀回。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.authorization import ScopeRecord
from pentest.checks import Finding, Severity
from pentest.scanner import ScanJob
from pentest.storage import Storage


def _job(job_id="job-db-1"):
    scope = ScopeRecord(target="https://example.com", host="example.com",
                        authorized_by="tester", attested=True)
    return ScanJob(id=job_id, scope=scope, polite=True, total_checks=2)


def _storage(tmp_path):
    return Storage(f"sqlite:///{tmp_path}/sentinel.db")


def test_create_and_load(tmp_path):
    st = _storage(tmp_path)
    job = _job()
    st.create_scan(job)

    job.status = "running"
    st.update_scan(job)
    st.add_findings(job.id, [
        Finding("c1", "暴露的 .env", Severity.CRITICAL, "說明", "下架", "GET /.env -> 200", ["http://ref"]),
        Finding("c2", "缺少 CSP", Severity.MEDIUM, "說明", "加上 CSP"),
    ])
    job.completed_checks = 2
    job.status = "done"
    st.update_scan(job)

    loaded = st.load_job(job.id)
    assert loaded is not None
    assert loaded.status == "done"
    assert loaded.scope.authorized_by == "tester"
    assert len(loaded.findings) == 2
    counts = loaded.severity_counts()
    assert counts["critical"] == 1 and counts["medium"] == 1
    # references 與 evidence 應正確還原
    crit = next(f for f in loaded.findings if f.severity == Severity.CRITICAL)
    assert crit.references == ["http://ref"]
    assert crit.evidence == "GET /.env -> 200"


def test_save_ai_persists(tmp_path):
    st = _storage(tmp_path)
    job = _job("job-ai-1")
    st.create_scan(job)
    st.save_ai(job.id, "修補計畫:先處理 critical。", "rule-based")
    loaded = st.load_job(job.id)
    assert "修補計畫" in loaded.ai_summary


def test_list_recent(tmp_path):
    st = _storage(tmp_path)
    for i in range(3):
        st.create_scan(_job(f"job-{i}"))
    recent = st.list_recent(limit=10)
    assert len(recent) == 3
    assert all(j.scope.target == "https://example.com" for j in recent)


def test_load_missing_returns_none(tmp_path):
    st = _storage(tmp_path)
    assert st.load_job("nope") is None
