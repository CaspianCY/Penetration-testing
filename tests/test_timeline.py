"""攻擊展示:作業時間軸、作戰階段步進器、即時戰情數據。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.authorization import ScopeRecord
from pentest.checks.base import Finding, Severity
from pentest.scanner import ScanJob


def _job(**kw):
    scope = ScopeRecord(target="https://a.test", host="a.test", authorized_by="t", attested=True)
    return ScanJob(id="j", scope=scope, polite=True, total_checks=6, **kw)


def test_add_event_and_snapshot_fields():
    job = _job()
    job.add_event("開始", icon="🚀", kind="start")
    snap = job.snapshot()
    for key in ("timeline", "phase_steps", "war", "current_phase"):
        assert key in snap
    assert snap["timeline"][0]["text"] == "開始"
    assert snap["timeline"][0]["kind"] == "start"
    assert "t" in snap["timeline"][0]               # 有時間戳記


def test_phase_steps_progress():
    job = _job()
    job.status = "running"
    job.current_phase = "exploitation"
    states = {s["key"]: s["state"] for s in job._phase_steps()}
    assert states["recon"] == "done" and states["vuln"] == "done"
    assert states["exploit"] == "current"
    assert states["post"] == "todo" and states["report"] == "todo"


def test_phase_steps_all_done_when_finished():
    job = _job()
    job.status = "done"
    job.current_phase = "reporting"
    assert all(s["state"] == "done" for s in job._phase_steps())


def test_war_stats_counts_real_findings():
    job = _job()
    job.crawl_summary = {"page_count": 9, "form_count": 2, "point_count": 4}
    job.completed_checks = 3
    job.findings = [
        Finding("active-sqli", "SQLi", Severity.CRITICAL, "d", "r"),
        Finding("surface", "面", Severity.INFO, "d", "r"),     # info 不算弱點
    ]
    w = job.war_stats()
    assert w["pages"] == 9 and w["forms"] == 2 and w["points"] == 4
    assert w["checks_done"] == 3 and w["checks_total"] == 6
    assert w["findings"] == 1


def test_timeline_capped():
    job = _job()
    for i in range(360):
        job.add_event(f"e{i}")
    assert len(job.timeline) <= 300
    assert job.timeline[-1]["text"] == "e359"        # 保留最新
