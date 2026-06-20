"""自我學習知識庫:記錄、取回、優先採用學過的方法。"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest import learning
from pentest.storage import Storage


def _store():
    return Storage("sqlite:///" + tempfile.mktemp(suffix=".db"))


def test_learn_and_recall_login_profile():
    st = _store()
    fp = {"frontend": ["React"], "backend": ["Express"]}
    learning.record_login(st, fp, {"kind": "api", "path": "/api/users/login"})
    learning.record_login(st, fp, {"kind": "api", "path": "/api/users/login"})  # 第二次成功
    assert learning.suggested_login_paths(st, fp, "api") == ["/api/users/login"]
    # 不同技術棧不會混用
    assert learning.suggested_login_paths(st, {"backend": ["PHP"]}, "api") == []


def test_learn_stack_findings_dedup_and_count():
    st = _store()
    fp = {"backend": ["Express"]}
    learning.record_stack_findings(st, fp, ["sqli", "xss", "sqli"])   # sqli 去重
    kinds = learning.likely_findings(st, fp)
    assert "sqli" in kinds and "xss" in kinds


def test_learning_summary_shapes():
    st = _store()
    fp = {"frontend": ["Vue"], "backend": ["Laravel (PHP)"]}
    learning.record_login(st, fp, {"kind": "form", "path": "/login"})
    learning.record_stack_findings(st, fp, ["idor"])
    s = st.learning_summary()
    assert s["total"] == 2
    assert "Vue|Laravel (PHP)" in s["stacks"]
    assert s["login_profiles"][0]["value"]["path"] == "/login"


def test_stack_key_stable():
    assert learning.stack_key({"frontend": ["React"], "backend": ["Express"]}) == "React|Express"
    assert learning.stack_key(None) == "?|?"
