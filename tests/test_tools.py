"""工具 adapter 的 parser 測試(用樣本輸出,不需安裝真工具)。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks.base import Severity
from pentest.tools import nmap_tool, nuclei_tool, nikto_tool, ffuf_tool, sqlmap_tool


def test_nmap_parse_flags_risky_service():
    out = """PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9
3306/tcp open  mysql   MySQL 8.0
"""
    fs = nmap_tool.parse(out)
    titles = {f.title.split(" — ")[0]: f.severity for f in fs}
    assert "開放埠 22/tcp" in titles and titles["開放埠 22/tcp"] == Severity.INFO
    assert "開放埠 3306/tcp" in titles and titles["開放埠 3306/tcp"] == Severity.MEDIUM
    assert all(f.tool == "nmap" for f in fs)


def test_nuclei_parse_maps_severity_cwe_attack():
    line = ('{"template-id":"CVE-2021-1234","matched-at":"http://t/x",'
            '"info":{"name":"Demo RCE","severity":"critical","tags":["cve","rce"],'
            '"classification":{"cve-id":["CVE-2021-1234"],"cwe-id":["CWE-78"]}}}')
    fs = nuclei_tool.parse(line)
    assert len(fs) == 1
    f = fs[0]
    assert f.severity == Severity.CRITICAL
    assert f.cwe == "CWE-78"
    assert f.attack.startswith("T1190")
    assert "CVE-2021-1234" in f.references[0]
    assert f.tool == "nuclei"


def test_nuclei_parse_ignores_noise_lines():
    out = "some status line\n{bad json\n" + (
        '{"template-id":"x","matched-at":"u","info":{"name":"N","severity":"low","tags":[]}}')
    fs = nuclei_tool.parse(out)
    assert len(fs) == 1 and fs[0].severity == Severity.LOW


def test_nikto_parse_skips_headers_flags_sensitive():
    out = "+ Target IP: 1.2.3.4\n+ Server: nginx\n+ /admin/: admin found\n+ OSVDB-1: /.git/: git dir\n"
    fs = nikto_tool.parse(out)
    titles = " ".join(f.title for f in fs)
    assert "Target IP" not in titles and "Server" not in titles
    assert any(f.severity == Severity.MEDIUM for f in fs)   # admin / .git


def test_ffuf_parse_flags_sensitive_paths():
    data = {"results": [
        {"input": {"FUZZ": "css"}, "status": 200, "url": "http://t/css"},
        {"input": {"FUZZ": ".env"}, "status": 200, "url": "http://t/.env"},
    ]}
    fs = ffuf_tool.parse_results(data)
    by = {f.location: f.severity for f in fs}
    assert by["/css"] == Severity.INFO
    assert by["/.env"] == Severity.MEDIUM


def test_sqlmap_is_vulnerable():
    assert sqlmap_tool.is_vulnerable("sqlmap identified the following injection point")
    assert sqlmap_tool.is_vulnerable("Parameter 'id' is vulnerable")
    assert not sqlmap_tool.is_vulnerable("all tested parameters do not appear to be injectable")


def test_adapters_registered():
    from pentest.tools import ADAPTERS, installed_summary
    names = {a.name for a in ADAPTERS}
    assert {"nmap", "nuclei", "ffuf", "nikto", "sqlmap"} <= names
    assert set(installed_summary().keys()) == names
