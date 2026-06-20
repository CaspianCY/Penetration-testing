"""工具 adapter 的 parser 測試(用樣本輸出,不需安裝真工具)。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest.checks.base import Severity
from pentest.tools import (
    nmap_tool, nuclei_tool, nikto_tool, ffuf_tool, sqlmap_tool,
    whatweb_tool, wafw00f_tool, sslscan_tool, wpscan_tool,
)


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


def test_nikto_parse_drops_tool_noise_and_dup_headers():
    """回歸:工具狀態 / 錯誤 / 平台無害資訊 / 與原生標頭檢查重複者一律不應成為 finding。
    先前報告被這類雜訊塞了十幾項 Low,嚴重稀釋專業度。"""
    out = (
        "+ ERROR: Failed to check for updates: 403\n"
        "+ ERROR: Host maximum execution time of 90 seconds reached\n"
        "+ 1 host(s) tested\n"
        "+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.\n"
        "+ Platform:           Unknown\n"
        "+ /: Uncommon header(s) 'x-zeabur-ip-country' found, with contents: JP.\n"
        "+ /: An alt-svc header was found which is advertising HTTP/3.\n"
        "+ /: Suggested security header missing: content-security-policy.\n"
        "+ /: Suggested security header missing: strict-transport-security.\n"
        "+ /: Retrieved x-powered-by header: Express.\n"
        "+ OSVDB-3092: /admin/: This might be interesting.\n"
    )
    fs = nikto_tool.parse(out)
    titles = " ".join(f.title for f in fs)
    # 雜訊全數丟棄
    for noise in ("Failed to check", "maximum execution", "host(s) tested", "CGI",
                  "Platform:", "x-zeabur", "alt-svc", "Suggested security header"):
        assert noise not in titles, noise
    # 技術指紋(x-powered-by)降為 INFO,不灌進 Low
    xpb = [f for f in fs if "x-powered-by" in f.title.lower()]
    assert xpb and xpb[0].severity == Severity.INFO
    # 真正的問題仍保留為 Medium
    assert any(f.severity == Severity.MEDIUM and "admin" in f.title.lower() for f in fs)


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


def test_whatweb_parse_lists_tech_and_flags_notable():
    fs = whatweb_tool.parse("http://x [200 OK] Apache[2.4], PHP[7.4], WordPress[6.0]")
    assert any("技術指紋" in f.title for f in fs)
    assert any("針對性測試" in f.title for f in fs)   # WordPress → notable
    assert all(f.tool == "whatweb" for f in fs)


def test_wafw00f_parse_detects_waf():
    fs = wafw00f_tool.parse("[+] The site http://x is behind Cloudflare (Cloudflare Inc.) WAF.")
    assert fs and "Cloudflare" in fs[0].title


def test_sslscan_parse_flags_weak_protocols():
    fs = sslscan_tool.parse("SSLv3      enabled\nTLSv1.0    enabled\nTLSv1.2    enabled")
    sevs = {f.title: f.severity for f in fs}
    assert any("SSLv3" in t and s == Severity.HIGH for t, s in sevs.items())
    assert any("TLSv1.0" in t and s == Severity.MEDIUM for t, s in sevs.items())
    # TLSv1.2 不應被標記
    assert not any("TLSv1.2" in t for t in sevs)


def test_wpscan_parse_version_vuln_users():
    out = ('{"version":{"number":"5.8","status":"insecure",'
           '"vulnerabilities":[{"title":"Core RCE","references":{"cve":["2021-1111"]}}]},'
           '"plugins":{"akismet":{"vulnerabilities":[{"title":"Plugin XSS"}]}},'
           '"users":{"admin":{},"editor":{}}}')
    fs = wpscan_tool.parse(out)
    titles = " ".join(f.title for f in fs)
    assert "WordPress 版本 5.8" in titles
    assert any(f.severity == Severity.HIGH for f in fs)        # 核心 + 外掛弱點
    assert "2 個 WordPress 使用者" in titles                    # 列舉到 admin/editor


def test_wpscan_parse_not_wordpress():
    fs = wpscan_tool.parse("The remote website is up, but does not seem to be running WordPress.")
    assert fs and "非 WordPress" in fs[0].title


def test_adapters_registered():
    from pentest.tools import ADAPTERS, installed_summary
    names = {a.name for a in ADAPTERS}
    assert {"nmap", "nuclei", "ffuf", "nikto", "sqlmap",
            "whatweb", "wafw00f", "sslscan", "wpscan"} <= names
    assert set(installed_summary().keys()) == names
