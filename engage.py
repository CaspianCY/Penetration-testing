#!/usr/bin/env python3
"""Sentinel 案件編排 CLI — 依 PTES 階段執行一次完整測試並產出 .docx 報告。

依方法論支援:
  * 白箱(SAST)     :--sast <原始碼目錄>
  * 灰箱 / 黑箱(DAST):--dast <URL>(灰箱再加 --cookie / --header 帶認證)
  * hybrid          :同時提供 --sast 與 --dast

範例:
  # 白箱 SAST
  python engage.py --name "Volvo DMS" --sast ./examples/vulnerable_app \
      --methodology white-box --test-type SAST --tester "你的名字" --out volvo.docx

  # 灰箱 DAST(帶 session cookie)
  python engage.py --name "My App" --dast https://staging.example.com \
      --methodology grey-box --test-type DAST --cookie "session=abc" --active

僅供你擁有或已獲授權測試的目標使用。詳見 AUTHORIZATION.md。
"""

from __future__ import annotations

import argparse
import os
import sys

from pentest import docx_report
from pentest.checks import ACTIVE_CHECK, REGISTRY, ScanContext
from pentest.checks.base import Severity
from pentest.engagement import Engagement
from pentest.standards import enrich, kind_from_check_id


def _parse_kv(items, sep="="):
    out = {}
    for item in items or []:
        if sep in item:
            k, v = item.split(sep, 1)
            out[k.strip()] = v.strip()
    return out


def run_sast(engagement: Engagement, path: str) -> list:
    from pentest import sast

    engagement.log_action(f"[偵察/弱點分析] 白箱 SAST 掃描原始碼:{path}")
    target_name = engagement.name.lower().replace(" ", "-")[:24] or "target"
    findings = sast.scan_path(path, target_name=target_name)
    engagement.log_action(f"SAST 完成,findings={len(findings)}")
    return findings


def run_dast(engagement: Engagement, url: str, *, active: bool, aggressive: bool,
             cookies: dict, headers: dict, polite: bool, deep: bool = False) -> list:
    engagement.log_action(f"[偵察] DAST 目標:{url}(認證={'有' if cookies or headers else '無'})")

    def _console(line: str) -> None:
        print("   │ " + line)

    ctx = ScanContext(
        target=url, polite=polite, delay=0.2 if polite else 0,
        aggressive=aggressive, auth_headers=headers, cookies=cookies,
        emit=_console if deep else None,
    )
    findings = []
    checks = list(REGISTRY) + ([ACTIVE_CHECK] if active else [])
    if deep:
        from pentest.tools import ADAPTERS
        checks += [(a.name, a.label, a) for a in ADAPTERS]
    for check_id, label, module in checks:
        engagement.log_action(f"[弱點分析/漏洞利用驗證] {label}")
        print(f"   ▸ {label}")
        try:
            findings.extend(module.run(ctx))
        except Exception as exc:
            engagement.log_action(f"{label} 發生錯誤:{exc}")
    # 補上標準對應
    for f in findings:
        enrich(f, kind_from_check_id(f.check_id))
    engagement.log_action(f"DAST 完成,findings={len(findings)}")
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sentinel 滲透測試案件編排")
    ap.add_argument("--name", default="Untitled Engagement", help="評估對象名稱")
    ap.add_argument("--target", default="", help="目標識別(URL 或系統名;DAST 時可省略)")
    ap.add_argument("--sast", help="白箱:原始碼目錄路徑")
    ap.add_argument("--dast", help="灰/黑箱:目標 URL")
    ap.add_argument("--methodology", default="white-box",
                    choices=["white-box", "grey-box", "black-box"])
    ap.add_argument("--test-type", default="", choices=["", "SAST", "DAST", "hybrid"])
    ap.add_argument("--tester", default="(撰寫人姓名)")
    ap.add_argument("--client", default="")
    ap.add_argument("--active", action="store_true", help="DAST 啟用主動測試(注入/XSS)")
    ap.add_argument("--aggressive", action="store_true", help="主動測試含時間延遲偵測")
    ap.add_argument("--deep", action="store_true",
                    help="DAST 啟用工具編排(nmap/nuclei/ffuf/nikto/sqlmap/whatweb…),輸出寫進報告")
    ap.add_argument("--cookie", action="append", help="灰箱認證 Cookie,如 session=abc(可多次)")
    ap.add_argument("--header", action="append", help="灰箱認證標頭,如 'Authorization: Bearer x'(可多次)")
    ap.add_argument("--no-polite", action="store_true", help="關閉低衝擊限速")
    ap.add_argument("--out", default="", help="報告輸出路徑(.docx)")
    ap.add_argument("--db", default=os.environ.get("DATABASE_URL", ""),
                    help="資料庫連線字串(用於跨次稽核比對);留空則不持久化")
    args = ap.parse_args(argv)

    if not args.sast and not args.dast:
        ap.error("至少需提供 --sast 或 --dast")

    # 推導 test_type
    test_type = args.test_type
    if not test_type:
        test_type = "hybrid" if (args.sast and args.dast) else ("SAST" if args.sast else "DAST")

    target = args.target or args.dast or (args.sast or "")
    engagement = Engagement(
        target=target, name=args.name, methodology=args.methodology,
        test_type=test_type, tester=args.tester, client=args.client,
        scope=[s for s in [args.dast, args.sast] if s],
    )
    print(f"== Engagement {engagement.id} ==")
    print(f"   {args.name} | {args.methodology} {test_type} | 目標 {target}")

    findings = []
    if args.sast:
        findings += run_sast(engagement, args.sast)
    if args.dast:
        findings += run_dast(
            engagement, args.dast,
            active=args.active, aggressive=args.aggressive,
            cookies=_parse_kv(args.cookie), headers=_parse_kv(args.header, sep=":"),
            polite=not args.no_polite, deep=args.deep,
        )

    # 跨次稽核比對(若有 DB)
    previous = set()
    storage = None
    if args.db:
        try:
            from pentest.storage import Storage
            storage = Storage(args.db)
            previous = storage.previous_stable_ids(target, exclude_id=engagement.id)
        except Exception as exc:
            print(f"   (警告:資料庫無法使用,略過跨次比對:{exc})")

    # 統計
    counts = {s: 0 for s in Severity.ORDER}
    for f in findings:
        counts[f.severity] += 1
    print("   findings:",
          " ".join(f"{s}={counts[s]}" for s in Severity.ORDER))

    # 產出報告
    out = args.out or f"{engagement.id}.docx"
    docx_report.generate(engagement, findings, out, previous_stable_ids=previous)
    print(f"   報告已輸出:{out}")

    # 持久化(供下次比對)
    if storage:
        try:
            storage.save_engagement(engagement, findings)
            print("   已寫入資料庫(供下次稽核比對 New/Fixed/Recurring)")
        except Exception as exc:
            print(f"   (警告:寫入資料庫失敗:{exc})")

    # 清理/整合性聲明
    cleanup = engagement.cleanup_report()
    print(f"   整合性聲明:{cleanup['attestation']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
