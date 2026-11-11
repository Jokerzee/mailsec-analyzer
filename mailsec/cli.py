"""命令行入口：mailsec analyze <file.eml> [...]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import run_checks, score_findings, verdict_for
from .parser import parse_eml
from .report import render_console, render_html, render_json, to_dict


def _write(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    print(f"[+] 已写出: {target}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailsec",
        description="离线邮件安全分析器：拆解钓鱼邮件的认证、发件人、URL、附件与社工特征。",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="分析一个或多个 .eml 文件")
    analyze.add_argument("files", nargs="+", help=".eml 文件路径")
    analyze.add_argument("--html", metavar="PATH", help="写出 HTML 报告")
    analyze.add_argument("--json", metavar="PATH", help="写出 JSON 结果")
    analyze.add_argument("--no-color", action="store_true", help="关闭终端颜色")
    analyze.add_argument(
        "--fail-on-high",
        action="store_true",
        help="存在 HIGH 判定时以退出码 1 结束，便于接 CI",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows 控制台默认可能是 GBK，统一按 UTF-8 输出，避免中文乱码。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    args = build_parser().parse_args(argv)
    if args.command != "analyze":
        return 2

    results = []
    any_high = False
    any_failed = False

    for file in args.files:
        try:
            mail = parse_eml(file)
        except OSError as exc:
            print(f"[!] 无法读取 {file}: {exc}", file=sys.stderr)
            any_failed = True
            continue

        findings = run_checks(mail)
        score = score_findings(findings)
        verdict = verdict_for(score)
        any_high = any_high or verdict == "HIGH"

        print(render_console(mail, findings, score, verdict, color=not args.no_color))
        results.append(to_dict(mail, findings, score, verdict))

    if not results and any_failed:
        return 2

    if args.html:
        _write(args.html, render_html(results))
    if args.json:
        _write(args.json, render_json(results))

    if args.fail_on_high and any_high:
        return 1
    return 1 if any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
