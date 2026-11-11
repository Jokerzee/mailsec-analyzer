"""三种输出：终端、JSON、单文件 HTML。"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .checks import Finding
from .parser import ParsedMail

COLORS = {
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}


def defang(url: str) -> str:
    return (
        url.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
    )


def _color(text: str, severity: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS.get(severity, '')}{text}{COLORS['reset']}"


def render_console(
    mail: ParsedMail,
    findings: list[Finding],
    score: int,
    verdict: str,
    color: bool = True,
) -> str:
    lines: list[str] = []
    lines.append("")
    lines.append(_color(f"=== {mail.path} ===", verdict.lower() if verdict != "CLEAN" else "info", color))
    lines.append(f"Verdict: {verdict}  Score: {score}/100")
    lines.append(f"Subject: {mail.subject or '(无主题)'}")
    lines.append(f"From:    {mail.from_display} <{mail.from_addr}>")
    if mail.reply_to:
        lines.append(f"Reply-To:{mail.reply_to}")
    lines.append(f"Date:    {mail.date}")
    lines.append("-" * 60)

    if not findings:
        lines.append("未命中任何检查项。")
    for finding in findings:
        label = _color(f"[{finding.severity.upper()}]", finding.severity, color)
        lines.append(f"{label} {finding.title}")
        lines.append(f"  {finding.detail}")
        if finding.evidence:
            lines.append(f"  证据: {finding.evidence}")

    if mail.urls:
        lines.append("-" * 60)
        lines.append("URL（已 defang）:")
        for url in mail.urls:
            lines.append("  " + defang(url))

    if mail.attachments:
        lines.append("-" * 60)
        lines.append("附件:")
        for item in mail.attachments:
            lines.append(
                f"  {item.filename}  {item.size}B  {item.content_type}  sha256={item.sha256[:16]}…"
            )

    lines.append("")
    return "\n".join(lines)


def to_dict(mail: ParsedMail, findings: list[Finding], score: int, verdict: str) -> dict:
    return {
        "file": mail.path,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "score": score,
        "subject": mail.subject,
        "from": {
            "display": mail.from_display,
            "address": mail.from_addr,
            "domain": mail.from_domain,
        },
        "reply_to": mail.reply_to,
        "return_path": mail.return_path,
        "urls": [defang(u) for u in mail.urls],
        "attachments": [
            {
                "filename": a.filename,
                "content_type": a.content_type,
                "size": a.size,
                "sha256": a.sha256,
            }
            for a in mail.attachments
        ],
        "findings": [
            {
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }


def render_json(results: list[dict]) -> str:
    return json.dumps(results, ensure_ascii=False, indent=2)


def render_html(results: list[dict]) -> str:
    blocks = []
    for r in results:
        urls = "".join(f"<li><code>{html.escape(u)}</code></li>" for u in r["urls"])
        attachments = "".join(
            f"<li><code>{html.escape(a['filename'])}</code> — {a['size']}B — "
            f"SHA-256 <code>{a['sha256']}</code></li>"
            for a in r["attachments"]
        )
        finding_rows = "".join(
            "<tr>"
            f'<td><span class="badge {f["severity"]}">{f["severity"].upper()}</span></td>'
            f'<td><strong>{html.escape(f["title"])}</strong><br>'
            f'<span class="muted">{html.escape(f["detail"])}</span>'
            + (f'<br><code>{html.escape(f["evidence"])}</code>' if f["evidence"] else "")
            + "</td></tr>"
            for f in r["findings"]
        ) or '<tr><td colspan="2">未命中任何检查项。</td></tr>'

        blocks.append(
            f"""
<section>
  <h2>{html.escape(r["file"])}</h2>
  <p class="verdict {r["verdict"].lower()}">判定：{r["verdict"]} · 风险分 {r["score"]}/100</p>
  <dl>
    <dt>主题</dt><dd>{html.escape(r["subject"] or "(无主题)")}</dd>
    <dt>发件人</dt><dd>{html.escape(r["from"]["display"])} &lt;{html.escape(r["from"]["address"])}&gt;</dd>
    <dt>Reply-To</dt><dd>{html.escape(r["reply_to"] or "—")}</dd>
    <dt>Return-Path</dt><dd>{html.escape(r["return_path"] or "—")}</dd>
  </dl>
  <h3>检查项</h3>
  <table>{finding_rows}</table>
  <h3>URL（已 defang）</h3>
  <ul>{urls or "<li>无</li>"}</ul>
  <h3>附件</h3>
  <ul>{attachments or "<li>无</li>"}</ul>
</section>"""
        )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mailsec-analyzer 报告</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.6 -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0; padding: 32px; max-width: 960px; }}
  h1 {{ font-size: 24px; }}
  h2 {{ font-size: 18px; margin-top: 40px; border-bottom: 1px solid #8884; padding-bottom: 6px; }}
  h3 {{ font-size: 15px; margin-top: 24px; }}
  code {{ font-family: ui-monospace, Consolas, monospace; font-size: 13px; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ border-bottom: 1px solid #8883; padding: 8px 6px; vertical-align: top; }}
  .muted {{ color: #888; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; color: #fff; }}
  .badge.high {{ background: #c0392b; }}
  .badge.medium {{ background: #d68910; }}
  .badge.low {{ background: #2980b9; }}
  .badge.info {{ background: #7f8c8d; }}
  .verdict.high {{ color: #c0392b; font-weight: 700; }}
  .verdict.medium {{ color: #d68910; font-weight: 700; }}
  .verdict.low {{ color: #2980b9; font-weight: 700; }}
  .verdict.clean {{ color: #27ae60; font-weight: 700; }}
  dl {{ display: grid; grid-template-columns: 110px 1fr; gap: 4px 12px; }}
  dt {{ color: #888; }}
  dd {{ margin: 0; word-break: break-all; }}
  footer {{ margin-top: 48px; color: #888; font-size: 12px; }}
</style>
</head>
<body>
<h1>邮件安全分析报告</h1>
<p class="muted">生成时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} · 由 mailsec-analyzer 生成 · 全程离线</p>
{"".join(blocks)}
<footer>本报告仅基于邮件头、正文与附件特征做启发式判断，结论需人工复核。</footer>
</body>
</html>
"""
