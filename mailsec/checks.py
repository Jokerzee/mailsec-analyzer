"""把一封邮件拆成可解释的检查项。

每个 Finding 都带 severity 与证据，方便写报告时直接引用。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .parser import ParsedMail

AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "link", "icu", "buzz", "rest", "cam", "cyou",
}

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "hta", "bat", "cmd",
    "com", "pif", "lnk", "iso", "img", "docm", "xlsm", "pptm",
    "jar", "ps1", "msix", "appx", "wsf", "reg",
}

DOUBLE_EXTENSION_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|zip)"
    r"\.(exe|scr|js|jse|vbs|vbe|hta|bat|cmd|com|pif|lnk|iso|img|jar|ps1)$",
    re.IGNORECASE,
)

IP_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

URGENCY_KEYWORDS = [
    "紧急", "立即", "马上", "24小时", "账户异常", "账号异常", "密码过期",
    "验证", "冻结", "停用", "中奖", "退款", "发票", "汇款", "转账", "附件",
    "urgent", "immediately", "verify your account", "suspend", "suspended",
    "password expires", "invoice", "payment", "wire transfer", "click here",
    "within 24 hours", "final notice",
]

WEIGHTS = {"high": 30, "medium": 15, "low": 5, "info": 0}


@dataclass
class Finding:
    severity: str  # high | medium | low | info
    title: str
    detail: str
    evidence: str = ""


def _auth_verdicts(mail: ParsedMail) -> dict[str, list[str]]:
    verdicts: dict[str, list[str]] = {}
    for header in mail.auth_results:
        for mechanism, result in AUTH_RE.findall(header):
            verdicts.setdefault(mechanism.lower(), []).append(result.lower())
    return verdicts


def _check_authentication(mail: ParsedMail) -> list[Finding]:
    findings: list[Finding] = []
    verdicts = _auth_verdicts(mail)

    if not mail.auth_results:
        findings.append(
            Finding(
                "info",
                "缺少 Authentication-Results 头",
                "邮件头里没有 SPF/DKIM/DMARC 的验证结果，无法判断发件域是否被伪造。",
                "收件方或转发链可能剥掉了该头。",
            )
        )
        return findings

    spf = verdicts.get("spf", [])
    dkim = verdicts.get("dkim", [])
    dmarc = verdicts.get("dmarc", [])

    if "fail" in spf or "softfail" in spf:
        findings.append(
            Finding(
                "high",
                "SPF 验证失败",
                "发件 IP 不在该域声明的授权列表里，发件域很可能被伪造。",
                "spf=" + ",".join(spf),
            )
        )
    if "fail" in dmarc:
        findings.append(
            Finding(
                "high",
                "DMARC 验证失败",
                "From 域与 SPF/DKIM 对齐失败，这是伪造发件人的强信号。",
                "dmarc=" + ",".join(dmarc),
            )
        )
    if dkim and "fail" in dkim:
        findings.append(
            Finding(
                "medium",
                "DKIM 验证失败",
                "签名校验未通过，邮件内容可能在传输中被改动，或签名域不可信。",
                "dkim=" + ",".join(dkim),
            )
        )
    return findings


def _check_sender_consistency(mail: ParsedMail) -> list[Finding]:
    findings: list[Finding] = []

    if (
        mail.from_domain
        and mail.return_path_domain
        and mail.from_domain != mail.return_path_domain
    ):
        findings.append(
            Finding(
                "medium",
                "From 与 Return-Path 域名不一致",
                "显示发件人与实际信封发件人不一致。邮件列表、代发服务也会出现，需结合其他信号判断。",
                f"From={mail.from_domain} Return-Path={mail.return_path_domain}",
            )
        )

    if (
        mail.from_domain
        and mail.reply_to_domain
        and mail.from_domain != mail.reply_to_domain
    ):
        findings.append(
            Finding(
                "medium",
                "Reply-To 指向其他域名",
                "回复会发到另一个域，常见于钓鱼（收信人以为在回复原发件人）。",
                f"From={mail.from_domain} Reply-To={mail.reply_to_domain}",
            )
        )

    embedded = re.findall(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", mail.from_display, re.IGNORECASE)
    for addr in embedded:
        if domain_of_simple(addr) and domain_of_simple(addr) != mail.from_domain:
            findings.append(
                Finding(
                    "high",
                    "显示名里嵌入了另一个邮箱地址",
                    "收件人看到的“发件人”与真实地址不是同一个域，是典型伪装手法。",
                    f"显示名: {mail.from_display}",
                )
            )
            break

    return findings


def domain_of_simple(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower().strip(".") if "@" in addr else ""


def _check_urls(mail: ParsedMail) -> list[Finding]:
    findings: list[Finding] = []
    if not mail.urls:
        return findings

    ip_urls: list[str] = []
    punycode_urls: list[str] = []
    tld_urls: list[str] = []

    for url in mail.urls:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        if IP_HOST_RE.match(host):
            ip_urls.append(url)
        if host.startswith("xn--") or ".xn--" in host:
            punycode_urls.append(url)
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            tld_urls.append(url)

    if ip_urls:
        findings.append(
            Finding(
                "high",
                "URL 直接使用 IP 地址",
                "正常业务极少用裸 IP 承载登录页，常见于钓鱼基础设施。",
                "; ".join(ip_urls[:5]),
            )
        )
    if punycode_urls:
        findings.append(
            Finding(
                "high",
                "URL 含 Punycode 域名",
                "xn-- 开头的域名可能用同形字伪装成知名品牌。",
                "; ".join(punycode_urls[:5]),
            )
        )
    if tld_urls:
        findings.append(
            Finding(
                "medium",
                "URL 使用高风险顶级域",
                "该 TLD 注册便宜、滥用率高，需人工确认。",
                "; ".join(tld_urls[:5]),
            )
        )

    findings.append(
        Finding(
            "info",
            f"共发现 {len(mail.urls)} 个 URL",
            "已去重，默认输出时做 defang 处理，避免误点。",
            "; ".join(mail.urls[:10]),
        )
    )
    return findings


def _check_attachments(mail: ParsedMail) -> list[Finding]:
    findings: list[Finding] = []
    if not mail.attachments:
        return findings

    dangerous: list[str] = []
    double: list[str] = []
    for item in mail.attachments:
        name = item.filename.lower()
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS:
            dangerous.append(item.filename)
        if DOUBLE_EXTENSION_RE.search(name):
            double.append(item.filename)

    if double:
        findings.append(
            Finding(
                "high",
                "附件使用双扩展名",
                "文件名伪装成文档，实际是可执行文件。",
                "; ".join(double),
            )
        )
    if dangerous:
        findings.append(
            Finding(
                "high",
                "附件包含可执行/脚本类型",
                "打开即可能执行代码，除非确认来源，不要运行。",
                "; ".join(dangerous),
            )
        )

    findings.append(
        Finding(
            "info",
            f"共 {len(mail.attachments)} 个附件",
            "已计算 SHA-256，可拿到沙箱或威胁情报平台做进一步比对。",
            "; ".join(f"{a.filename} ({a.size}B)" for a in mail.attachments),
        )
    )
    return findings


def _check_social_engineering(mail: ParsedMail) -> list[Finding]:
    haystack = "\n".join([mail.subject, mail.text_body, mail.html_body]).lower()
    hits = [kw for kw in URGENCY_KEYWORDS if kw in haystack]
    if len(hits) >= 2:
        return [
            Finding(
                "low",
                "正文含催促/诱导性用语",
                "制造时间压力、要求点击或转账的措辞，是社工邮件的常见特征。",
                "命中: " + ", ".join(hits[:8]),
            )
        ]
    return []


def _check_headers(mail: ParsedMail) -> list[Finding]:
    findings: list[Finding] = []
    if not mail.received:
        findings.append(
            Finding(
                "info",
                "缺少 Received 头",
                "无法还原投递链路，可能被导出时剥离。",
            )
        )
    if not mail.message_id:
        findings.append(
            Finding(
                "low",
                "缺少 Message-ID",
                "正常邮件客户端都会生成，缺失可能是脚本伪造。",
            )
        )
    return findings


def run_checks(mail: ParsedMail) -> list[Finding]:
    """执行全部检查，按严重度排序返回。"""
    findings: list[Finding] = []
    findings += _check_authentication(mail)
    findings += _check_sender_consistency(mail)
    findings += _check_urls(mail)
    findings += _check_attachments(mail)
    findings += _check_social_engineering(mail)
    findings += _check_headers(mail)

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(findings, key=lambda f: order.get(f.severity, 9))


def score_findings(findings: list[Finding]) -> int:
    """0-100 的风险分，封顶 100。"""
    return min(100, sum(WEIGHTS.get(f.severity, 0) for f in findings))


def verdict_for(score: int) -> str:
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAN"
