"""解析 .eml 文件，抽取分析所需的字段。"""

from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import parseaddr
from pathlib import Path

URL_RE = re.compile(r"""(?i)\b(?:https?|hxxps?|ftp)://[^\s<>"'`)\]]+""")


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedMail:
    path: str
    size: int
    subject: str
    from_display: str
    from_addr: str
    from_domain: str
    reply_to: str
    reply_to_domain: str
    return_path: str
    return_path_domain: str
    message_id: str
    date: str
    received: list[str] = field(default_factory=list)
    auth_results: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    urls: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)


def domain_of(value: str) -> str:
    """从 `Name <a@b.com>` 或裸地址里取出小写域名。"""
    _, addr = parseaddr(value or "")
    if "@" in addr:
        return addr.rsplit("@", 1)[1].lower().strip(".")
    return ""


def extract_urls(text: str) -> list[str]:
    """抽取 URL，去重并保持出现顺序。"""
    seen: set[str] = set()
    urls: list[str] = []
    for match in URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(".,;:!?)]}'\"")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _header(msg, name: str) -> str:
    value = msg.get(name)
    return str(value).strip() if value is not None else ""


def _payload_text(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _walk_parts(msg) -> tuple[str, str, list[Attachment]]:
    text_chunks: list[str] = []
    html_chunks: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        content_type = part.get_content_type()
        filename = part.get_filename()

        if filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=str(filename),
                    content_type=content_type,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
            continue

        if (part.get_content_disposition() or "").lower() == "attachment":
            continue

        if content_type == "text/plain":
            text_chunks.append(_payload_text(part))
        elif content_type == "text/html":
            html_chunks.append(_payload_text(part))

    return "\n".join(text_chunks), "\n".join(html_chunks), attachments


def parse_eml(path: str | Path) -> ParsedMail:
    """解析单个 .eml 文件。不发起任何网络请求。"""
    file_path = Path(path)
    raw = file_path.read_bytes()
    msg = email.message_from_bytes(raw, policy=policy.default)

    from_header = _header(msg, "From")
    from_display, from_addr = parseaddr(from_header)
    reply_to_header = _header(msg, "Reply-To")
    return_path_header = _header(msg, "Return-Path")

    text_body, html_body, attachments = _walk_parts(msg)
    urls = extract_urls(text_body + "\n" + html_body)

    return ParsedMail(
        path=str(file_path),
        size=len(raw),
        subject=_header(msg, "Subject"),
        from_display=from_display,
        from_addr=from_addr,
        from_domain=domain_of(from_header),
        reply_to=reply_to_header,
        reply_to_domain=domain_of(reply_to_header),
        return_path=return_path_header,
        return_path_domain=domain_of(return_path_header),
        message_id=_header(msg, "Message-ID"),
        date=_header(msg, "Date"),
        received=[str(item) for item in (msg.get_all("Received") or [])],
        auth_results=[
            str(item)
            for item in (msg.get_all("Authentication-Results") or [])
        ],
        text_body=text_body,
        html_body=html_body,
        urls=urls,
        attachments=attachments,
    )
