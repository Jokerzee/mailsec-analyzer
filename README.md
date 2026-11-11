# mailsec-analyzer

离线邮件安全分析器。输入一个 `.eml` 文件，输出可解释的风险结论：认证结果、发件人一致性、URL 特征、附件类型、社工话术。

无第三方依赖，不上传任何数据，Python 3.9+。

## 为什么写这个

分析钓鱼邮件时，常见做法是把 `.eml` 丢进在线沙箱或 VirusTotal。但在很多场景里这行不通：客户邮件、内部邮件、带敏感信息的样本不能外传。

这个工具解决的是**第一分钟**的问题：在本地把邮件拆开，快速回答四个问题——

1. 发件域有没有通过 SPF/DKIM/DMARC？
2. 显示的发件人和真实信封发件人对得上吗？
3. 正文里的链接指向哪里？有没有 IP 直连、Punycode、可疑 TLD？
4. 附件是什么类型？哈希是多少？

它不替代沙箱和人工研判，但能让你在打开附件之前就知道该不该点。

## 特性

- **认证分析**：解析 `Authentication-Results` 中的 SPF / DKIM / DMARC 结果
- **发件人一致性**：`From` / `Return-Path` / `Reply-To` 交叉比对，识别显示名里嵌入地址的伪装
- **URL 分析**：裸 IP、Punycode（`xn--`）、高风险 TLD，输出自动 defang
- **附件分析**：危险扩展名、双扩展名（`invoice.pdf.exe`）、SHA-256
- **社工信号**：中英文催促/诱导话术命中
- **三种输出**：终端、JSON、单文件 HTML 报告
- **可接 CI**：`--fail-on-high` 在判定为 HIGH 时返回退出码 1

## 快速开始

```bash
git clone https://github.com/<your-name>/mailsec-analyzer.git
cd mailsec-analyzer

# 直接运行，无需安装
python -m mailsec analyze samples/phish-sample.eml

# 可选：安装后使用 mailsec 命令
pip install -e .
mailsec analyze samples/phish-sample.eml
```

生成报告：

```bash
python -m mailsec analyze samples/phish-sample.eml \
  --html out/report.html \
  --json out/report.json
```

实际输出（样本为合成数据）：

```text
=== samples/phish-sample.eml ===
Verdict: HIGH  Score: 100/100
Subject: 【紧急】您的账户将在24小时内被冻结，请立即验证
From:    PayPal Security service@paypal.com <notice@paypa1.com>
Reply-To:support@paypal-help.top
Date:    Mon, 09 Nov 2026 03:12:00 +0000
------------------------------------------------------------
[HIGH] SPF 验证失败
  发件 IP 不在该域声明的授权列表里，发件域很可能被伪造。
  证据: spf=fail
[HIGH] DMARC 验证失败
  From 域与 SPF/DKIM 对齐失败，这是伪造发件人的强信号。
  证据: dmarc=fail
[HIGH] 显示名里嵌入了另一个邮箱地址
  收件人看到的“发件人”与真实地址不是同一个域，是典型伪装手法。
  证据: 显示名: PayPal Security service@paypal.com
[HIGH] URL 直接使用 IP 地址
  正常业务极少用裸 IP 承载登录页，常见于钓鱼基础设施。
  证据: http://192.0.2.10/login
[HIGH] URL 含 Punycode 域名
  xn-- 开头的域名可能用同形字伪装成知名品牌。
  证据: https://xn--pypal-4ve.com/verify
[HIGH] 附件使用双扩展名
  文件名伪装成文档，实际是可执行文件。
  证据: invoice.pdf.exe
[HIGH] 附件包含可执行/脚本类型
  打开即可能执行代码，除非确认来源，不要运行。
  证据: invoice.pdf.exe
[MEDIUM] From 与 Return-Path 域名不一致
  显示发件人与实际信封发件人不一致。邮件列表、代发服务也会出现，需结合其他信号判断。
  证据: From=paypa1.com Return-Path=mailer.xyz
[MEDIUM] Reply-To 指向其他域名
  回复会发到另一个域，常见于钓鱼（收信人以为在回复原发件人）。
  证据: From=paypa1.com Reply-To=paypal-help.top
[LOW] 正文含催促/诱导性用语
  制造时间压力、要求点击或转账的措辞，是社工邮件的常见特征。
  证据: 命中: 紧急, 立即, 24小时, 验证, 附件, immediately, verify your account, suspend
[INFO] 共发现 3 个 URL
[INFO] 共 1 个附件
------------------------------------------------------------
URL（已 defang）:
  hxxp://192[.]0[.]2[.]10/login
  hxxps://xn--pypal-4ve[.]com/verify
  hxxps://paypa1[.]com/account/verify?token=abc123
```

## 检查项

| 类别 | 检查 | 严重度 |
| --- | --- | --- |
| 认证 | SPF fail / softfail | HIGH |
| 认证 | DMARC fail | HIGH |
| 认证 | DKIM fail | MEDIUM |
| 认证 | 缺少 `Authentication-Results` | INFO |
| 发件人 | 显示名嵌入另一邮箱地址 | HIGH |
| 发件人 | `From` 与 `Return-Path` 域名不一致 | MEDIUM |
| 发件人 | `Reply-To` 指向其他域名 | MEDIUM |
| URL | 裸 IP 地址 | HIGH |
| URL | Punycode（`xn--`） | HIGH |
| URL | 高风险 TLD | MEDIUM |
| 附件 | 双扩展名 | HIGH |
| 附件 | 可执行/脚本扩展名 | HIGH |
| 附件 | SHA-256 与大小 | INFO |
| 社工 | 催促/诱导关键词 ≥ 2 个 | LOW |
| 邮件头 | 缺少 `Received` | INFO |
| 邮件头 | 缺少 `Message-ID` | LOW |

风险分 = 各检查项权重之和（HIGH 30 / MEDIUM 15 / LOW 5 / INFO 0），封顶 100。

- `≥ 60` → HIGH
- `≥ 30` → MEDIUM
- `> 0` → LOW
- `0` → CLEAN

## 项目结构

```text
mailsec-analyzer/
├── mailsec/
│   ├── parser.py    # .eml 解析、URL/附件抽取
│   ├── checks.py    # 检查项与打分
│   ├── report.py    # 终端 / JSON / HTML 输出
│   └── cli.py       # 命令行入口
├── samples/
│   └── phish-sample.eml
├── tests/
│   └── test_smoke.py
└── pyproject.toml
```

## 开发

```bash
python -m unittest discover -s tests -v
```

## 路线图

- [ ] HTML 锚文本与 `href` 不一致检测
- [ ] `Received` 链路逐跳分析，提取首发 IP
- [ ] 批量目录扫描与 CSV 汇总
- [ ] 可选在线校验（DNS / 威胁情报），默认关闭
- [ ] 规则 YAML 化，支持自定义检查项
- [ ] 输出 STIX 2.1 指标

## 免责声明

只分析你有权处理的邮件。不要提交客户数据或内部邮件到公开仓库。本工具基于邮件头、正文和附件特征做启发式判断，结论必须人工复核，不能替代沙箱动态分析。

## License

MIT
