import unittest
from pathlib import Path

from mailsec.checks import run_checks, score_findings, verdict_for
from mailsec.parser import parse_eml

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "phish-sample.eml"


class ParserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mail = parse_eml(SAMPLE)

    def test_sender_fields(self):
        self.assertEqual(self.mail.from_domain, "paypa1.com")
        self.assertIn("paypal", self.mail.from_display.lower())
        self.assertEqual(self.mail.reply_to_domain, "paypal-help.top")
        self.assertEqual(self.mail.return_path_domain, "mailer.xyz")

    def test_subject_is_decoded(self):
        self.assertIn("紧急", self.mail.subject)

    def test_urls_and_attachment(self):
        self.assertEqual(len(self.mail.urls), 3)
        self.assertEqual(len(self.mail.attachments), 1)
        self.assertEqual(self.mail.attachments[0].filename, "invoice.pdf.exe")
        self.assertEqual(len(self.mail.attachments[0].sha256), 64)


class ChecksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mail = parse_eml(SAMPLE)
        cls.findings = run_checks(cls.mail)
        cls.titles = [f.title for f in cls.findings]

    def test_auth_findings(self):
        self.assertTrue(any("SPF" in t for t in self.titles))
        self.assertTrue(any("DMARC" in t for t in self.titles))

    def test_sender_consistency_findings(self):
        self.assertTrue(any("Return-Path" in t for t in self.titles))
        self.assertTrue(any("Reply-To" in t for t in self.titles))
        self.assertTrue(any("显示名" in t for t in self.titles))

    def test_url_findings(self):
        self.assertTrue(any("IP 地址" in t for t in self.titles))
        self.assertTrue(any("Punycode" in t for t in self.titles))

    def test_attachment_findings(self):
        self.assertTrue(any("双扩展名" in t for t in self.titles))
        self.assertTrue(any("可执行" in t for t in self.titles))

    def test_score_and_verdict(self):
        score = score_findings(self.findings)
        self.assertGreaterEqual(score, 60)
        self.assertEqual(verdict_for(score), "HIGH")


if __name__ == "__main__":
    unittest.main()
