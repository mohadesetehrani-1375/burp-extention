#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
common.py
==========
کد مشترک برای اسکریپت‌های مستقل OWASP API Security Top 10 (2023)
هر اسکریپت جداگانه اجرا می‌شود و حتماً باید آدرس هدف (IP یا API) را بگیرد.
هیچ مقدار پیش‌فرضی برای target وجود ندارد.

نیازمندی: Python 3.8+ و کتابخانه requests
  pip install requests
"""

from __future__ import print_function

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from collections import defaultdict
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# اطمینان از پیدا شدن این فایل وقتی از پوشه‌های دیگر اجرا می‌شود
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

try:
    import requests
except ImportError:
    sys.stderr.write(
        "\n[خطا] کتابخانه 'requests' نصب نیست.\n"
        "نصب کنید با دستور:\n"
        "    pip install requests\n\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# مدل Finding و گزارش
# ---------------------------------------------------------------------------

class Finding(object):
    def __init__(self, category, name, severity, confidence, detail,
                 remediation, method=None, url=None, status=None,
                 evidence=None):
        self.category = category
        self.name = name
        self.severity = severity        # High / Medium / Low / Information
        self.confidence = confidence    # Certain / Firm / Tentative
        self.detail = detail
        self.remediation = remediation
        self.method = method
        self.url = url
        self.status = status
        self.evidence = evidence or ""
        self.time = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_console(self):
        lines = []
        lines.append("-" * 78)
        lines.append("[%s] %s  (severity=%s, confidence=%s)" % (
            self.category, self.name, self.severity, self.confidence))
        if self.method and self.url:
            lines.append("  %s %s -> HTTP %s" % (self.method, self.url, self.status))
        lines.append("  " + self.detail.replace("\n", "\n  "))
        if self.evidence:
            lines.append("  Evidence: " + self.evidence.replace("\n", "\n  "))
        lines.append("  Remediation: " + self.remediation)
        return "\n".join(lines)

    def to_dict(self):
        return {
            "category": self.category,
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "detail": self.detail,
            "remediation": self.remediation,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "evidence": self.evidence,
            "time": self.time,
        }

    def to_md(self, index):
        lines = []
        lines.append("### %d. [%s] %s" % (index, self.category, self.name))
        lines.append("")
        lines.append("- **Severity:** %s" % self.severity)
        lines.append("- **Confidence:** %s" % self.confidence)
        lines.append("- **Time:** %s" % self.time)
        if self.method and self.url:
            lines.append("- **Request:** `%s %s` -> HTTP %s" % (self.method, self.url, self.status))
        lines.append("")
        lines.append(self.detail)
        if self.evidence:
            lines.append("")
            lines.append("```")
            lines.append(self.evidence)
            lines.append("```")
        lines.append("")
        lines.append("**Remediation:** %s" % self.remediation)
        lines.append("")
        return "\n".join(lines)


class Report(object):
    def __init__(self, script_name, target):
        self.script_name = script_name
        self.target = target
        self.findings = []

    def add(self, finding):
        self.findings.append(finding)
        print(finding.to_console())
        return finding

    def summary(self):
        by_sev = defaultdict(int)
        for f in self.findings:
            by_sev[f.severity] += 1
        print("=" * 78)
        print("%s - %d finding(s) against %s" % (self.script_name, len(self.findings), self.target))
        for sev in ("High", "Medium", "Low", "Information"):
            if by_sev[sev]:
                print("  %s: %d" % (sev, by_sev[sev]))
        print("=" * 78)

    def to_json_obj(self):
        by_sev = defaultdict(int)
        for f in self.findings:
            by_sev[f.severity] += 1
        return {
            "script": self.script_name,
            "target": self.target,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(self.findings),
            "findings_by_severity": dict(by_sev),
            "findings": [f.to_dict() for f in self.findings],
        }

    def export_json(self, path):
        obj = self.to_json_obj()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
        print("\n[OK] گزارش JSON ذخیره شد: %s" % path)
        return path

    def export_md(self, path):
        lines = []
        lines.append("# %s - findings" % self.script_name)
        lines.append("")
        lines.append("Target: `%s`  " % self.target)
        lines.append("Generated: %s  " % time.strftime("%Y-%m-%d %H:%M:%S"))
        lines.append("Total findings: %d" % len(self.findings))
        lines.append("")
        if not self.findings:
            lines.append("_No findings._")
        else:
            for i, f in enumerate(self.findings, 1):
                lines.append(f.to_md(i))
        text = "\n".join(lines)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("\n[OK] گزارش Markdown ذخیره شد: %s" % path)
        return path


# ---------------------------------------------------------------------------
# argparse + حالت تعاملی
# ---------------------------------------------------------------------------

def build_arg_parser(description):
    """
    --target را اجباری می‌کند، اما اگر کاربر هیچ آرگومانی ندهد،
    بعداً در parse_args_smart به صورت تعاملی می‌پرسیم.
    """
    p = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "مثال‌ها:\n"
            "  python3 %(prog)s --target https://api.example.com\n"
            "  python3 %(prog)s --target 192.168.1.10:8443 --paths /api/v1/users/1 --auth \"Bearer TOKEN\"\n"
            "  python3 %(prog)s   (بدون آرگومان → حالت تعاملی فعال می‌شود)\n"
        )
    )
    p.add_argument(
        "--target", default=None,
        help="آدرس هدف (اجباری). مثال: 192.168.1.10:8443 یا https://api.example.com "
             "— هیچ مقدار پیش‌فرضی وجود ندارد."
    )
    p.add_argument(
        "--paths", default="",
        help="لیست مسیرهای API با کاما جدا شده. مثال: /api/v1/users,/api/v1/orders/1 "
             "اگر ندهید، لیست نمونه کوچک داخلی استفاده می‌شود."
    )
    p.add_argument(
        "--auth", default=None,
        help="مقدار هدر Authorization یا Cookie. مثال: \"Bearer eyJ...\" یا \"session=abc\""
    )
    p.add_argument(
        "--alt-auth", default=None,
        help="توکن/کوکی هویت دوم (برای تست BOLA/BFLA). فقط با --active معنی دارد."
    )
    p.add_argument(
        "--insecure", action="store_true",
        help="چک گواهی TLS را غیرفعال می‌کند (فقط برای محیط تست با گواهی self-signed)."
    )
    p.add_argument(
        "--timeout", type=float, default=10.0,
        help="تایم‌اوت هر درخواست به ثانیه (پیش‌فرض ۱۰)."
    )
    p.add_argument(
        "--active", action="store_true",
        help="فعال‌سازی پروب‌های Active (درخواست اضافه می‌فرستد). پیش‌فرض خاموش است."
    )
    p.add_argument(
        "--export-md", default=None, metavar="PATH",
        help="ذخیره گزارش Markdown در مسیر مشخص‌شده (اختیاری)."
    )
    p.add_argument(
        "--interactive", "-i", action="store_true",
        help="حتی اگر --target داده شده باشد، از حالت تعاملی برای بقیه پارامترها استفاده کن."
    )
    return p


def _prompt(msg, default=None):
    """پرسش تعاملی ساده."""
    if default:
        full = "%s [%s]: " % (msg, default)
    else:
        full = "%s: " % msg
    try:
        val = input(full)
    except (EOFError, KeyboardInterrupt):
        print("\n[لغو شد]")
        sys.exit(1)
    val = (val or "").strip()
    return val if val else default


def parse_args_smart(parser):
    """
    اگر --target داده نشده باشد، به صورت تعاملی می‌پرسد.
    این همان چیزی است که مشکل «ورودی نمی‌گیرد» را حل می‌کند.
    """
    # اگر هیچ آرگومانی داده نشده، مستقیماً به حالت تعاملی برو
    if len(sys.argv) == 1:
        print("=" * 60)
        print("  حالت تعاملی فعال شد (هیچ آرگومانی داده نشده)")
        print("  برای استفاده از فلگ‌ها: python3 %s --target <آدرس>" % os.path.basename(sys.argv[0]))
        print("=" * 60)
        args = parser.parse_args([])          # همه چیز None/default
        args.interactive = True
    else:
        args = parser.parse_args()

    # --- target اجباری ---
    if not args.target:
        print("\n[!] آدرس هدف (--target) مشخص نشده.")
        print("    مثال: 192.168.1.50:8899   یا   https://api.example.com")
        args.target = _prompt("آدرس IP یا URL هدف را وارد کنید")
        if not args.target:
            sys.stderr.write("\n[خطا] بدون آدرس هدف نمی‌توان ادامه داد.\n")
            sys.exit(1)

    # اگر کاربر -i زده یا از حالت بدون‌آرگومان آمده
    if getattr(args, "interactive", False) or (len(sys.argv) == 1):
        if not args.paths:
            paths_in = _prompt("مسیرهای API (با کاما جدا کنید، خالی = نمونه داخلی)", "")
            if paths_in:
                args.paths = paths_in
        if not args.auth:
            auth_in = _prompt("هدر Authorization یا Cookie (اختیاری، Enter برای رد کردن)", "")
            if auth_in:
                args.auth = auth_in
        if not args.alt_auth:
            alt_in = _prompt("توکن هویت دوم --alt-auth (اختیاری)", "")
            if alt_in:
                args.alt_auth = alt_in
        active_in = _prompt("فعال‌سازی پروب Active؟ (y/N)", "N")
        if active_in and active_in.lower() in ("y", "yes", "1", "بله"):
            args.active = True
        insecure_in = _prompt("رد کردن چک TLS؟ (y/N)", "N")
        if insecure_in and insecure_in.lower() in ("y", "yes", "1", "بله"):
            args.insecure = True

    return args


def desktop_dir():
    """
    مسیر Desktop را برمی‌گرداند.
    اگر پوشه Desktop وجود نداشت، آن را می‌سازد.
    """
    home = os.path.expanduser("~")
    desktop = os.path.join(home, "Desktop")
    if not os.path.isdir(desktop):
        try:
            os.makedirs(desktop)
            print("[i] پوشه Desktop ساخته شد: %s" % desktop)
        except Exception:
            return home
    return desktop


def auto_export_json(report, script_slug):
    """
    همیشه در پایان هر اسکریپت صدا زده می‌شود.
    گزارش JSON را روی Desktop ذخیره می‌کند (بدون نیاز به هیچ فلگی).
    """
    ts = time.strftime("%Y%m%d_%H%M%S")
    filename = "owasp_%s_findings_%s.json" % (script_slug, ts)
    path = os.path.join(desktop_dir(), filename)
    try:
        report.export_json(path)
    except Exception as e:
        sys.stderr.write("[خطا] نتوانستم JSON را روی Desktop ذخیره کنم (%s): %s\n" % (path, e))
        fallback = os.path.join(os.getcwd(), filename)
        try:
            report.export_json(fallback)
        except Exception as e2:
            sys.stderr.write("[خطا] ذخیره در پوشه جاری هم شکست خورد: %s\n" % e2)
    return path


def normalize_target(raw_target):
    """
    IP/host خام یا URL کامل را به base URL نرمال تبدیل می‌کند.
      "192.168.1.10:8443"     -> "https://192.168.1.10:8443"
      "api.example.com"       -> "https://api.example.com"
      "http://10.0.0.5:8080"  -> "http://10.0.0.5:8080"
    """
    raw = (raw_target or "").strip()
    if not raw:
        raise ValueError("آدرس هدف خالی است")
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw.rstrip("/")
    return "https://%s" % raw.rstrip("/")


def join_url(base, path):
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path


def default_headers(auth_value):
    headers = {"User-Agent": "owasp-api-top10-cli/1.1"}
    if auth_value:
        if (auth_value.lower().startswith("bearer ") or
                re.match(r'^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.', auth_value)):
            headers["Authorization"] = (
                auth_value if auth_value.lower().startswith("bearer ")
                else "Bearer %s" % auth_value
            )
        else:
            headers["Cookie"] = auth_value
    return headers


def safe_request(method, url, headers=None, json_body=None, data=None,
                  timeout=10.0, verify=True, allow_redirects=False):
    """همه درخواست‌ها از این تابع عبور می‌کنند تا خطاها یکسان مدیریت شوند."""
    try:
        resp = requests.request(
            method, url, headers=headers, json=json_body, data=data,
            timeout=timeout, verify=verify, allow_redirects=allow_redirects,
        )
        return resp, None
    except requests.exceptions.SSLError as e:
        return None, "خطای TLS (برای گواهی self-signed از --insecure استفاده کنید): %s" % e
    except requests.exceptions.ConnectionError as e:
        return None, "خطای اتصال: %s" % e
    except requests.exceptions.Timeout:
        return None, "تایم‌اوت بعد از %.1f ثانیه" % timeout
    except Exception as e:
        return None, "درخواست شکست خورد: %s" % e


def parse_paths_arg(paths_arg, default_paths):
    if not paths_arg:
        return list(default_paths)
    return [p.strip() for p in paths_arg.split(",") if p.strip()]


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


def find_jwt(text):
    if not text:
        return None
    m = JWT_RE.search(text)
    return m.group(0) if m else None


def b64pad(s):
    return s + "=" * (-len(s) % 4)


def decode_jwt(token):
    try:
        header_b, payload_b = token.split(".")[0], token.split(".")[1]
        header = json.loads(base64.urlsafe_b64decode(b64pad(header_b)))
        payload = json.loads(base64.urlsafe_b64decode(b64pad(payload_b)))
        return header, payload
    except Exception:
        return None, None


COMMON_JWT_SECRETS = [
    "secret", "changeme", "password", "123456", "your-256-bit-secret",
    "jwt_secret", "supersecret", "test", "dev", "development",
]


def crack_weak_hmac_secret(jwt):
    try:
        header_b, payload_b, sig_b = jwt.split(".")
    except ValueError:
        return None
    signing_input = ("%s.%s" % (header_b, payload_b)).encode("utf-8")
    for secret in COMMON_JWT_SECRETS:
        mac = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        candidate = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
        if candidate == sig_b:
            return secret
    return None


def forge_alg_none(jwt):
    try:
        header_b, payload_b, _sig = jwt.split(".")
        header = json.loads(base64.urlsafe_b64decode(b64pad(header_b)))
        header["alg"] = "none"
        new_header_b = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b"=").decode()
        return "%s.%s." % (new_header_b, payload_b)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

SENSITIVE_FIELD_NAMES = set([
    "password", "passwd", "ssn", "social_security", "credit_card", "card_number",
    "cvv", "secret", "api_key", "apikey", "access_token", "refresh_token",
    "private_key", "email", "phone", "date_of_birth", "dob", "national_id",
    "salary", "balance", "iban", "bank_account", "is_admin", "role", "isadmin",
])


def walk_json(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            newpath = "%s.%s" % (path, k) if path else k
            if isinstance(v, (dict, list)):
                for item in walk_json(v, newpath):
                    yield item
            else:
                yield (newpath, k, v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            newpath = "%s[%d]" % (path, i)
            if isinstance(v, (dict, list)):
                for item in walk_json(v, newpath):
                    yield item
            else:
                yield (newpath, "[%d]" % i, v)


def rough_similarity(a, b):
    if not a or not b:
        return 0.0
    if abs(len(a) - len(b)) > max(len(a), len(b)) * 0.5:
        return 0.0

    def shingles(s, k=8):
        return set(s[i:i + k] for i in range(0, max(1, len(s) - k), k))
    sa, sb = shingles(a), shingles(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / float(len(sa | sb))


def confirm_authorized(target):
    """هشدار برای پروب‌های Active."""
    sys.stderr.write(
        "\n[!] پروب Active روی هدف زیر فعال است:\n"
        "    %s\n"
        "    فقط در صورتی ادامه دهید که مجوز کتبی تست این سیستم را دارید.\n\n"
        % target
    )
