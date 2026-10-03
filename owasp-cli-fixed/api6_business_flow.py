#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api6_business_flow.py - OWASP API6:2023 Unrestricted Access to Sensitive Business Flows

RUN THIS FILE ON ITS OWN:
  python3 api6_business_flow.py --target https://api.example.com \
      --paths /register,/login,/checkout

--target is REQUIRED, no default.

Passive only, by design: real automation-abuse can't be proven from one
request. This flags sensitive-flow endpoints with no visible
anti-automation marker (CAPTCHA/challenge) in the response, as an
INFO-level pointer to manually load-test that specific flow.
"""

import re
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding)
from common import auto_export_json

DEFAULT_PATHS = ["/register", "/login", "/checkout"]
SENSITIVE_FLOW_RE = re.compile(
    r'/(register|signup|sign-up|login|reset-password|forgot-password|'
    r'redeem|coupon|voucher|checkout|purchase|order|transfer|withdraw)(/|$)', re.I)
ANTI_AUTOMATION_HINT_RE = re.compile(r'captcha|recaptcha|hcaptcha|turnstile|challenge', re.I)


def main():
    parser = build_arg_parser("API6:2023 Unrestricted Access to Sensitive Business Flows - standalone checker")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API6 - Unrestricted Access to Sensitive Business Flows", base)
    headers = default_headers(args.auth)

    for path in paths:
        url = join_url(base, path)
        resp, err = safe_request("GET", url, headers=headers,
                                  timeout=args.timeout, verify=not args.insecure)
        if err:
            print("  [skip] %s -> %s" % (url, err))
            continue
        if not SENSITIVE_FLOW_RE.search(path):
            continue
        body = resp.text or ""
        header_blob = " ".join(resp.headers.values())
        if ANTI_AUTOMATION_HINT_RE.search(body) or ANTI_AUTOMATION_HINT_RE.search(header_blob):
            print("  [ok] %s - anti-automation marker found, no finding raised." % path)
            continue
        report.add(Finding(
            category="API6:2023",
            name="Sensitive business-flow endpoint, no visible anti-automation control",
            severity="Information", confidence="Tentative",
            detail=(
                "%s looks like a sensitive flow (register/login/"
                "redemption/purchase/transfer). No CAPTCHA/challenge "
                "marker found. This does NOT confirm abusability - "
                "protections may exist without client-visible markers. "
                "Use this as a pointer to manually load-test the flow "
                "(with authorization) rather than conclusive proof."
                % path
            ),
            remediation=(
                "Apply business-flow-aware controls: CAPTCHA/step-up "
                "verification after N attempts, per-account/per-IP rate "
                "limiting, and quantity/monetary limits on financial actions."
            ),
            method="GET", url=url, status=resp.status_code,
        ))

    report.summary()
    auto_export_json(report, 'api6_business_flow')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
