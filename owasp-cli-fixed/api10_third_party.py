#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api10_third_party.py - OWASP API10:2023 Unsafe Consumption of Third-Party APIs

RUN THIS FILE ON ITS OWN:
  python3 api10_third_party.py --target https://api.example.com \
      --paths /webhooks/stripe,/api/v1/checkout

--target is REQUIRED, no default.

Honest limitation: most 3rd-party-API consumption happens server-to-
server and never appears in any traffic you can observe externally.
What this script CAN check from the outside:
  (A) webhook/callback receiver endpoints with no recognized
      provider-signature header on the probe request,
  (B) responses that look like they embed third-party data verbatim
      (Stripe/Twilio/PayPal/etc-shaped nested objects).
"""

import re
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding)
from common import auto_export_json

DEFAULT_PATHS = ["/webhooks/stripe", "/api/v1/callback"]

WEBHOOK_PATH_RE = re.compile(r'/(webhook|callback|hook)s?(/|$)', re.I)
KNOWN_SIGNATURE_HEADERS = [
    "x-hub-signature", "x-signature", "stripe-signature",
    "x-webhook-signature", "x-callback-signature", "paypal-transmission-sig",
]
THIRD_PARTY_KEY_RE = re.compile(
    r'"(stripe|twilio|paypal|braintree|cloudinary|s3|aws|google|firebase|'
    r'sendgrid|mailgun|plaid)_?[a-z_]*"\s*:\s*\{', re.I)


def main():
    parser = build_arg_parser("API10:2023 Unsafe Consumption of 3rd-Party APIs - standalone checker")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API10 - Unsafe Consumption of 3rd-Party APIs", base)
    headers = default_headers(args.auth)

    for path in paths:
        url = join_url(base, path)

        if WEBHOOK_PATH_RE.search(path):
            resp, err = safe_request("POST", url, headers=headers, json_body={"test": "probe"},
                                      timeout=args.timeout, verify=not args.insecure)
            if err:
                print("  [skip] %s -> %s" % (url, err))
            else:
                has_sig = any(h.lower() in KNOWN_SIGNATURE_HEADERS for h in resp.request.headers.keys()) \
                    if hasattr(resp, "request") else False
                if not has_sig:
                    report.add(Finding(
                        category="API10:2023",
                        name="Webhook endpoint accepts request with no recognized signature header",
                        severity="Medium", confidence="Tentative",
                        detail=(
                            "%s looks like a webhook/callback receiver. "
                            "Probe POST carried no common provider-signature "
                            "header (Stripe-Signature, X-Hub-Signature, "
                            "etc). If the implementation doesn't verify "
                            "authenticity some other way, forged events "
                            "may be accepted. Confirm against the specific "
                            "provider's documented verification method."
                            % path
                        ),
                        remediation=(
                            "Verify webhook authenticity using the "
                            "provider's documented signature scheme "
                            "before trusting/processing the payload."
                        ),
                        method="POST", url=url, status=resp.status_code,
                    ))

        resp2, err2 = safe_request("GET", url, headers=headers,
                                    timeout=args.timeout, verify=not args.insecure)
        if err2:
            continue
        body = resp2.text or ""
        m = THIRD_PARTY_KEY_RE.search(body)
        if m:
            report.add(Finding(
                category="API10:2023",
                name="Response appears to embed third-party API data (%s)" % m.group(1),
                severity="Information", confidence="Tentative",
                detail=(
                    "%s response contains a structure resembling "
                    "third-party API data (%s) passed through your own "
                    "API. Manually review: is this content sanitized/"
                    "validated before use, rendered, or reused for "
                    "further requests (SSRF risk via third-party URLs)?"
                    % (path, m.group(1))
                ),
                remediation=(
                    "Treat all third-party API responses as untrusted "
                    "input: validate schema/types, sanitize before "
                    "rendering/storing, never use third-party-supplied "
                    "URLs or claims without your own validation."
                ),
                method="GET", url=url, status=resp2.status_code,
            ))

    report.summary()
    auto_export_json(report, 'api10_third_party')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
