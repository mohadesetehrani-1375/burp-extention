#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api8_misconfig.py - OWASP API8:2023 Security Misconfiguration

RUN THIS FILE ON ITS OWN:
  python3 api8_misconfig.py --target https://api.example.com \
      --paths /,/api/v1/users --auth "Bearer <token>"

--target is REQUIRED, no default.

All checks are passive and directly observable in a single response:
verbose stack traces, missing security headers, dangerous CORS config,
default/sensitive endpoints (Swagger, Actuator) reachable.
"""

import re
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding)
from common import auto_export_json

DEFAULT_PATHS = ["/", "/api/v1"]

STACK_TRACE_MARKERS = [
    (re.compile(r'Traceback \(most recent call last\)', re.I), "Python traceback"),
    (re.compile(r'werkzeug\.exceptions|Werkzeug Debugger', re.I), "Flask/Werkzeug debugger"),
    (re.compile(r'DisallowedHost|You\'re seeing this error because you have <code>DEBUG = True', re.I), "Django DEBUG page"),
    (re.compile(r'Whitelabel Error Page|org\.springframework', re.I), "Spring stack trace"),
    (re.compile(r'ActionController::|ActiveRecord::.*Error', re.I), "Ruby on Rails error page"),
    (re.compile(r'at java\.[a-zA-Z.]+\(.*\.java:\d+\)', re.I), "Java stack trace"),
    (re.compile(r'System\.Exception|at System\.[A-Za-z.]+\(', re.I), ".NET stack trace"),
    (re.compile(r'ORA-\d{5}|You have an error in your SQL syntax|PostgreSQL.*ERROR|SQLSTATE\[', re.I), "raw SQL error"),
]

DEFAULT_ENDPOINT_MARKERS = [
    (re.compile(r'/actuator/(env|heapdump|shutdown|mappings)', re.I), "Spring Boot Actuator sensitive endpoint"),
    (re.compile(r'swagger-ui|/v2/api-docs|/openapi\.json', re.I), "OpenAPI/Swagger docs endpoint"),
]


def main():
    parser = build_arg_parser("API8:2023 Security Misconfiguration - standalone checker")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API8 - Security Misconfiguration", base)
    headers = default_headers(args.auth)
    is_https = base.startswith("https://")

    for path in paths:
        url = join_url(base, path)
        req_headers = dict(headers)
        req_headers["Origin"] = "https://attacker-controlled.example"
        resp, err = safe_request("GET", url, headers=req_headers,
                                  timeout=args.timeout, verify=not args.insecure)
        if err:
            print("  [skip] %s -> %s" % (url, err))
            continue

        body = resp.text or ""
        ctype = resp.headers.get("Content-Type", "").lower()

        for pattern, label in STACK_TRACE_MARKERS:
            if pattern.search(body):
                report.add(Finding(
                    category="API8:2023",
                    name="Verbose error / stack trace disclosed: %s" % label,
                    severity="Medium", confidence="Certain",
                    detail="%s response matches a known %s pattern. Stack "
                           "traces disclose internal paths/versions." % (path, label),
                    remediation="Disable debug/verbose error modes in production.",
                    method="GET", url=url, status=resp.status_code,
                ))
                break

        if "html" in ctype:
            missing = []
            if is_https and "strict-transport-security" not in [h.lower() for h in resp.headers]:
                missing.append("Strict-Transport-Security")
            if "x-content-type-options" not in [h.lower() for h in resp.headers]:
                missing.append("X-Content-Type-Options")
            if "content-security-policy" not in [h.lower() for h in resp.headers]:
                missing.append("Content-Security-Policy")
            if missing:
                report.add(Finding(
                    category="API8:2023", name="Missing recommended security headers",
                    severity="Low", confidence="Certain",
                    detail="Missing on %s: %s" % (path, ", ".join(missing)),
                    remediation="Set HSTS, X-Content-Type-Options: nosniff, and a restrictive CSP.",
                    method="GET", url=url, status=resp.status_code,
                ))

        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao:
            reflected = acao == req_headers["Origin"]
            if (acao == "*" and acac == "true") or (reflected and acac == "true"):
                report.add(Finding(
                    category="API8:2023",
                    name="Dangerous CORS configuration (credentials + permissive origin)",
                    severity="High", confidence="Certain",
                    detail=(
                        "%s: Access-Control-Allow-Origin=%s, "
                        "Access-Control-Allow-Credentials=true. %s"
                        % (path, acao,
                           "Server reflects the request Origin verbatim." if reflected
                           else "Wildcard + credentials.")
                    ),
                    remediation="Use an explicit allow-list of trusted origins when credentials are involved.",
                    method="GET", url=url, status=resp.status_code,
                ))

        for pattern, label in DEFAULT_ENDPOINT_MARKERS:
            if pattern.search(path):
                report.add(Finding(
                    category="API8:2023", name=label,
                    severity="Medium" if not args.auth else "Low",
                    confidence="Certain",
                    detail="%s matched: %s." % (path, label),
                    remediation="Disable or authenticate management/docs endpoints in production.",
                    method="GET", url=url, status=resp.status_code,
                ))

    report.summary()
    auto_export_json(report, 'api8_misconfig')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
