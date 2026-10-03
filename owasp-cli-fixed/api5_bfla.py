#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api5_bfla.py - OWASP API5:2023 Broken Function Level Authorization

RUN THIS FILE ON ITS OWN:
  python3 api5_bfla.py --target https://api.example.com \
      --paths /admin/users,/api/v1/users/1/delete --auth "Bearer <token>" --active

--target is REQUIRED, no default.

Checks: admin/sensitive-path reachability with the given identity
(passive), and (active, opt-in) HTTP verb-tampering bypass of a
401/403 using an alternate method + X-HTTP-Method-Override.
"""

import re
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding, confirm_authorized)
from common import auto_export_json

DEFAULT_PATHS = ["/admin", "/api/v1/admin/users"]

ADMIN_PATH_RE = re.compile(
    r'/(admin|internal|debug|manage|management|staff|backoffice|_internal|superuser|root)(/|$)', re.I)
SENSITIVE_ACTION_RE = re.compile(
    r'/(delete|remove|ban|suspend|promote|grant|revoke|impersonate|export|bulk)(/|$)', re.I)


def main():
    parser = build_arg_parser("API5:2023 Broken Function Level Authorization - standalone checker")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API5 - Broken Function Level Authorization", base)
    headers = default_headers(args.auth)

    if args.active:
        confirm_authorized(base)

    for path in paths:
        url = join_url(base, path)
        resp, err = safe_request("GET", url, headers=headers,
                                  timeout=args.timeout, verify=not args.insecure)
        if err:
            print("  [skip] %s -> %s" % (url, err))
            continue

        is_admin = ADMIN_PATH_RE.search(path)
        is_sensitive = SENSITIVE_ACTION_RE.search(path)
        if (is_admin or is_sensitive) and 200 <= resp.status_code < 300:
            severity = "Medium" if not args.auth else "Information"
            report.add(Finding(
                category="API5:2023",
                name="Admin/sensitive-looking endpoint returned 2xx",
                severity=severity, confidence="Tentative",
                detail=(
                    "%s matched an admin/internal or sensitive-action "
                    "path pattern and returned HTTP %d with %s. Confirm "
                    "manually whether the calling identity's role "
                    "entitles it to this function."
                    % (path, resp.status_code,
                       "no --auth supplied" if not args.auth else "the given --auth")
                ),
                remediation="Enforce function-level authorization checks server-side on every admin/privileged endpoint.",
                method="GET", url=url, status=resp.status_code,
            ))

        if args.active and resp.status_code in (401, 403) and (is_admin or is_sensitive):
            orig_method = "GET"
            for alt in ("POST", "PUT"):
                presp, perr = safe_request(alt, url, headers=headers,
                                            data=b"", timeout=args.timeout,
                                            verify=not args.insecure)
                if perr:
                    continue
                override_headers = dict(headers)
                override_headers["X-HTTP-Method-Override"] = orig_method
                presp2, perr2 = safe_request(alt, url, headers=override_headers,
                                              data=b"", timeout=args.timeout,
                                              verify=not args.insecure)
                for label, pr in (("plain verb swap", presp), ("+ method-override header", presp2)):
                    if pr is not None and 200 <= pr.status_code < 300:
                        report.add(Finding(
                            category="API5:2023",
                            name="Verb-tampering bypassed 401/403 (%s, method %s)" % (label, alt),
                            severity="High", confidence="Firm",
                            detail=(
                                "Original GET %s was denied (HTTP %d). "
                                "Resending as %s (%s) returned HTTP %d."
                                % (path, resp.status_code, alt, label, pr.status_code)
                            ),
                            remediation=(
                                "Ensure authorization middleware runs for "
                                "every HTTP verb on a route; disable "
                                "X-HTTP-Method-Override in production unless "
                                "equally protected."
                            ),
                            method=alt, url=url, status=pr.status_code,
                        ))
                        break

    report.summary()
    auto_export_json(report, 'api5_bfla')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
