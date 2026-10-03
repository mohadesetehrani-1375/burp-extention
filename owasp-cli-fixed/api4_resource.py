#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api4_resource.py - OWASP API4:2023 Unrestricted Resource Consumption

RUN THIS FILE ON ITS OWN:
  python3 api4_resource.py --target https://api.example.com \
      --paths /api/v1/items --auth "Bearer <token>" --active

--target is REQUIRED, no default.

Checks: absence of rate-limit headers across repeated calls, very large
unpaginated list responses, and (active, opt-in) whether a `limit`-style
query parameter is honored unbounded.
"""

import re
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding, confirm_authorized)
from common import auto_export_json

DEFAULT_PATHS = ["/api/v1/items"]
RATE_LIMIT_HEADER_RE = re.compile(r'^(x-)?ratelimit-|^retry-after$', re.I)
LIMIT_PARAM_RE = re.compile(r'(limit|per_page|pagesize|page_size|count|top)=(\d+)', re.I)


def main():
    parser = build_arg_parser("API4:2023 Unrestricted Resource Consumption - standalone checker")
    parser.add_argument(
        "--repeat", type=int, default=5,
        help="How many times to call each path to check for rate-limit "
             "headers (default: 5).")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API4 - Unrestricted Resource Consumption", base)
    headers = default_headers(args.auth)

    if args.active:
        confirm_authorized(base)

    for path in paths:
        url = join_url(base, path)
        saw_rate_limit_header = False
        last_resp = None
        for i in range(args.repeat):
            resp, err = safe_request("GET", url, headers=headers,
                                      timeout=args.timeout, verify=not args.insecure)
            if err:
                print("  [skip] %s -> %s" % (url, err))
                break
            last_resp = resp
            if any(RATE_LIMIT_HEADER_RE.match(h) for h in resp.headers.keys()):
                saw_rate_limit_header = True

        if last_resp is None:
            continue

        if not saw_rate_limit_header:
            report.add(Finding(
                category="API4:2023",
                name="No rate-limit headers observed after %d calls" % args.repeat,
                severity="Low", confidence="Tentative",
                detail=(
                    "%s was called %d times; no response carried "
                    "RateLimit-*/X-RateLimit-*/Retry-After headers. Does "
                    "not prove limiting is absent server-side (a gateway "
                    "may enforce it silently) - worth checking against "
                    "your actual limiting infrastructure."
                    % (path, args.repeat)
                ),
                remediation="Apply and surface rate limits (429 + Retry-After) per user/IP/API-key.",
                method="GET", url=url, status=last_resp.status_code,
            ))

        ctype = last_resp.headers.get("Content-Type", "")
        if "json" in ctype.lower():
            try:
                data = last_resp.json()
                arr = data if isinstance(data, list) else (
                    next((v for v in data.values() if isinstance(v, list)), None)
                    if isinstance(data, dict) else None)
            except Exception:
                arr = None
            if arr is not None and len(arr) > 500:
                report.add(Finding(
                    category="API4:2023",
                    name="Very large unpaginated list response (%d items)" % len(arr),
                    severity="Low", confidence="Firm",
                    detail="%s returned %d array items with no visible "
                           "pagination applied." % (path, len(arr)),
                    remediation="Enforce a server-side maximum page size regardless of client input.",
                    method="GET", url=url, status=last_resp.status_code,
                ))

        if args.active:
            m = LIMIT_PARAM_RE.search(url)
            if m:
                huge_url = url[:m.start()] + "%s=100000" % m.group(1) + url[m.end():]
            else:
                sep = "&" if "?" in url else "?"
                huge_url = url + sep + "limit=100000"
            presp, perr = safe_request("GET", huge_url, headers=headers,
                                        timeout=args.timeout, verify=not args.insecure)
            if perr:
                print("  [skip active] %s -> %s" % (huge_url, perr))
                continue
            if presp is not None and presp.status_code == 200:
                try:
                    data = presp.json()
                    arr = data if isinstance(data, list) else (
                        next((v for v in data.values() if isinstance(v, list)), None)
                        if isinstance(data, dict) else None)
                    count = len(arr) if arr is not None else None
                except Exception:
                    count = None
                if count and count > 1000:
                    report.add(Finding(
                        category="API4:2023",
                        name="Server honors unbounded limit parameter",
                        severity="Medium", confidence="Firm",
                        detail="Requested limit=100000 on %s, server "
                               "returned HTTP 200 with %d items - no "
                               "server-side cap applied." % (path, count),
                        remediation="Clamp pagination parameters server-side to a sane maximum (e.g. 100).",
                        method="GET", url=huge_url, status=presp.status_code,
                    ))

    report.summary()
    auto_export_json(report, 'api4_resource')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
