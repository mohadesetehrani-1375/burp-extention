#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api9_inventory.py - OWASP API9:2023 Improper Inventory Management

RUN THIS FILE ON ITS OWN:
  python3 api9_inventory.py --target https://api.example.com \
      --paths /api/v1/users,/api/v2/users,/api/v3-beta/users

--target is REQUIRED, no default.

Checks: multiple API versions reachable (zombie/shadow API candidates),
internal/staging hostnames leaked in response bodies, GraphQL
introspection enabled.
"""

import re
from collections import defaultdict
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding)
from common import auto_export_json

DEFAULT_PATHS = ["/api/v1/users", "/api/v2/users"]
VERSION_PATH_RE = re.compile(r'/api/(v\d+[a-z0-9\-]*)/', re.I)
INTERNAL_HOST_RE = re.compile(r'https?://[a-z0-9.\-]*\.(internal|staging|corp|local|test)\b', re.I)
GRAPHQL_INTROSPECTION_RE = re.compile(r'"__schema"|IntrospectionQuery', re.I)


def main():
    parser = build_arg_parser("API9:2023 Improper Inventory Management - standalone checker")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API9 - Improper Inventory Management", base)
    headers = default_headers(args.auth)

    version_counts = defaultdict(int)
    seen_hosts = set()
    graphql_reported = False

    for path in paths:
        m = VERSION_PATH_RE.search(path)
        if m:
            version_counts[m.group(1).lower()] += 1

    for path in paths:
        url = join_url(base, path)
        resp, err = safe_request("GET", url, headers=headers,
                                  timeout=args.timeout, verify=not args.insecure)
        if err:
            print("  [skip] %s -> %s" % (url, err))
            continue
        body = resp.text or ""

        for hm in INTERNAL_HOST_RE.finditer(body):
            host = hm.group(0)
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            report.add(Finding(
                category="API9:2023", name="Internal/staging hostname leaked in response",
                severity="Low", confidence="Firm",
                detail="%s body contains an apparently internal/staging URL: %s" % (path, host),
                remediation="Do not leak internal hostnames/URLs in public API responses.",
                method="GET", url=url, status=resp.status_code,
            ))

        if not graphql_reported and GRAPHQL_INTROSPECTION_RE.search(body):
            graphql_reported = True
            report.add(Finding(
                category="API9:2023", name="GraphQL introspection appears enabled",
                severity="Low", confidence="Firm",
                detail="%s response contains introspection schema data (__schema)." % path,
                remediation="Disable introspection in production GraphQL endpoints.",
                method="GET", url=url, status=resp.status_code,
            ))

    if len(version_counts) > 1:
        minority = sorted(v for v, c in version_counts.items() if c < max(version_counts.values()))
        for v in minority:
            report.add(Finding(
                category="API9:2023",
                name="Multiple API versions reachable (possible zombie/shadow: %s)" % v,
                severity="Low", confidence="Tentative",
                detail=(
                    "Version '%s' is reachable alongside more frequently "
                    "tested version(s) (%s). Older/preview versions often "
                    "miss fixes and access controls. Confirm this version "
                    "is intentionally supported and equally hardened."
                    % (v, ", ".join(version_counts.keys()))
                ),
                remediation="Maintain a live API inventory; decommission or equally-harden old versions.",
            ))

    report.summary()
    auto_export_json(report, 'api9_inventory')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
