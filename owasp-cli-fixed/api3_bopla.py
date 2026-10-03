#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api3_bopla.py - OWASP API3:2023 Broken Object Property Level Authorization

RUN THIS FILE ON ITS OWN:
  python3 api3_bopla.py --target https://api.example.com \
      --paths /api/v1/users/1 --auth "Bearer <token>"

  # mass-assignment probe (sends an extra PUT/PATCH with injected fields):
  python3 api3_bopla.py --target https://api.example.com \
      --paths /api/v1/users/1 --auth "Bearer <token>" --active

--target is REQUIRED, no default.
"""

import json
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding, walk_json, SENSITIVE_FIELD_NAMES,
                     confirm_authorized)
from common import auto_export_json

DEFAULT_PATHS = ["/api/v1/users/1"]


def main():
    parser = build_arg_parser("API3:2023 Broken Object Property Level Authorization - standalone checker")
    parser.add_argument(
        "--write-method", default="PATCH", choices=["PUT", "PATCH", "POST"],
        help="HTTP method to use for the active mass-assignment probe (default: PATCH).")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API3 - Broken Object Property Level Authorization", base)
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

        ctype = resp.headers.get("Content-Type", "")
        if "json" in ctype.lower():
            try:
                data = resp.json()
            except Exception:
                data = None
            if data is not None:
                hits = []
                import re
                for jpath, key, value in walk_json(data):
                    key_norm = re.sub(r'[^a-z]', '', key.lower())
                    if key_norm in SENSITIVE_FIELD_NAMES and value not in (None, "", False):
                        hits.append((jpath, value))
                if hits:
                    report.add(Finding(
                        category="API3:2023",
                        name="Sensitive field(s) present in response body",
                        severity="Medium", confidence="Firm",
                        detail=(
                            "%s returned fields whose names match common "
                            "sensitive-data patterns. Confirm each is "
                            "actually needed by the consuming client."
                            % path
                        ),
                        remediation=(
                            "Return only fields the specific client needs "
                            "(explicit response DTOs); never serialize the "
                            "full internal object."
                        ),
                        method="GET", url=url, status=resp.status_code,
                        evidence="\n".join("%s = %r" % (p, v) for p, v in hits[:15]),
                    ))

        if args.active:
            injected = {"is_admin": True, "role": "admin", "isAdmin": True}
            probe_resp, perr = safe_request(
                args.write_method, url, headers=headers, json_body=injected,
                timeout=args.timeout, verify=not args.insecure)
            if perr:
                print("  [skip active] %s -> %s" % (url, perr))
                continue
            if probe_resp is not None and 200 <= probe_resp.status_code < 300:
                body_text = probe_resp.text or ""
                reflected = [k for k in injected if ('"%s"' % k) in body_text and
                             str(injected[k]).lower() in body_text.lower()]
                if reflected:
                    report.add(Finding(
                        category="API3:2023",
                        name="Mass assignment: privileged field(s) accepted",
                        severity="Medium", confidence="Tentative",
                        detail=(
                            "Sent %s %s with extra unexpected fields %s. "
                            "Server returned HTTP %d and echoes the "
                            "injected field(s) as accepted: %s. You MUST "
                            "manually confirm the target account's actual "
                            "privilege level changed - an echoed field is "
                            "suggestive, not proof."
                            % (args.write_method, path, json.dumps(injected),
                               probe_resp.status_code, ", ".join(reflected))
                        ),
                        remediation=(
                            "Use explicit allow-lists for writable fields "
                            "per endpoint; never bind the raw request body "
                            "onto an internal model."
                        ),
                        method=args.write_method, url=url, status=probe_resp.status_code,
                    ))
                else:
                    print("  [ok] %s - mass-assignment probe got HTTP %d but "
                          "injected fields not echoed back; not conclusive "
                          "either way without checking account state manually." %
                          (path, probe_resp.status_code))

    report.summary()
    auto_export_json(report, 'api3_bopla')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
