#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api1_bola.py - OWASP API1:2023 Broken Object Level Authorization

RUN THIS FILE ON ITS OWN, e.g.:
  python3 api1_bola.py --target https://api.example.com \
      --paths /api/v1/users/1,/api/v1/users/2 \
      --auth "Bearer <identity-A-token>" \
      --alt-auth "Bearer <identity-B-token>" \
      --active

--target is REQUIRED - there is no default. Run `python3 api1_bola.py -h`
for all options.

WHAT THIS PROVES AND WHAT IT DOESN'T
--------------------------------------
Without --alt-auth: this script ONLY fetches each path with --auth and
reports the object-ID shape it sees (sequential/numeric vs UUID vs
opaque) as an INFO-level observation. That is NOT a BOLA finding by
itself - it's just telling you which IDs exist to test.

With --alt-auth AND --active: for each path, it fetches the SAME path
with IDENTITY A (--auth) and then with IDENTITY B (--alt-auth), and
compares. If identity B gets HTTP 200 with a response body highly
similar to identity A's, that is reported as a genuine
Medium/Firm-confidence finding, with both raw responses' status/length
shown as evidence - verify the body actually contains A's private data
before treating it as confirmed.
"""

import sys
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding, rough_similarity, confirm_authorized)
from common import auto_export_json

DEFAULT_PATHS = ["/api/v1/users/1", "/api/v1/orders/1"]

NUMERIC_ID = __import__("re").compile(r'\d+')
UUID_ID = __import__("re").compile(
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')


def main():
    parser = build_arg_parser("API1:2023 Broken Object Level Authorization - standalone checker")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API1 - Broken Object Level Authorization", base)
    headers_a = default_headers(args.auth)

    if args.active:
        confirm_authorized(base)

    for path in paths:
        url = join_url(base, path)
        resp_a, err = safe_request("GET", url, headers=headers_a,
                                    timeout=args.timeout, verify=not args.insecure)
        if err:
            print("  [skip] %s -> %s" % (url, err))
            continue

        id_shape = "sequential/numeric" if NUMERIC_ID.search(path) else (
            "UUID" if UUID_ID.search(path) else "opaque/none")

        report.add(Finding(
            category="API1:2023", name="Object ID observed",
            severity="Information", confidence="Certain",
            detail=(
                "Path %s returned HTTP %d with identity A. Object ID "
                "shape in this path: %s. %s"
                % (path, resp_a.status_code, id_shape,
                   "Sequential/numeric IDs are cheap to enumerate once "
                   "BOLA is confirmed." if id_shape == "sequential/numeric"
                   else "")
            ),
            remediation="N/A - informational only.",
            method="GET", url=url, status=resp_a.status_code,
        ))

        if not args.alt_auth:
            continue
        if not args.active:
            print("  [note] --alt-auth given but --active not set; skipping "
                  "the differential replay for %s. Add --active to run it." % path)
            continue

        headers_b = default_headers(args.alt_auth)
        resp_b, err_b = safe_request("GET", url, headers=headers_b,
                                      timeout=args.timeout, verify=not args.insecure)
        if err_b:
            print("  [skip alt] %s -> %s" % (url, err_b))
            continue

        if resp_a.status_code == 200 and resp_b.status_code == 200:
            similarity = rough_similarity(resp_a.text, resp_b.text)
            if similarity > 0.6:
                report.add(Finding(
                    category="API1:2023",
                    name="Candidate BOLA: identity B got 200 with similar body to identity A",
                    severity="Medium", confidence="Firm",
                    detail=(
                        "Fetched %s with identity A (HTTP %d) and identity "
                        "B (HTTP %d). Response bodies are ~%.0f%% similar "
                        "by content shingling. If identity B is NOT "
                        "supposed to access identity A's object, this is "
                        "likely a confirmed BOLA - manually inspect both "
                        "response bodies to verify B received A's actual "
                        "private data rather than a generic/empty "
                        "template." % (path, resp_a.status_code,
                                        resp_b.status_code, similarity * 100)
                    ),
                    remediation=(
                        "Enforce object-ownership checks server-side on "
                        "every request carrying an object identifier."
                    ),
                    method="GET", url=url, status=resp_b.status_code,
                    evidence="Identity A: HTTP %d, %d bytes\nIdentity B: HTTP %d, %d bytes\nSimilarity: %.0f%%" % (
                        resp_a.status_code, len(resp_a.content),
                        resp_b.status_code, len(resp_b.content), similarity * 100),
                ))
            else:
                print("  [ok] %s - identity B got 200 but body differs "
                      "significantly from identity A (similarity %.0f%%), "
                      "no finding raised." % (path, similarity * 100))
        elif resp_b.status_code in (401, 403, 404):
            print("  [ok] %s - identity B correctly denied (HTTP %d)." % (path, resp_b.status_code))

    report.summary()
    auto_export_json(report, 'api1_bola')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
