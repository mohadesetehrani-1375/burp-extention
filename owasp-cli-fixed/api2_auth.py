#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api2_auth.py - OWASP API2:2023 Broken Authentication

RUN THIS FILE ON ITS OWN:
  python3 api2_auth.py --target https://api.example.com \
      --paths /api/v1/profile --auth "Bearer <token>" --active

--target is REQUIRED, no default.

Checks: plaintext transport of credentials, JWT without 'exp', JWT
lifetime, JWT "alg":"none" acceptance (active probe), weak/well-known
HMAC secret (active probe, built-in short wordlist only).
"""

from common import (build_arg_parser, parse_args_smart, normalize_target, join_url,
                     default_headers, safe_request, parse_paths_arg,
                     Report, Finding, find_jwt, decode_jwt,
                     crack_weak_hmac_secret, forge_alg_none,
                     confirm_authorized)
from common import auto_export_json

DEFAULT_PATHS = ["/api/v1/profile", "/api/v1/me"]


def main():
    parser = build_arg_parser("API2:2023 Broken Authentication - standalone checker")
    args = parse_args_smart(parser)

    base = normalize_target(args.target)
    paths = parse_paths_arg(args.paths, DEFAULT_PATHS)
    report = Report("API2 - Broken Authentication", base)
    headers = default_headers(args.auth)

    if base.startswith("http://") and args.auth:
        report.add(Finding(
            category="API2:2023", name="Credentials sent over plaintext HTTP",
            severity="High", confidence="Certain",
            detail="Target base URL uses http:// and --auth was supplied; "
                   "this credential would travel in cleartext.",
            remediation="Use HTTPS/TLS for every endpoint accepting credentials.",
        ))

    if args.active:
        confirm_authorized(base)

    jwt = find_jwt(args.auth or "")

    for path in paths:
        url = join_url(base, path)
        resp, err = safe_request("GET", url, headers=headers,
                                  timeout=args.timeout, verify=not args.insecure)
        if err:
            print("  [skip] %s -> %s" % (url, err))
            continue

        if "token" in url.lower() or "apikey" in url.lower() or "api_key" in url.lower():
            report.add(Finding(
                category="API2:2023", name="Credential/token-looking value in URL",
                severity="Medium", confidence="Certain",
                detail="URL %s appears to carry a token/key in the path or "
                       "query string - this leaks via logs/history/Referer." % url,
                remediation="Pass tokens via Authorization header or secure cookie, never in the URL.",
                method="GET", url=url, status=resp.status_code,
            ))

        if jwt:
            header, payload = decode_jwt(jwt)
            if header is not None and payload is not None:
                if "exp" not in payload:
                    report.add(Finding(
                        category="API2:2023", name="JWT without 'exp' claim",
                        severity="Medium", confidence="Certain",
                        detail="Decoded JWT payload has no 'exp' claim - "
                               "token never expires.",
                        remediation="Always set a short 'exp'; use refresh tokens for longevity.",
                        evidence=str(payload),
                    ))
                else:
                    iat = payload.get("iat")
                    exp = payload.get("exp")
                    if iat and (exp - iat) > 7 * 86400:
                        report.add(Finding(
                            category="API2:2023", name="JWT lifetime > 7 days",
                            severity="Low", confidence="Firm",
                            detail="iat=%s exp=%s (%.1f days)." % (iat, exp, (exp - iat) / 86400.0),
                            remediation="Shorten access-token lifetime; use refresh-token rotation.",
                        ))

        break  # JWT-content checks above are per-token, not per-path; no need to repeat

    if args.active and jwt:
        # alg=none probe
        forged = forge_alg_none(jwt)
        if forged:
            url = join_url(base, paths[0])
            new_headers = dict(headers)
            for k, v in list(new_headers.items()):
                if jwt in v:
                    new_headers[k] = v.replace(jwt, forged)
            resp, err = safe_request("GET", url, headers=new_headers,
                                      timeout=args.timeout, verify=not args.insecure)
            if resp is not None and 200 <= resp.status_code < 300:
                report.add(Finding(
                    category="API2:2023", name='JWT "alg":"none" bypass accepted',
                    severity="High", confidence="Certain",
                    detail="Resent %s with an unsigned alg=none JWT. Server "
                           "returned HTTP %d." % (url, resp.status_code),
                    remediation="Reject 'none' algorithm explicitly via an allow-list of accepted algs.",
                    method="GET", url=url, status=resp.status_code,
                    evidence="Forged token: %s" % forged,
                ))
            elif resp is not None:
                print("  [ok] alg=none probe correctly rejected (HTTP %d)." % resp.status_code)

        # weak HMAC secret probe
        secret = crack_weak_hmac_secret(jwt)
        if secret:
            report.add(Finding(
                category="API2:2023", name="JWT signed with weak/well-known HMAC secret",
                severity="High", confidence="Certain",
                detail="Token's HMAC signature matches a common secret "
                       "from a small built-in wordlist. Anyone can forge valid tokens.",
                remediation="Use a long, random, high-entropy signing secret (32+ bytes), stored securely.",
                evidence="Matched secret: %r" % secret,
            ))
        else:
            print("  [ok] JWT HMAC secret did not match the small built-in common-secrets wordlist.")
    elif args.active and not jwt:
        print("  [note] --active set but no JWT found in --auth; "
              "alg=none / weak-secret probes need a JWT in --auth.")

    report.summary()
    auto_export_json(report, 'api2_auth')  # ALWAYS saved to Desktop, no flag needed
    if args.export_md:
        report.export_md(args.export_md)


if __name__ == "__main__":
    main()
