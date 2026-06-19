#!/usr/bin/env python3
"""Toy JWT claims audit for defensive education.

Decodes unsigned JWT segments locally and flags risky claim patterns. It does not
bruteforce secrets, forge tokens, bypass auth, or validate third-party systems.
"""
from __future__ import annotations

import argparse
import base64
import json
import time
from typing import Any


def b64url_decode(segment: str) -> bytes:
    padding = '=' * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_json(segment: str) -> dict[str, Any]:
    return json.loads(b64url_decode(segment).decode('utf-8'))


def audit(token: str) -> dict[str, Any]:
    parts = token.split('.')
    if len(parts) != 3:
        return {'valid_shape': False, 'findings': ['JWT should have three dot-separated segments']}

    header = decode_json(parts[0])
    claims = decode_json(parts[1])
    now = int(time.time())
    findings: list[str] = []

    if str(header.get('alg', '')).lower() == 'none':
        findings.append('Header uses alg=none; reject this in production.')
    if 'iss' not in claims:
        findings.append('Missing issuer claim.')
    if 'aud' not in claims:
        findings.append('Missing audience claim.')
    if 'exp' not in claims:
        findings.append('Missing expiration claim.')
    elif int(claims['exp']) < now:
        findings.append('Token is expired.')
    elif int(claims['exp']) - now > 60 * 60 * 24 * 30:
        findings.append('Expiration is more than 30 days away; consider shorter-lived tokens.')
    if 'sub' not in claims:
        findings.append('Missing subject claim.')

    return {'valid_shape': True, 'header': header, 'claims': claims, 'findings': findings or ['No obvious claim hygiene issues found.']}


def main() -> None:
    parser = argparse.ArgumentParser(description='Decode and audit JWT claims locally.')
    parser.add_argument('token')
    parser.add_argument('--pretty', action='store_true')
    args = parser.parse_args()
    print(json.dumps(audit(args.token), indent=2 if args.pretty else None, sort_keys=True))


if __name__ == '__main__':
    main()
