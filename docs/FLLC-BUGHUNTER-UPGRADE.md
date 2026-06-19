# FLLC Bug Hunter Upgrade — jwt_tool

## Portfolio role

jwt_tool belongs in the FLLC portfolio as an **authorized JWT and session-token audit reference** for bug bounty, API security, and application assessment.

## Offensive research angle

JWT issues are high-value bug bounty territory when tested in scope:

- weak signing configuration;
- algorithm confusion risk;
- missing claim validation;
- excessive token lifetime;
- insecure key rotation;
- broken audience/issuer checks;
- privilege claim tampering in toy labs.

## FLLC upgrade path

### 1. Add scoped API token audit template

```text
Program:
API asset:
Auth flow:
Token issuer:
Algorithm:
Expiration:
Audience check:
Issuer check:
Privilege claims:
Finding hypothesis:
Validation allowed by program: yes/no
```

### 2. Add safe labs

Build labs with toy tokens only:

- unsigned token teaching case;
- weak secret teaching case;
- bad claim validation teaching case;
- expired token acceptance teaching case.

### 3. Reporting output

Report should include:

- affected endpoint;
- token claim evidence redacted;
- security impact;
- safe reproduction steps;
- remediation: enforce algorithm, validate issuer/audience, shorten TTL, rotate keys.

## Website integration

Feature as:

- `JWT Audit Lab`.
- `API Token Exploitability Checklist`.
- `Bug Bounty Session Finding Template`.

## Public boundary

Use toy tokens, owned apps, or authorized programs only. Do not attack real sessions, steal tokens, or publish live credentials.
