# 03. API Authentication & Authorization Hardening (JWT)

**Project:** C28 — SOC False-Positive Reduction Assistant (Semester 5 AI Immersion)  
**Phase:** 2 — Machine Learning & Production Hardening  
**Target:** 70% Project Completion  

---

## 1. Executive Summary & Reviewer Gap Context

In Review 1, the examination committee noted that while Phase 1 successfully implemented role-based access control (RBAC), relying on unauthenticated client-supplied HTTP headers (`X-Analyst-Role`, `X-Analyst-ID`) was inadequate for an enterprise security system claiming production relevance.

To resolve **GAP 4**, Phase 2 introduces **stateless, cryptographically signed JSON Web Tokens (JWT)**. All protected endpoints now require signed Bearer tokens issued exclusively by `/auth/login`. This architectural enhancement eliminates client header spoofing, enforces cryptographic non-repudiation, and establishes an auditable security perimeter for Tier-1 analysts and SOC Leads.

---

## 2. Vulnerability Analysis of Phase 1 Prototype Auth

Phase 1 used a prototype-oriented role check:

```
[Client] ---> HTTP GET /config/rules
              Header: X-Analyst-Role: soc_lead
              Header: X-Analyst-ID: ana_004
              (Server trusts header without verification)
```

### Critical Flaws in Header-Based Identification:
1. **Header Spoofing / Privilege Escalation:** Any unauthenticated client or compromised workstation could forge `X-Analyst-Role: soc_lead` in an HTTP request. A malicious insider or compromised host could manipulate safety thresholds, lower auto-suppression floors, or delete detection rules.
2. **Absence of Cryptographic Integrity:** Plain headers have no digital signature. Intermediaries or reverse proxies cannot verify whether the identity claim was created by the authentic identity provider or forged in transit.
3. **No Expiration or Session Lifecycle:** Plain headers persist indefinitely across requests. There is no cryptographic expiration timestamp (`exp`), meaning stolen or captured headers could be replayed forever.
4. **Non-Repudiation Failure:** In an audit investigation, a rogue actor could claim another analyst's ID (`X-Analyst-ID: ana_001`), falsifying the operational trail in `analyst_decisions`.

---

## 3. Phase 2 Architecture: Cryptographic JWT Authentication

Phase 2 implements RFC 7519 compliant JWT authentication:

```
+-------------+                     +-------------------+                     +--------------------+
| Tier-1 / L2 |                     | FastAPI Server    |                     | Endpoint Telemetry |
| Analyst UI  |                     | (/auth/login)     |                     | & SQLite Database  |
+-------------+                     +-------------------+                     +--------------------+
       |                                      |                                         |
       |  1. POST /auth/login                 |                                         |
       |     {analyst_id, password}           |                                         |
       |------------------------------------->|                                         |
       |                                      | Verify against seeded                   |
       |                                      | analyst directory                       |
       |  2. HTTP 200 OK                      |                                         |
       |     {access_token, role, exp}        |                                         |
       |<-------------------------------------|                                         |
       |                                      |                                         |
       |  3. GET /alerts/{id}/recommend_v2    |                                         |
       |     Header: Authorization:           |                                         |
       |             Bearer <signed_jwt>      |                                         |
       |------------------------------------->|                                         |
       |                                      | 4. Decode & verify HMAC-SHA256 signature|
       |                                      |    Check exp, extract 'role' & 'sub'    |
       |                                      |    Verify role permissions in rules.yaml|
       |                                      |---------------------------------------->| Query DB
       |  5. HTTP 200 (Model Recommendation)  |                                         |
       |<-------------------------------------|                                         |
```

### Cryptographic Configuration
- **Signature Algorithm:** HMAC-SHA256 (`HS256`).
- **Signing Key:** Server-side managed secret (`JWT_SECRET_KEY`).
- **Token Validity Window:** 8 hours (standard SOC operational shift).

### Token Payload Structure
```json
{
  "sub": "ana_001",
  "role": "l1_analyst",
  "iss": "c28-soc-assistant-auth",
  "iat": 1758172800,
  "exp": 1758201600
}
```

---

## 4. Role-Based Access Control (RBAC) Enforcement

Permissions are defined in `config/rules.yaml` under `role_permissions`:

| Endpoint | Required Permission | Allowed Roles | Enforced By |
|---|---|---|---|
| `GET /alerts` | `alerts:read` | `l1_analyst`, `soc_lead` | Decoded JWT `role` |
| `GET /alerts/{id}` | `alerts:read` | `l1_analyst`, `soc_lead` | Decoded JWT `role` |
| `GET /alerts/{id}/recommend` | `alerts:read` | `l1_analyst`, `soc_lead` | Decoded JWT `role` |
| `GET /alerts/{id}/recommend_v2`| `alerts:read` | `l1_analyst`, `soc_lead` | Decoded JWT `role` |
| `POST /alerts/{id}/disposition`| `alerts:disposition` | `l1_analyst`, `soc_lead` | Decoded JWT `role` |
| `GET /config/rules` | `config:read` | **`soc_lead` only** | Decoded JWT `role` (HTTP 403 for L1) |
| `PUT /config/rules` | `config:write` | **`soc_lead` only** | Decoded JWT `role` (HTTP 403 for L1) |
| `GET /roles/soc_lead/view` | `config:read` | **`soc_lead` only** | Decoded JWT `role` (HTTP 403 for L1) |

---

## 5. Seeded Analyst Directory (Demonstration Credentials)

For reproducible local evaluation and viva demonstration without external OAuth infrastructure, credentials mirror the analyst pool in `data/analyst_decisions.csv`:

| Analyst ID | Role | Name / Description | Password |
|---|---|---|---|
| `ana_001` | `l1_analyst` | Sarah Chen (Tier-1 Analyst) | `Analyst123!` |
| `ana_002` | `l1_analyst` | Marcus Vance (Tier-1 Analyst) | `Analyst123!` |
| `ana_003` | `l1_analyst` | Elena Rostova (Tier-1 Analyst) | `Analyst123!` |
| `ana_004` | `soc_lead` | David Kalu (SOC Lead / Tier-2) | `Lead123!` |
| `ana_005` | `l1_analyst` | Priya Patel (Tier-1 Analyst) | `Analyst123!` |

---

## 6. Backward Compatibility Strategy

To ensure that existing Phase 1 integration tests (`tests/test_failure_cases.py`) continue to pass without regression:
1. `get_current_analyst` prioritizes `Authorization: Bearer <token>`.
2. If `Authorization` is absent, it inspects legacy headers (`X-Analyst-Role`, `X-Analyst-ID`).
3. If neither is supplied, the endpoint immediately halts with `HTTP 401 Unauthorized`.
4. If an L1 analyst attempts to access `GET /config/rules` via either a valid L1 JWT or the legacy header, the system strictly returns `HTTP 403 Forbidden` (verifying test F4).

---

## 7. Viva Discussion Points

When questioned on authentication architecture during the viva:
- **Q: Why not integrate an external provider like Okta or Azure AD?**  
  *A:* In accordance with the course constraints, external cloud dependencies would break clean-clone reproducibility. A self-contained HS256 JWT issuer implements the exact enterprise standard (stateless bearer token verification, claim-based RBAC) without external failure modes.
- **Q: What happens if a token is tampered with?**  
  *A:* PyJWT verifies the cryptographic HMAC signature using `JWT_SECRET_KEY`. Any modification to the payload (e.g. changing `l1_analyst` to `soc_lead`) invalidates the signature and triggers an immediate `HTTP 401 Unauthorized`.
- **Q: How does this address the Review 1 feedback?**  
  *A:* It proves that the assistant does not simply accept ambient client claims, hardening the control plane for safety-critical SOC configuration changes.
