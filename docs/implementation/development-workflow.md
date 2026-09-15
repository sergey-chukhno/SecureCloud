# SecureCloud — Development Workflow

**Status:** Implementation baseline
**Scope:** Team workflow, branches, pull requests, reviews, integration, and change management

---

## 1. Purpose

This document defines how the SecureCloud team turns approved design into integrated code.

It covers:

* work assignment
* branches
* commits
* pull requests
* reviews
* CI
* integration
* design changes
* completion criteria

It does not redefine architecture or implementation rules.

---

# 2. Team Ownership

Initial ownership:

| Developer   | Primary ownership                                                                                    |
| ----------- | ---------------------------------------------------------------------------------------------------- |
| Sergey      | Gateway, Messaging, ScyllaDB, distributed integration, resilience, performance, security integration |
| Developer 2 | Auth, PostgreSQL, MFA, sessions/tokens, devices, crypto directory                                    |
| Developer 3 | Files, PostgreSQL metadata, MinIO, transfers, file-access capabilities                               |

Shared responsibilities:

* API/Protobuf contracts
* architecture reviews
* security review
* integration testing
* E2E testing
* CI
* final MVP validation

Ownership means **primary implementation responsibility**, not exclusive knowledge.

---

# 3. Trello → Branch → PR

Every implementation task starts from a Trello card.

Recommended branch format:

```text id="xq3m1p"
feature/<short-name>
fix/<short-name>
security/<short-name>
test/<short-name>
refactor/<short-name>
```

Examples:

```text id="1y7k9z"
feature/auth-refresh-rotation
feature/messaging-idempotency
feature/file-resumable-upload
security/device-revocation
test/messaging-delivery-recovery
```

One branch should represent **one coherent engineering outcome**.

Do not create branches containing several unrelated features.

---

# 4. Before Starting Implementation

A developer may start implementation when:

* the relevant design decision exists
* required API/Protobuf contract is defined
* data model is sufficiently defined
* dependencies are known
* acceptance criteria are clear
* required tests are identifiable

If a required decision is missing, **stop and raise the issue** rather than inventing architecture locally.

---

# 5. Commit Rules

Commits should be:

* small enough to review
* logically coherent
* buildable when practical
* free of unrelated changes

Recommended format:

```text
<type>: <short description>
```

Examples:

```text
feat: add refresh token rotation
fix: reject revoked device
test: cover duplicate message submission
security: enforce MFA for device registration
refactor: isolate delivery scheduler
```

Do not commit:

* generated build artifacts
* credentials
* private keys
* temporary debugging code
* unrelated formatting changes

---

# 6. Pull Requests

Every PR must contain:

### Description

* what changed
* why it changed
* Trello card
* affected services/components
* relevant design/API documents

### Validation

State:

* tests executed
* sanitizer used, if applicable
* integration tests used
* known limitations

### Security impact

Explicitly state:

```text
Security impact: none
```

or describe the security-relevant change.

### Database/API changes

Clearly identify:

* schema changes
* migration requirements
* OpenAPI changes
* Protobuf changes
* compatibility impact

---

# 7. PR Size

Prefer:

```text
one feature
→ several focused commits
→ one reviewable PR
```

Avoid very large PRs combining:

```text
database + API + unrelated refactoring + UI + deployment
```

If a feature is genuinely large, split it into independently reviewable PRs while keeping the system buildable.

---

# 8. Required Review

At least **one other developer** reviews every PR.

Security-sensitive changes require review by another developer with particular attention to:

* authentication
* authorization
* device lifecycle
* cryptographic integration
* secret handling
* sensitive logging
* persistence/durability
* trust-boundary changes

The author remains responsible for correctness; the reviewer verifies assumptions and integration impact.

---

# 9. CI Before Merge

A PR cannot merge when required CI checks fail.

Minimum PR checks:

```text id="l1a8zq"
Build
Unit tests
Relevant integration tests
Contract tests
clang-format
clang-tidy
AddressSanitizer
```

Additional tests are required when relevant:

```text id="r9v2cs"
ThreadSanitizer
Security tests
Resilience tests
E2E tests
Performance benchmarks
```

The PR author must fix the failure or explicitly resolve it with the reviewer. Never bypass a failing security/correctness test merely to merge.

---

# 10. Integration Order

When several services are developed in parallel:

```text
Contracts
   ↓
Service implementation
   ↓
Service integration tests
   ↓
Cross-service integration
   ↓
E2E validation
```

Prefer integrating changes in dependency order.

Example:

```text
Auth contract
    ↓
Auth implementation
    ↓
Gateway authentication integration
    ↓
Messaging authorization integration
    ↓
E2E authentication + messaging
```

---

# 11. Contract Changes

If implementation requires an API or Protobuf change:

1. Stop implementation at the affected boundary.
2. Explain why the existing contract is insufficient.
3. Update the contract.
4. Review compatibility impact.
5. Update affected tests.
6. Then continue implementation.

Do not silently modify contracts inside an unrelated PR.

---

# 12. Design Problems Discovered During Implementation

If code reveals a problem with the approved architecture/design:

### Do not

* silently redesign the service
* introduce a new database
* bypass another service
* create a hidden shared dependency
* weaken a security requirement
* change an invariant locally

### Do

1. Document the concrete problem.
2. Identify the affected decision/document.
3. Propose the smallest viable change.
4. Review it with the team.
5. Update the source-of-truth document.
6. Implement against the updated decision.

Existing ADRs are amended when an architectural decision genuinely changes.

---

# 13. Cross-Developer Dependencies

If Developer A requires work from Developer B:

```text
A identifies dependency
        ↓
dependency documented in Trello
        ↓
B implements contract/foundation
        ↓
B opens PR
        ↓
A integrates after review
```

Do not duplicate another developer's implementation simply to avoid waiting.

Temporary mocks/stubs are allowed when they do not change the real contract.

---

# 14. Merge Strategy

Use protected `main`.

Rules:

* no direct pushes to `main`
* PR required
* CI required
* review required
* branch must be up to date before merge where practical
* resolve merge conflicts before approval
* do not merge known broken code

After merge, the author is responsible for checking that the integrated system remains healthy.

---

# 15. Definition of Ready

A Trello card is **Ready** when:

* objective is clear
* owner is assigned
* relevant design reference exists
* dependencies are identified
* API/data changes are known or explicitly unnecessary
* acceptance criteria are defined
* tests can be identified

---

# 16. Definition of Done

A card is **Done** only when:

* implementation is complete
* relevant tests pass
* security requirements are satisfied
* API/contracts are updated if necessary
* documentation is updated if a decision/interface changed
* code has been reviewed
* CI passes
* changes are merged
* no known critical defect remains

"Code works locally" is not sufficient for Done.

---

# 17. Daily Development Rule

Developers should continuously keep the integration surface small.

When blocked by another component:

> **Expose the dependency early rather than implementing around it.**

When uncertain about architecture:

> **Ask before coding.**

When changing a decision:

> **Update the source of truth before relying on the new decision.**

When fixing a bug:

> **Add a regression test whenever practical.**

The goal is to keep three developers working in parallel without creating three incompatible versions of SecureCloud.
