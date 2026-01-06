# Requirements Matrix (January 2026)

This file maps the product requirements (protocols, storage, security, ops) to the current LightMail implementation.

Legend:
- **Implemented**: present and wired in runtime, with at least basic handler coverage/tests.
- **Partial**: present but missing key sub-features / correctness / hardening.
- **Planned/Stub**: parsing or placeholders exist, but not production-ready.
- **Not implemented**: no functional support in the codebase yet.

## 1. Core Mail Protocols

### SMTP (RFC 5321) / Submission
- SMTP server (inbound, local delivery): **Implemented**.
- ESMTP extensions (PIPELINING/SIZE/STARTTLS/AUTH): **Implemented** (core subset).
- SMTP Submission (587 / 465): **Implemented** (listeners; typically require AUTH).
- Outbound SMTP client (used by Admin API `/admin/send`): **Partial** (basic SMTP client with AUTH PLAIN/LOGIN + STARTTLS/SMTPS).

### LMTP
- LMTP over Unix socket (Postfix → LMTP socket): **Implemented**.
- Streaming to object storage: **Implemented**.

### IMAP4rev1 (RFC 3501)
- Core IMAP4rev1 (LOGIN/LIST/SELECT/FETCH/STORE/APPEND/UID/EXPUNGE/etc): **Implemented** (subset).
- UID-based operations: **Implemented**.
- IDLE: **Implemented**.
- SEARCH: **Implemented** (subset).
- SORT: **Not implemented**.
- CONDSTORE / QRESYNC: **Not implemented** (must not be advertised until implemented).
- STARTTLS upgrade: **Not implemented** (implicit TLS via 993 is supported).

### POP3
- Core POP3 commands (USER/PASS/STAT/LIST/RETR/DELE/QUIT): **Implemented**.
- UIDL: **Not implemented**.
- TOP: **Not implemented**.

### WebSocket / JMAP
- JMAP / WebSocket edge protocol: **Not implemented** (folders exist but no runtime server).

## 2. Storage & Data Model

- Pluggable backend (Local FS + S3): **Partial**
  - S3-compatible object storage for blobs: **Implemented**.
  - Local filesystem blob backend: **Not implemented**.
- Metadata DB: **Partial**
  - MySQL is used and wired: **Implemented**.
  - PostgreSQL support: **Not implemented**.
- Efficient MIME handling: **Partial**
  - Streaming upload to object storage exists for APPEND/LMTP.
  - Full MIME parsing / attachment dedupe is not complete.
- Mailbox formats
  - Maildir-like semantics: **Partial** (mailbox/UID semantics exist in DB model).
  - Virtual mailboxes: **Not implemented**.

## 3. Security

- TLS 1.2+: **Partial** (implicit TLS listeners exist; STARTTLS upgrade not implemented).
- STARTTLS enforcement: **Partial** (IMAP has `tls_only` mode; STARTTLS upgrade path not present).
- SASL mechanisms (PLAIN/LOGIN/SCRAM): **Partial** (PLAIN/LOGIN present for IMAP AUTH; SCRAM not implemented).
- OAuth2: **Not implemented**.
- Token/app-passwords: **Partial** (Admin API bearer token exists; client auth is DB password based).

Anti-abuse:
- SPF/DKIM/DMARC: **Not implemented**.
- Rate limiting:
  - IMAP per-session command rate limiting: **Implemented**.
  - Per-IP / per-user rate limiting: **Not implemented**.
- Greylisting: **Not implemented**.

Mail filtering:
- ClamAV integration: **Implemented** (LMTP + IMAP APPEND hooks).
- Spam filtering hooks / policy engine: **Not implemented**.

## 4. Performance & Resource Control

- Zero-copy I/O: **Partial** (streaming paths exist; not systematically zero-copy).
- Backpressure-aware queues / retry system / dead-letter queue: **Not implemented**.
- System memory detection & self-throttling: **Not implemented**.

## 5. Observability & Operations

- Structured logging: **Partial** (JSON logging toggle exists; not all events are structured fields).
- Per-message trace ID: **Not implemented**.
- Metrics (Prometheus): **Not implemented** (no metrics endpoint/exporter; internal counters exist in GC logs only).

Admin controls:
- Live reload config: **Not implemented**.
- Graceful shutdown: **Partial** (tokio tasks run; no coordinated drain/stop yet).
- Mailbox reindex/repair tools: **Not implemented**.

## 6. Compliance & Reliability

- RFC compliance testing harness: **Partial** (integration tests exist for IMAP/POP3/LMTP).
- Message durability guarantees / atomic delivery: **Partial** (LMTP + S3 + DB commit path exists; needs stronger invariants + recovery).
- Crash recovery / idempotent delivery: **Partial/Not implemented** (depends on queue/retry design).

## 7. User & Admin Features

- Quotas: **Not implemented**.
- Auto-reply / forwarding rules / Sieve-like filters: **Not implemented**.
- Domain/user management: **Partial** (Admin API provides account/mailbox/message endpoints).
- Backup/restore: **Not implemented**.

## 8. Modern Expectations

- Object storage first + immutable blobs: **Implemented/Partial** (S3 is primary; immutability policies not enforced).
- Multi-tenant isolation: **Partial** (accounts exist; hard multi-tenant boundaries not audited).
- Zero-trust internal auth: **Not implemented**.
