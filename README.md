# LightMail

LightMail is a modern, async mail server implemented in Rust. It provides IMAP, LMTP, POP3, and an Admin HTTP API built for production reliability, modularity, and performance.

## Highlights
- Native Rust and Tokio-based async runtime
- Memory-safe, high-performance protocol handlers (IMAP, POP3, LMTP)
- S3-only object storage for message bodies and calendar objects
- MySQL metadata for accounts, mailboxes, messages, flags, UIDVALIDITY
- Soft-delete with a background Garbage Worker (non-blocking deletions)
- TLS via rustls and secure password hashing (bcrypt)
- Structured logging and metrics-ready

## IMAP Features
- Core: LOGIN, CAPABILITY, NOOP, LOGOUT
- Mailbox: LIST, LSUB, SELECT, EXAMINE, STATUS, CLOSE, CHECK
- Messages: FETCH, STORE, COPY, MOVE, EXPUNGE (soft-delete)
- UID: UID FETCH, UID SEARCH, UID EXPUNGE
- Extensions: IDLE, UIDPLUS (`APPENDUID`), LITERAL+ advertised
- APPEND: Streams literal to S3 with optional antivirus scanning

## Architecture Overview
- Runtime supervises protocol servers and background workers.
- Protocols live under `src/protocol/*` with session-based state machines:
  - `protocol::imap`: RFC 3501 + extensions (IDLE, UIDPLUS, MOVE, LITERAL+)
  - `protocol::pop3`: Minimal POP3 (USER/PASS, STAT, LIST, RETR, DELE, QUIT)
  - `protocol::lmtp`: Streaming delivery to S3 with atomic commit
- Storage:
  - S3 for bodies and attachments (`object_keys` table tracks S3 keys and sizes)
  - MySQL for metadata only (accounts, mailboxes, messages, flags, UIDVALIDITY)

See [ARCHITECTURE.md](ARCHITECTURE.md), [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md), and [STORAGE.md](STORAGE.md) for details.
For admin-only HTTP management, see [docs/API.md](docs/API.md).

## Configuration
The default config template is in [config.ini.example](config.ini.example). Copy it to `config.ini` and customize for your environment.

Key sections:
- `[database]`: MySQL connection (host/port or socket), user, password, database
- `[s3]`: endpoint, bucket, region, access/secret keys
- `[imap]`, `[pop3]`, `[lmtp]`, `[api]`: enable/disable modules and ports

## Running

### Development
```bash
cargo run
```

By default, servers start for the enabled sections in `config.ini`. Ensure MySQL and S3 are reachable and configured.

### Testing IMAP
Use the enhanced test script:
```bash
bash test_imap.sh --server 127.0.0.1 --port 1143 --no-ssl -v
```

Seeded account: `user@example.com` with a valid password (bcrypt hash in schema).

### Antivirus (ClamAV)
- Enabled via `[antivirus]` section in config; communicates with `clamd` using the INSTREAM protocol.
- Modes:
  - `reject`: Rejects infected APPEND with `NO`.
  - `quarantine`: Delivers infected messages to the `Quarantine` mailbox (auto-created if missing).
  - `tag`: Marks infected messages with `$Virus` flag in the destination mailbox.
- Keys: `enabled`, `host`, `port`, `mode`.

## Storage Model
- Bodies in S3 only. No body content in MySQL.
- MySQL tables: `accounts`, `mailboxes`, `messages`, `object_keys`, etc.
- Object keys format:
  - `emails/<uuidv7>.eml`
  - `calendars/<uuidv7>.ics`

## Garbage Collection (Soft Delete)
Deletions are soft-marked with `deleted_at` and processed asynchronously:

1. Frontline operations (IMAP EXPUNGE, POP3 DELE, API delete) set `deleted_at = NOW()`.
2. Background Garbage Worker:
   - Scans soft-deleted records
   - Deletes S3 objects
   - Hard-deletes metadata
   - Logs successes, retries failures

Details: [GARBAGE_COLLECTOR.md](GARBAGE_COLLECTOR.md).

### Garbage Worker Configuration

Tune the garbage worker via config settings:

```
[garbage]
batch_size = 100      # Number of messages per batch
idle_seconds = 60     # Sleep when no work is found
pause_seconds = 5     # Pause between batches
```

Adjust these values to match your storage throughput and operational needs.

## Security
- Password hashing: bcrypt (Argon2 optional)
- TLS via rustls
- Input validation for IMAP literals and POP3 lines
- Optional rate limiting and anti-bruteforce (roadmap)

## Roadmap
- Full APPEND with antivirus scanning
- Expanded SEARCH criteria and ENVELOPE/BODYSTRUCTURE
- STARTTLS upgrade flow
- CalDAV readiness for calendar objects
- Observability metrics endpoints

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome.
