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
- `[smtp_server]`: inbound SMTP/Submission server (AUTH uses per-account credentials from the `accounts` table)
- `[smtp]`: outbound SMTP client settings (used by the Admin API for sending mail)

## Installation

### Option A: Build from source (recommended)
Prerequisites:
- Rust toolchain (stable)
- MySQL (or compatible) for metadata
- S3-compatible object storage (MinIO, AWS S3, etc.)

Build:
```bash
cargo build --release
```

Install binary:
```bash
sudo install -m 0755 target/release/lightmail /usr/local/bin/lightmail
```

Install configuration:
```bash
sudo mkdir -p /etc/lightmail
sudo cp config.ini.example /etc/lightmail/config.ini
```

Initialize database schema (creates `maildb` by default):
```bash
mysql -u root -p < sql/schema.sql
```

Systemd service:
- A sample unit file is provided as [lightmail.service](lightmail.service).
- Copy it into place and start the service:
```bash
sudo cp lightmail.service /etc/systemd/system/lightmail.service
sudo systemctl daemon-reload
sudo systemctl enable --now lightmail
```

By default the service loads `/etc/lightmail/config.ini`.

### Option B: Install from a prebuilt binary
If you already have a `lightmail` binary (for example, from a release artifact), install it to a system PATH location:
```bash
sudo install -m 0755 lightmail /usr/local/bin/lightmail
```
Then follow the same configuration + systemd steps as above.

## Running

### Development
```bash
cargo run
```

By default, servers start for the enabled sections in `config.ini`. Ensure MySQL and S3 are reachable and configured.

## Postfix integration (recommended)
If you want to use Postfix for internet-facing SMTP (queueing, retry, DNS checks, etc.) and use LightMail as the mailbox server (IMAP/POP3 storage), the cleanest integration is:

- Postfix receives mail from the internet.
- Postfix delivers to LightMail via LMTP over a local UNIX socket.

### 0) UNIX socket permissions (recommended)
Run LightMail as a dedicated user/group (example: `lightmail:lightmail`) and allow Postfix to access the LMTP socket via group membership:

```bash
sudo groupadd --system lightmail
sudo useradd --system --no-create-home --gid lightmail lightmail

# Allow Postfix to connect to the LMTP socket
sudo usermod -aG lightmail postfix

# Postfix reads group membership at startup
sudo systemctl restart postfix
```

Create a socket directory inside Postfix's spool (works with Postfix's default chrooted services):

```bash
sudo mkdir -p /var/spool/postfix/lightmail
sudo chown lightmail:lightmail /var/spool/postfix/lightmail
sudo chmod 750 /var/spool/postfix/lightmail
```

### 1) Enable LMTP in LightMail
In `/etc/lightmail/config.ini`:
```
[lmtp]
socket = /var/spool/postfix/lightmail/lmtp.sock
max_message_size = 52428800
```
Expected permissions (after LightMail starts):
`srw-rw---- lightmail lightmail ... lmtp.sock`

### 2) Configure Postfix to deliver via LMTP
Add this to `/etc/postfix/main.cf`:
```
# Deliver local mail to LightMail over LMTP
virtual_transport = lmtp:unix:/var/spool/postfix/lightmail/lmtp.sock
```

If you only want some domains/users to go to LightMail, use `transport_maps` instead (domain-based routing):
```
transport_maps = hash:/etc/postfix/transport
```
Example `/etc/postfix/transport`:
```
example.com lmtp:unix:/var/spool/postfix/lightmail/lmtp.sock
```
Then run:
```bash
sudo postmap /etc/postfix/transport
sudo systemctl reload postfix
```

Verification helpers:
```bash
ls -l /var/spool/postfix/lightmail/lmtp.sock
id postfix
```

### 3) Run LightMail behind Postfix (optional)
If Postfix is your front-door MTA, you can keep LightMail’s inbound SMTP (`[smtp_server]`) bound to localhost only (or disable it) and rely on LMTP for delivery.

### Testing IMAP
Use the enhanced test script:
```bash
bash test_imap.sh --server 127.0.0.1 --port 1143 --no-ssl -v
```

Seeded account: `user@example.com` with a valid password (bcrypt hash in schema).

### SMTP Delivery Integration Test (Opt-in)
There is an opt-in integration test that delivers a message via SMTP and asserts it was persisted to MySQL + S3.

- It loads configuration from `/etc/lightmail/config.ini` by default.
- For local development you can symlink it to the repo config:
  - `sudo mkdir -p /etc/lightmail`
  - `sudo ln -sf "$(pwd)/config/lightmail.conf" /etc/lightmail/config.ini`

Run the test (requires DB + S3 reachable per your config):
```bash
LIGHTMAIL_DELIVERY_ITEST=1 cargo test -q smtp_delivery_persists_to_db_and_s3_when_configured
```

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
- Password hashing: bcrypt
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
