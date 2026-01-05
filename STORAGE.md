# Storage Architecture

LightMail uses a hybrid storage system designed for scalability and performance.

## 1. Object Storage (S3)

All large binary data (email bodies, attachments, calendar objects) is stored in an S3-compatible object storage (e.g., AWS S3, MinIO, Ceph).

### Structure
- **Bucket**: Configured in `lightmail.conf`.
- **Key Format**: `emails/<uuidv7>.eml`
  - `uuidv7`: A time-ordered unique identifier generated when the message is received.
  - `.eml`: The raw email content including headers and body.

### Calendar Objects
- **Key Format**: `calendars/<calendar_id>/<event_uuid>.ics`

### Caching
- A local LRU cache (on disk or memory) is used to store frequently accessed messages to reduce S3 API calls and latency.
- Temporary files during LMTP reception are stored in `/tmp/lightmail-*` before being streamed to S3.

## 2. Metadata Storage (MySQL)

MySQL is used to store all structured data, relationships, and state.

### Schema Overview

#### `users`
- `id`: INT AUTO_INCREMENT
- `username`: VARCHAR (email address)
- `password_hash`: VARCHAR (bcrypt/argon2)
- `created_at`: DATETIME
- `quota_bytes`: BIGINT

#### `mailboxes`
- `id`: INT AUTO_INCREMENT
- `user_id`: INT (FK -> users.id)
- `name`: VARCHAR (e.g., INBOX, Sent, Trash)
- `uid_validity`: INT (IMAP UIDVALIDITY)
- `next_uid`: INT (Next UID to assign)
- `attributes`: JSON (Special-Use flags like \Inbox, \Sent)

#### `messages`
- `id`: BIGINT AUTO_INCREMENT
- `mailbox_id`: INT (FK -> mailboxes.id)
- `uid`: INT (IMAP UID)
- `s3_key`: VARCHAR (UUIDv7 key in S3)
- `internal_date`: DATETIME
- `size`: INT
- `flags`: INT (Bitmask or JSON for \Seen, \Answered, etc.)
- `headers`: JSON (Cached headers for fast SEARCH/SORT)

#### `calendars`
- `id`: INT AUTO_INCREMENT
- `user_id`: INT
- `name`: VARCHAR
- `color`: VARCHAR

#### `calendar_events`
- `id`: BIGINT AUTO_INCREMENT
- `calendar_id`: INT
- `s3_key`: VARCHAR
- `start_time`: DATETIME
- `end_time`: DATETIME
- `summary`: VARCHAR

## 3. Data Consistency

- **Atomic Delivery**: When a message arrives via LMTP:
  1. Stream content to S3.
  2. If S3 upload succeeds, insert metadata into MySQL.
  3. If MySQL insert fails, delete orphan object from S3 (or let a cleanup job handle it).
  4. Acknowledge LMTP only after both succeed.

- **Deletion**:
  1. Mark message as `\Deleted` in IMAP.
  2. On `EXPUNGE`, remove row from MySQL.
  3. Asynchronously delete object from S3.
