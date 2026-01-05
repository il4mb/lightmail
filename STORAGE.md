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
#### `domains`
- `id` int AUTO_INCREMENT(PK)
- `domain_name` VARCHAR(255)
- `max_account` INT 
- `is_active` TINYINT(1)
- `created_at` TIMESTAMP
- `updated_at` TIMESTAMP
  
#### `accounts`
- `id` int AUTO_INCREMENT(PK)
- `domain_id` INT(FK -> domains.id)
- `username` VARCHAR(64)
- `password_hash` VARCHAR(255)
- `full_name` VARCHAR(255)
- `storage_quota` INT(MB) DEFAULT 10240
- `is_active` TINYINT(1)
- `created_at` TIMESTAMP
- `updated_at` TIMESTAMP

#### `mailboxes`
- `id` INT AUTO_INCREMENT(PK)
- `account_id` INT(FK -> accounts.id)
- `name` VARCHAR(255)
- `flags` VARCHAR(512)
- `quota` INT DEFAULT 1000000
- `created_at` TIMESTTAMP
- `updated_at` TIMESTTAMP 
- `uidvalidity` INT DEFAULT NULL

#### `object_keys`
- `id` INT AUTO_INCREMENT(PK)
- `size` INT
- `key` VARCHAR(64)

#### `messages`
- `id` INT AUTO_INCREMENT(PK)
- `mailbox_id` INT(FK -> mailboxes.id)
- `object_id` INT(FK -> object_keys.id)
- `flags` VARCHAR(255)
- `sender` VARCHAR(255)
- `subject` TEXT,
- `header` JSON,
- `created_at` TIMESTAMP 
- `updated_at` TIMESTAMP


#### `calendars`
- `id`: INT AUTO_INCREMENT(PK)
- `user_id`: INT
- `name`: VARCHAR
- `color`: VARCHAR

#### `calendar_events`
- `id`: BIGINT AUTO_INCREMENT(PK)
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

- **Deletion (Soft Delete)**:
  1. Mark message as `\Deleted` in IMAP.
  2. On `EXPUNGE`, set `deleted_at = NOW()` (soft-delete) in MySQL.
  3. Background Garbage Worker:
     - Deletes S3 object (if present).
     - Deletes `object_keys` row.
     - Hard-deletes `messages` row.
     - Logs metrics and failures.
