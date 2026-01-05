# LightMail Architecture

## Overview

LightMail is a modern, high-performance mail server written in Rust. It is designed to be modular, scalable, and secure. It uses a hybrid storage approach with MySQL for metadata and S3-compatible object storage for message bodies and attachments.

## Core Components

### 1. Runtime (`src/runtime.rs`)
The `Runtime` struct is the heart of the application. It initializes and manages:
- **Configuration**: Loaded from `config.ini`.
- **Database Connection**: Connection pool to MySQL via `sqlx`.
- **S3 Client**: Async client for object storage via `aws-sdk-s3`.
- **Protocol Servers**: Spawns tasks for IMAP, LMTP, POP3, and HTTP API.
- **Background Workers**: Spawns the Garbage Worker to process soft-deletes.

### 2. Protocols (`src/protocol/`)
LightMail supports multiple protocols, each implemented as a separate module:

- **IMAP (`src/protocol/imap/`)**:
  - Implements RFC 3501 and extensions.
  - Handles client sessions, state machine (NotAuthenticated, Authenticated, Selected).
  - Uses `nom` for parsing IMAP commands.
  - Supports IDLE for real-time updates.
  - APPEND with optional antivirus scanning (ClamAV INSTREAM).
  - UIDPLUS: returns `APPENDUID` on successful APPEND.
  - MOVE and COPY implemented; EXPUNGE performs soft-delete.

- **LMTP (`src/protocol/lmtp/`)**:
  - Implements RFC 2033.
  - Receives mail from MTAs (like Postfix) via Unix socket.
  - Streams message content directly to S3.
  - Performs antivirus scanning (ClamAV) before accepting delivery.

- **POP3 (`src/protocol/pop3/`)**:
  - Implements basic POP3 commands.
  - Read-only access to the mailbox.
  - Retrieves message content from S3.

### 3. Storage (`src/storage/`)
The storage layer abstracts the underlying data stores.

- **Database (`src/storage/db.rs`)**:
  - Handles all metadata operations (User auth, Mailbox listing, Message flags).
  - Uses `sqlx` for type-safe SQL queries.

- **Object Storage (`src/storage/s3.rs`)**:
  - Stores raw email messages (`.eml`) and calendar objects (`.ics`).
  - Uses `uuidv7` for unique object keys.
  - Supports streaming for low memory footprint.

### 4. HTTP API (`src/api/`)
- Provides a RESTful API for administration.
- Built with `axum`.
- Secured with Bearer token authentication.

### 5. Security
- **Authentication**: Passwords hashed with `bcrypt` or `argon2`.
- **TLS**: Native TLS support using `rustls`.
- **Antivirus**: Integration with ClamAV for scanning incoming mail.
  - Modes: `reject`, `quarantine`, `tag` for infected content handling.

## Data Flow

1. **Incoming Mail (LMTP)**:
   MTA -> LMTP Socket -> Parser -> Antivirus Scan -> Stream to S3 -> Insert Metadata to MySQL -> OK

2. **Mail Retrieval (IMAP)**:
   Client -> TCP/TLS -> Auth (MySQL) -> List/Select (MySQL) -> Fetch Body (S3) -> Client

3. **Message Append (IMAP)**:
  Client -> APPEND literal -> Antivirus (optional) -> Upload to S3 -> Insert metadata -> `APPENDUID` -> EXISTS/RECENT update

4. **Mail Retrieval (POP3)**:
   Client -> TCP/TLS -> Auth (MySQL) -> List (MySQL) -> Retr (S3) -> Client

5. **Garbage Collection**:
  Soft-deleted messages -> Worker batches -> Delete S3 -> Delete `object_keys` -> Delete `messages` -> Metrics

## Concurrency Model
LightMail uses `tokio` for asynchronous I/O. Each client connection is handled in its own lightweight task. Shared state (like DB pool and S3 client) is wrapped in `Arc` and shared across tasks.
