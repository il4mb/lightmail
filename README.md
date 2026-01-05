# LightMail 📧

**A modern, high-performance, production-ready mail server written in Rust.**

LightMail is a complete rewrite of a legacy C mail server, designed for security, concurrency, and scalability. It leverages the safety of Rust and the power of the Tokio async runtime.

## 🚀 Features

- **Protocols**:
  - **IMAP4rev1** (RFC 3501) with extensions (IDLE, UIDPLUS, SPECIAL-USE).
  - **POP3** (RFC 1939) for lightweight retrieval.
  - **LMTP** (RFC 2033) for local delivery from MTAs like Postfix.
  - **HTTP API** for administration.

- **Storage**:
  - **Hybrid Architecture**:
    - **S3 Object Storage**: Stores all email bodies and attachments (scalable, cheap).
    - **MySQL**: Stores metadata, indexes, and user information (fast, relational).
  - **Zero-Copy Streaming**: Emails are streamed directly to S3 during delivery.

- **Security**:
  - **Modern Auth**: Bcrypt/Argon2 password hashing.
  - **TLS**: Native support via `rustls`.
  - **Antivirus**: Integrated ClamAV scanning during delivery.

- **Observability**:
  - Structured logging with `tracing`.
  - Prometheus-ready metrics.

## 📚 Documentation

- [Architecture Overview](ARCHITECTURE.md)
- [RFC Compliance](RFC_COMPLIANCE.md)
- [Storage Design](STORAGE.md)

## 🛠️ Installation & Usage

### Prerequisites
- Rust (latest stable)
- MySQL 8.0+
- S3-compatible storage (AWS S3, MinIO, etc.)
- ClamAV (optional, for antivirus)

### Configuration
Copy the example config:
```bash
cp config.ini.example /etc/lightmail/config.ini
```
Edit `/etc/lightmail/config.ini` with your database and S3 credentials.

### Running
```bash
# Build release
cargo build --release

# Run
./target/release/lightmail --config /etc/lightmail/config.ini
```

## 🏗️ Development

### Project Structure
- `src/protocol/`: IMAP, POP3, LMTP implementations.
- `src/storage/`: Database and S3 abstractions.
- `src/api/`: HTTP REST API.
- `src/runtime.rs`: Service lifecycle management.

### Testing
```bash
cargo test
```

## 📄 License
MIT
