# LightMail 📧

**🚧 Work in Progress - A lightweight, scalable IMAP server with MySQL storage and S3 integration**

> **⚠️ Warning: This project is currently under active development. Features may be incomplete or subject to change.**

[![Status: WIP](https://img.shields.io/badge/status-WIP-orange)](https://github.com/il4mb/lightmail)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚧 Project Status

**Current Phase:** Early Development  
**Stability:** Pre-Alpha  
**Production Ready:** ❌ No  
**API Stability:** ❌ Breaking changes expected  

## 📋 Planned Features

### Core IMAP Server
- [ ] IMAP4rev1 protocol implementation
- [ ] SSL/TLS support (IMAPS)
- [ ] Multi-threaded client handling
- [ ] Connection pooling

### Storage Backends
- [ ] MySQL for metadata storage
- [ ] S3-compatible storage for message bodies
- [ ] Redis caching layer
- [ ] Local file system fallback

### Authentication & Security
- [ ] PLAIN authentication
- [ ] CRAM-MD5 authentication
- [ ] STARTTLS support
- [ ] Rate limiting
- [ ] IP-based access control

### Postfix Integration
- [ ] MySQL user lookup integration
- [ ] Virtual mailbox mapping
- [ ] Maildir compatibility
- [ ] LMTP delivery support

### Administration
- [ ] REST API for management
- [ ] Command-line tools
- [ ] Import/export utilities

## 🔧 Current Development Setup

### Prerequisites

```bash
# Required system packages
sudo apt-get install -y \
    build-essential \
    libmysqlclient-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    pkg-config \
    mysql-server
```

### Building from Source

```bash
# Clone repository
git clone https://github.com/il4mb/lightmail.git
cd lightmail

# Build development version
make

# Build with debug symbols
make debug

# Clean build
make clean
```

### Running Development Server

```bash
# Start server (development mode)
make run

# Run tests
make test

# Test with telnet
make test-telnet
```

## 📖 Roadmap

### Phase 1: Core Infrastructure (Current)
- [ ] Basic IMAP command parsing
- [ ] MySQL connection pool
- [ ] Configuration management
- [ ] Build system

### Phase 2: IMAP Protocol
- [ ] Authentication commands
- [ ] Mailbox operations
- [ ] Message retrieval
- [ ] Flag management

### Phase 3: Storage Integration
- [ ] S3 storage backend
- [ ] Message indexing
- [ ] Cache implementation
- [ ] Backup/restore

### Phase 4: Production Features
- [ ] SSL/TLS support
- [ ] Performance optimization
- [ ] Monitoring & logging
- [ ] Docker containers

### Phase 5: Postfix Integration
- [ ] Virtual mailbox mapping
- [ ] User authentication
- [ ] Delivery agent
- [ ] Queue management

## 🤝 Contributing

We welcome contributions! Since this project is in early development, please note:

1. **Check Issues First:** Look for open issues or create a new one to discuss your ideas
2. **Follow Code Style:** Use the existing code style and structure
3. **Add Tests:** Include tests for new features
4. **Update Documentation:** Keep documentation current with code changes

### Development Workflow

```bash
# 1. Fork the repository
# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/lightmail.git

# 3. Create a feature branch
git checkout -b feature/your-feature

# 4. Make changes and test
make debug
make test

# 5. Commit changes
git commit -m "Add your feature"

# 6. Push to your fork
git push origin feature/your-feature

# 7. Create a Pull Request
```

## 🐛 Known Issues

- [ ] Memory leaks in connection handling
- [ ] Incomplete IMAP command implementation
- [ ] Limited error handling
- [ ] No SSL/TLS support yet
- [ ] Basic authentication only

## 🔍 Testing

```bash
# Run unit tests
make test-unit

# Run integration tests
make test-integration

# Run full test suite
make test-all

# Test specific IMAP commands
make test-imap
```

## 📊 Database Schema

The planned MySQL schema includes:

```sql
-- Users and authentication
CREATE TABLE users (...);

-- Mailboxes and hierarchy
CREATE TABLE mailboxes (...);

-- Message metadata
CREATE TABLE messages (...);

-- Message bodies (S3 references)
CREATE TABLE message_bodies (...);

-- Sessions and connections
CREATE TABLE sessions (...);
```

## 🔐 Security Considerations

**⚠️ Important:** This software is not yet secure for production use.

- [ ] Implement proper password hashing
- [ ] Add rate limiting
- [ ] Implement connection encryption
- [ ] Add input validation
- [ ] Security audit needed

## 📈 Performance Goals

- Target: 10,000 concurrent connections
- Message retrieval: < 50ms for 10MB messages
- Search operations: < 100ms for 1M messages
- Memory usage: < 50MB base + 1MB per connection

## 🐳 Docker Development

```bash
# Build development container
docker build -t lightmail-dev -f Dockerfile.dev .

# Run with mounted source
docker run -v $(pwd):/app -p 143:143 lightmail-dev

# Run tests in container
docker run lightmail-dev make test
```

## 📚 Documentation Status

- [ ] API Documentation: Not started
- [ ] User Guide: Not started
- [ ] Admin Guide: Not started
- [ ] Deployment Guide: Not started
- [ ] Developer Guide: Partial

## 💡 Getting Help

- **Issues:** Use GitHub Issues for bugs and feature requests
- **Discussion:** GitHub Discussions for questions and ideas
- **Email:** [project maintainer email if available]

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by Dovecot, Cyrus IMAP, and Courier
- Built with open-source libraries: libmysqlclient, OpenSSL, libcurl
- Community contributors welcome

---

**⚠️ Disclaimer:** This software is provided "as is", without warranty of any kind. Use at your own risk. Not suitable for production environments until version 1.0.0 release.

*Last Updated: $(date)*
*Version: 0.1.0-alpha*