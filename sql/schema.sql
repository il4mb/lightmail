-- Create database
CREATE DATABASE IF NOT EXISTS maildb;
USE maildb;

-- Domains table
CREATE TABLE domains (
    id INT PRIMARY KEY AUTO_INCREMENT,
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    quota_mb INT DEFAULT 1024,
    quota_used_mb INT DEFAULT 0,
    max_accounts INT DEFAULT 10,
    INDEX idx_domain_name (domain_name)
) ENGINE=InnoDB;

-- Users/Accounts table
-- Note: email is derived from username@domain, so no separate email column is needed
CREATE TABLE accounts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    domain_id INT NOT NULL,
    username VARCHAR(64) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    quota_mb INT DEFAULT 1024,
    quota_used_mb INT DEFAULT 0,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_username (username),
    UNIQUE KEY unique_domain_user (domain_id, username)
) ENGINE=InnoDB;

-- Mailboxes table
CREATE TABLE mailboxes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    account_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    flags VARCHAR(512) DEFAULT '',
    permanent_flags VARCHAR(512) DEFAULT '',
    uid_validity INT DEFAULT 1,
    uid_next INT DEFAULT 1,
    total_messages INT DEFAULT 0,
    unseen_messages INT DEFAULT 0,
    recent_messages INT DEFAULT 0,
    is_subscribed BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    UNIQUE KEY unique_account_mailbox (account_id, name),
    INDEX idx_name (name)
) ENGINE=InnoDB;

-- Messages table
CREATE TABLE messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    mailbox_id INT NOT NULL,
    uid INT NOT NULL,
    internal_date DATETIME NOT NULL,
    flags VARCHAR(255) DEFAULT '',
    size INT NOT NULL,
    envelope_from VARCHAR(512),
    envelope_to VARCHAR(512),
    envelope_cc VARCHAR(512),
    envelope_bcc VARCHAR(512),
    envelope_subject VARCHAR(512),
    envelope_message_id VARCHAR(255),
    envelope_in_reply_to VARCHAR(255),
    envelope_references VARCHAR(1024),
    body_s3_key VARCHAR(1024) NOT NULL,
    body_size INT NOT NULL,
    mime_type VARCHAR(255) DEFAULT 'text/plain',
    encoding VARCHAR(50) DEFAULT '7bit',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE,
    UNIQUE KEY unique_mailbox_uid (mailbox_id, uid),
    INDEX idx_uid (uid),
    INDEX idx_internal_date (internal_date),
    INDEX idx_flags (flags(50))
) ENGINE=InnoDB;

-- Message headers table
CREATE TABLE message_headers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    message_id INT NOT NULL,
    header_name VARCHAR(255) NOT NULL,
    header_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    INDEX idx_message_id (message_id),
    INDEX idx_header_name (header_name)
) ENGINE=InnoDB;

-- Message flags table (for faster flag queries)
CREATE TABLE message_flags (
    id INT PRIMARY KEY AUTO_INCREMENT,
    message_id INT NOT NULL,
    flag_name VARCHAR(50) NOT NULL,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    UNIQUE KEY unique_message_flag (message_id, flag_name),
    INDEX idx_flag_name (flag_name)
) ENGINE=InnoDB;

-- Sessions table
CREATE TABLE sessions (
    id VARCHAR(128) PRIMARY KEY,
    account_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    INDEX idx_account_id (account_id),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB;

-- Create initial indexes
CREATE INDEX idx_messages_date ON messages(internal_date);
CREATE INDEX idx_mailboxes_account ON mailboxes(account_id);
CREATE INDEX idx_messages_mailbox ON messages(mailbox_id);