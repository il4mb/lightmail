-- V2 Schema Upgrade
-- This script upgrades the database schema from the initial version to support
-- all required features like POP3 UIDL and IMAP CONDSTORE/QRESYNC.

-- Add modification sequence numbers for IMAP CONDSTORE / QRESYNC
ALTER TABLE mailboxes ADD COLUMN highest_modseq BIGINT UNSIGNED NOT NULL DEFAULT 1;
ALTER TABLE messages ADD COLUMN modseq BIGINT UNSIGNED NOT NULL DEFAULT 1;

-- Drop the redundant string-based flags column from the messages table.
-- The `message_flags` table is the authoritative source for flags.
ALTER TABLE messages DROP COLUMN flags;

-- Create a table to map POP3 UIDLs to messages.
-- This ensures a persistent and unique identifier for each message per account,
-- as required by RFC 1939.
CREATE TABLE pop3_uidl_map (
    id INT PRIMARY KEY AUTO_INCREMENT,
    account_id INT NOT NULL,
    message_id INT NOT NULL,
    uidl VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    UNIQUE KEY unique_account_message (account_id, message_id),
    UNIQUE KEY unique_account_uidl (account_id, uidl)
) ENGINE=InnoDB;

-- Add an index to the modseq column for faster lookups.
CREATE INDEX idx_messages_modseq ON messages(modseq);

-- Add an index to the s3 key for potential lookups
CREATE INDEX idx_messages_s3_key ON messages(body_s3_key(255));
