USE imap_server;

-- Insert default domain
INSERT INTO domains (domain_name) VALUES ('example.com');

-- Insert default user
-- Password: "password123" hashed with bcrypt
INSERT INTO accounts (domain_id, username, password_hash, full_name) VALUES
(1, 'user@example.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test User');

-- Create default mailboxes for the user
INSERT INTO mailboxes (account_id, name, flags, permanent_flags) VALUES
(1, 'INBOX', '\\Answered \\Flagged \\Deleted \\Seen \\Draft', '\\Answered \\Flagged \\Deleted \\Seen \\Draft'),
(1, 'Sent', '\\Answered \\Flagged \\Deleted \\Seen \\Draft', '\\Answered \\Flagged \\Deleted \\Seen \\Draft'),
(1, 'Drafts', '\\Answered \\Flagged \\Deleted \\Seen \\Draft', '\\Answered \\Flagged \\Deleted \\Seen \\Draft'),
(1, 'Trash', '\\Answered \\Flagged \\Deleted \\Seen \\Draft', '\\Answered \\Flagged \\Deleted \\Seen \\Draft'),
(1, 'Spam', '\\Answered \\Flagged \\Deleted \\Seen \\Draft', '\\Answered \\Flagged \\Deleted \\Seen \\Draft');