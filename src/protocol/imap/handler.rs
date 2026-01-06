// src/protocol/imap/handler.rs
use crate::runtime::Runtime;
use crate::storage::models::{ account, mailbox, object, message };
use crate::utils::generate_uidvalidity;

use account::state::AuthError::{ InvalidCredentials, Database, Crypto };
use super::state::{ ImapSession, ImapState, SelectedMailbox };
use super::command::{
    state::{ ImapCommand, UidCommand, SearchCriteria, SequenceSet, FetchItem, StoreOperation },
    parse_command,
};
use std::sync::Arc;
use chrono::{ Utc };
use tokio::io::{ AsyncBufReadExt, AsyncWriteExt, AsyncReadExt, BufReader, BufWriter };
use tokio::sync::Mutex;
use tracing::{ debug, error, info, warn };
use anyhow::{ Result };

pub struct ImapHandler {
    runtime: Arc<Runtime>,
    session: Arc<Mutex<ImapSession>>,
}

impl ImapHandler {
    pub fn new(runtime: Arc<Runtime>, session: Arc<Mutex<ImapSession>>) -> Self {
        Self { runtime, session }
    }

    pub async fn handle_connection<T>(&self, stream: T) -> Result<()>
        where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut writer = BufWriter::new(write_half);

        // Send initial greeting
        self.send_greeting(&mut writer).await?;

        let mut line = String::new();

        loop {
            line.clear();

            // Read command line
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                debug!("Client disconnected");
                break;
            }

            // If we're currently expecting literal data, consume raw bytes including CRLF
            let mut session = self.session.lock().await;
            if session.in_literal {
                self.read_literal_bytes(&mut session, &mut reader, &mut writer).await?;
                continue;
            }

            // For normal command lines, trim CRLF
            let trimmed = line.trim_end_matches("\r\n");
            if trimmed.is_empty() {
                continue;
            }

            if session.idle_active && trimmed.eq_ignore_ascii_case("DONE") {
                self.handle_id_done(&trimmed, &mut writer).await?;
                continue;
            }

            // Parse command
            match parse_command(trimmed) {
                Ok((remaining, (tag, command))) => {
                    debug!("Parsed command: {:?}", command);

                    // Check for literal string
                    if remaining.contains('{') {
                        if
                            let Err(e) = self.handle_literal_start(
                                &mut session,
                                remaining,
                                &mut writer
                            ).await
                        {
                            error!("Literal handling error: {}", e);
                            self.send_error(
                                &mut writer,
                                &tag,
                                "BAD",
                                "Literal handling failed"
                            ).await?;
                            continue;
                        }
                        // Store original command line for processing after literal
                        session.pending_commands.push(tag.clone());
                        session.pending_commands.push(trimmed.to_string());
                        continue;
                    }

                    // Process command
                    drop(session); // Release lock before async processing
                    self.process_command(&tag, command, &mut writer).await?;
                }
                Err(e) => {
                    error!("Parse error: {} for line: {}", e, trimmed);
                    self.send_error(&mut writer, "BAD", "BAD", "Command parse error").await?;
                }
            }

            // Check if session is in logout state
            let session = self.session.lock().await;
            if session.state == super::state::ImapState::Logout {
                info!("Logout requested, closing connection");
                break;
            }
        }

        Ok(())
    }

    async fn send_greeting(
        &self,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let hostname = self.runtime.config
            .get_value("system", "hostname")
            .unwrap_or("localhost")
            .to_string();

        // Build capabilities dynamically
        let enable_ssl = self.runtime
            .config
            .get_value("imap", "enable_ssl")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let session = self.session.lock().await;
        // Start with IMAP4rev1 and merge session capabilities
        let mut caps: Vec<String> = vec!["IMAP4rev1".to_string()];
        // Merge session capabilities
        for c in &session.capabilities {
            if !caps.iter().any(|x| x.eq_ignore_ascii_case(c)) {
                caps.push(c.clone());
            }
        }
        if enable_ssl && !session.tls_active {
            // Advertise STARTTLS only on non-TLS connections when SSL is enabled
            if !caps.iter().any(|x| x.eq_ignore_ascii_case("STARTTLS")) {
                caps.push("STARTTLS".to_string());
            }
        }
        drop(session);

        let greeting = format!(
            "* OK [CAPABILITY {}] {} IMAP server ready\r\n",
            caps.join(" "),
            hostname
        );
        writer.write_all(greeting.as_bytes()).await?;
        writer.flush().await?;

        Ok(())
    }

    async fn process_command(
        &self,
        tag: &str,
        command: ImapCommand,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        info!("IMAP command received: tag={} cmd={:?}", tag, command);
        // Enforce TLS-only if configured
        let tls_only = self.runtime.config.get_bool("imap", "tls_only", false);
        if tls_only {
            let session = self.session.lock().await;
            let is_tls = session.tls_active;
            drop(session);
            match command {
                ImapCommand::StartTls | ImapCommand::Capability | ImapCommand::Logout | ImapCommand::Noop => {}
                _ => {
                    if !is_tls {
                        self.send_error(writer, tag, "NO", "TLS required").await?;
                        return Ok(());
                    }
                }
            }
        }

        // Per-session rate limiting: N commands per window
        let window_secs = self.runtime.config.get_int("imap", "rate_limit_window_secs", 10);
        let max_cmds = self.runtime.config.get_int("imap", "rate_limit_commands", 50);
        {
            use std::time::{Instant, Duration};
            let mut session = self.session.lock().await;
            let now = Instant::now();
            if let Some(start) = session.rate_window_start {
                if now.duration_since(start) > Duration::from_secs(window_secs as u64) {
                    session.rate_window_start = Some(now);
                    session.rate_count = 0;
                }
            } else {
                session.rate_window_start = Some(now);
                session.rate_count = 0;
            }
            session.rate_count = session.rate_count.saturating_add(1);
            if (session.rate_count as i32) > max_cmds {
                drop(session);
                self.send_error(writer, tag, "NO", "Rate limit exceeded").await?;
                return Ok(());
            }
        }

        match command {
            ImapCommand::Capability => self.handle_capability(tag, writer).await,
            ImapCommand::Noop => self.handle_noop(tag, writer).await,
            ImapCommand::Logout => self.handle_logout(tag, writer).await,
            ImapCommand::Login { username, password } => {
                self.handle_login(tag, username, password, writer).await
            }
            ImapCommand::Select { mailbox } => {
                self.handle_select(tag, mailbox, false, writer).await
            }
            ImapCommand::Examine { mailbox } => {
                self.handle_select(tag, mailbox, true, writer).await
            }
            ImapCommand::Fetch { sequence_set, items } => {
                self.handle_fetch(tag, sequence_set, items, false, writer).await
            }
            ImapCommand::Uid { command: uid_cmd } => {
                match *uid_cmd {
                    UidCommand::Fetch { sequence_set, items } => {
                        self.handle_fetch(tag, sequence_set, items, true, writer).await
                    }
                    UidCommand::Search { criteria, charset } => {
                        self.handle_search(tag, criteria, charset, true, writer).await
                    }
                    _ => {
                        self.send_error(writer, tag, "BAD", "UID command not implemented").await
                    }
                }
            }
            ImapCommand::Search { criteria, charset } => {
                self.handle_search(tag, criteria, charset, false, writer).await
            }
            ImapCommand::Store { sequence_set, flags, operation } => {
                self.handle_store(tag, sequence_set, flags, operation, false, writer).await
            }
            ImapCommand::Idle => self.handle_idle(tag, writer).await,
            ImapCommand::IdDone => self.handle_id_done(tag, writer).await,
            ImapCommand::Create { mailbox } => self.handle_create(tag, mailbox, writer).await,
            ImapCommand::Delete { mailbox } => self.handle_delete(tag, mailbox, writer).await,
            ImapCommand::List { reference, pattern } => {
                self.handle_list(tag, &reference, &pattern, writer).await
            }
            ImapCommand::Lsub { reference, pattern } => {
                self.handle_lsub(tag, &reference, &pattern, writer).await
            }

            ImapCommand::Status { mailbox, items } => {
                self.handle_status(tag, mailbox, items, writer).await
            }
            ImapCommand::Append { mailbox, flags, date_time, message } => {
                self.handle_append(tag, mailbox, flags, date_time, message, writer).await
            }
            ImapCommand::Check => self.handle_check(tag, writer).await,
            ImapCommand::Close => self.handle_close(tag, writer).await,
            ImapCommand::Expunge => self.handle_expunge(tag, writer).await,
            ImapCommand::Copy { sequence_set, mailbox } => {
                self.handle_copy(tag, sequence_set, mailbox, false, writer).await
            }
            ImapCommand::Move { sequence_set, mailbox } => {
                self.handle_copy(tag, sequence_set, mailbox, true, writer).await
            }

            ImapCommand::Rename { from, to } => self.handle_rename(tag, from, to, writer).await,
            ImapCommand::StartTls => self.handle_starttls(tag, writer).await,
            ImapCommand::Authenticate { mechanism, initial_response } => {
                self.handle_authenticate(tag, mechanism, initial_response, writer).await
            }
            ImapCommand::Enable { features } => self.handle_enable(tag, features, writer).await,
            ImapCommand::Namespace => self.handle_namespace(tag, writer).await,
            ImapCommand::Unknown { command } => {
                warn!("Unknown command: {}", command);
                self.send_error(writer, tag, "BAD", "Unknown command").await
            }
            _ => { self.send_error(writer, tag, "BAD", "Command not implemented").await }
        }
    }

    async fn handle_capability(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let session = self.session.lock().await;
        let caps = session.get_capabilities_string();

        let response = format!(
            "* CAPABILITY IMAP4rev1 {}\r\n{} OK CAPABILITY completed\r\n",
            caps,
            tag
        );

        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_login(
        &self,
        tag: &str,
        username: String,
        password: String,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        // Check session state
        let mut session = self.session.lock().await;
        if session.state != ImapState::NotAuthenticated {
            self.send_error(writer, tag, "NO", "Already authenticated").await?;
            return Ok(());
        }

        // Validate credentials: allow graceful failure when DB is unavailable
        let database = match self.runtime.db.get() {
            Some(db) => db,
            None => {
                // Gracefully indicate auth service is unavailable without closing connection
                self.send_error(writer, tag, "NO", "[UNAVAILABLE] Authentication service unavailable").await?;
                return Ok(());
            }
        };
        let pool = database.pool();

        // Authenticate user
        match account::authenticate(pool, &username, &password).await {
            Ok(user_id) => {
                session.authenticate(username.clone(), user_id);
                let response = format!("{} OK LOGIN completed\r\n", tag);
                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;

                info!("User logged in: {}", username);
                Ok(())
            }
            Err(err) => {
                match err {
                    InvalidCredentials => {
                        info!("Invalid login attempt for {}", username);

                        self.send_error(
                            writer,
                            tag,
                            "NO",
                            "[AUTHENTICATIONFAILED] Invalid username or password"
                        ).await
                    }

                    Database(e) => {
                        error!("Database error during login: {:?}", e);

                        writer.write_all(
                            format!(
                                "* BYE [UNAVAILABLE] Authentication service unavailable\r\n"
                            ).as_bytes()
                        ).await?;
                        writer.flush().await?;
                        Ok(())
                    }

                    Crypto(e) => {
                        error!("Password verification failure: {:?}", e);

                        writer.write_all(
                            format!(
                                "* BYE [SERVERBUG] Authentication system failure\r\n"
                            ).as_bytes()
                        ).await?;
                        writer.flush().await?;
                        Ok(())
                    }
                }
            }
        }
    }

    async fn handle_select(
        &self,
        tag: &str,
        mailbox_name: String,
        read_only: bool,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let mut session = self.session.lock().await;
        // Check authentication
        if session.state == ImapState::NotAuthenticated {
            self.send_error(writer, tag, "NO", "Authentication required").await?;
            return Ok(());
        }

        let user_id = &session.authenticated_user_id.ok_or_else(||
            anyhow::anyhow!("No authenticated user")
        )?;
        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();

        // Find mailbox
        match mailbox::find_by_name(&pool, user_id, &mailbox_name).await {
            Ok(Some(mailbox)) => {
                // Get mailbox stats
                let stats = mailbox::get_mailbox_stats(&pool, mailbox.id).await?;

                // Create selected mailbox info
                let selected = SelectedMailbox {
                    id: mailbox.id, // Should be actual mailbox UUID
                    name: mailbox_name.clone(),
                    uid_validity: mailbox.uidvalidity.unwrap_or(1),
                    uid_next: stats.total + 1,
                    exists: stats.total,
                    recent: stats.recent,
                    unseen: stats.unseen,
                    flags: vec![
                        "\\Answered".to_string(),
                        "\\Flagged".to_string(),
                        "\\Deleted".to_string(),
                        "\\Seen".to_string(),
                        "\\Draft".to_string()
                    ],
                    permanent_flags: vec![
                        "\\Answered".to_string(),
                        "\\Flagged".to_string(),
                        "\\Deleted".to_string(),
                        "\\Seen".to_string(),
                        "\\Draft".to_string(),
                        "\\*".to_string() // Client can create keywords
                    ],
                    read_write: !read_only,
                };

                session.select_mailbox(selected, !read_only);

                // Send SELECT/EXAMINE response (RFC 3501)
                let cmd_name = if read_only { "EXAMINE" } else { "SELECT" };

                // Use mailbox uidvalidity if present, else fallback to 1
                let uidvalidity = mailbox.uidvalidity.unwrap_or(1);
                let uidnext = stats.total + 1;

                // Write untagged responses line by line to help clients that read incrementally
                writer.write_all(format!("* {} EXISTS\r\n", stats.total).as_bytes()).await?;
                writer.write_all(format!("* {} RECENT\r\n", stats.recent).as_bytes()).await?;
                writer.write_all(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n").await?;
                writer.write_all(format!("* OK [UNSEEN {}] First unseen\r\n", stats.unseen).as_bytes()).await?;
                writer.write_all(format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", uidvalidity).as_bytes()).await?;
                writer.write_all(format!("* OK [UIDNEXT {}] Predicted next UID\r\n", uidnext).as_bytes()).await?;
                writer.write_all(b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Permanent flags\r\n").await?;
                // Final tagged OK line with read/write status per RFC 3501
                let mode = if read_only { "[READ-ONLY]" } else { "[READ-WRITE]" };
                writer.write_all(format!("{} OK {} {} completed\r\n", tag, mode, cmd_name).as_bytes()).await?;
                writer.flush().await?;

                info!(
                    "{} completed: mailbox={} exists={} recent={} unseen={} uidvalidity={} uidnext={} mode={}",
                    cmd_name,
                    mailbox_name,
                    stats.total,
                    stats.recent,
                    stats.unseen,
                    uidvalidity,
                    uidnext,
                    if read_only { "READ-ONLY" } else { "READ-WRITE" }
                );
                Ok(())
            }
            Ok(None) => { self.send_error(writer, tag, "NO", "Mailbox does not exist").await }
            Err(e) => {
                error!("Database error: {}", e);
                self.send_error(writer, tag, "NO", "Temporary failure").await
            }
        }
    }

    async fn resolve_sequence_set(
        &self,
        sequence_set: &super::command::state::SequenceSet,
        mailbox_id: i64,
        is_uid: bool,
        pool: &sqlx::MySqlPool
    ) -> Result<Vec<i64>> {
        use super::command::state::{ SequenceRange };

        let mut message_ids = Vec::new();
        let total_messages = message::get_message_count(pool, mailbox_id).await?;

        for range in &sequence_set.ranges {
            match range {
                SequenceRange::Single(n) => {
                    if is_uid {
                        // UID mode: n is a UID
                        if *n > 0 {
                            message_ids.push(*n as i64);
                        }
                    } else {
                        // Sequence mode: n is a 1-based sequence number
                        if *n > 0 && (*n as i64) <= total_messages {
                            // Get the message at this sequence position
                            let messages: Vec<message::Message> = message::get_messages_by_sequence_range(
                                pool, mailbox_id, *n as i64, *n as i64
                            ).await?;
                            if let Some(msg) = messages.first() {
                                message_ids.push(msg.id);
                            }
                        }
                    }
                }
                SequenceRange::Range(start, end) => {
                    if is_uid {
                        // UID range
                        let messages: Vec<message::Message> = message::get_messages_by_uid_range(
                            pool, mailbox_id, *start as i64, *end as i64
                        ).await?;
                        message_ids.extend(messages.iter().map(|m| m.id));
                    } else {
                        // Sequence range
                        let start_seq = *start as i64;
                        let end_seq = *end as i64;
                        if start_seq > 0 && end_seq >= start_seq && start_seq <= total_messages {
                            let actual_end = end_seq.min(total_messages);
                            let messages: Vec<message::Message> = message::get_messages_by_sequence_range(
                                pool, mailbox_id, start_seq, actual_end
                            ).await?;
                            message_ids.extend(messages.iter().map(|m| m.id));
                        }
                    }
                }
                SequenceRange::From(start) => {
                    if is_uid {
                        // All UIDs >= start
                        let messages: Vec<message::Message> = message::get_messages_by_uid_range(
                            pool, mailbox_id, *start as i64, i64::MAX
                        ).await?;
                        message_ids.extend(messages.iter().map(|m| m.id));
                    } else {
                        // All sequences >= start
                        let start_seq = *start as i64;
                        if start_seq > 0 && start_seq <= total_messages {
                            let messages: Vec<message::Message> = message::get_messages_by_sequence_range(
                                pool, mailbox_id, start_seq, total_messages
                            ).await?;
                            message_ids.extend(messages.iter().map(|m| m.id));
                        }
                    }
                }
                SequenceRange::To(end) => {
                    if is_uid {
                        // All UIDs <= end (unusual but supported)
                        let messages: Vec<message::Message> = message::get_messages_by_uid_range(
                            pool, mailbox_id, 1, *end as i64
                        ).await?;
                        message_ids.extend(messages.iter().map(|m| m.id));
                    } else {
                        // All sequences <= end
                        let end_seq = *end as i64;
                        if end_seq > 0 {
                            let actual_end = end_seq.min(total_messages);
                            let messages: Vec<message::Message> = message::get_messages_by_sequence_range(
                                pool, mailbox_id, 1, actual_end
                            ).await?;
                            message_ids.extend(messages.iter().map(|m| m.id));
                        }
                    }
                }
            }
        }

        // Remove duplicates and sort
        message_ids.sort();
        message_ids.dedup();
        Ok(message_ids)
    }

    async fn get_sequence_number(&self, pool: &sqlx::MySqlPool, mailbox_id: i64, message_id: i64) -> Result<i64> {
        // Count messages with lower IDs in the same mailbox (1-based), excluding soft-deleted
        let query = "SELECT COUNT(*) as seq FROM messages WHERE mailbox_id = ? AND deleted_at IS NULL AND id <= ?";
        let (seq,): (i64,) = sqlx::query_as(query)
            .bind(mailbox_id)
            .bind(message_id)
            .fetch_one(pool).await?;
        Ok(seq)
    }

    async fn handle_fetch(
        &self,
        tag: &str,
        sequence_set: SequenceSet,
        items: Vec<FetchItem>,
        is_uid: bool,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let session = self.session.lock().await;

        // Check state
        if session.state != ImapState::Selected {
            self.send_error(writer, tag, "BAD", "No mailbox selected").await?;
            return Ok(());
        }

        let selected = session.selected_mailbox
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No mailbox selected"))?;

        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();

        // Resolve sequence set to message IDs
        let message_ids = self.resolve_sequence_set(&sequence_set, selected.id, is_uid, pool).await?;

        // For each message, fetch and send response
        for message_id in message_ids {
            if let Some(message) = message::get_message(pool, message_id).await? {
                // Calculate sequence number (1-based position in mailbox)
                let sequence_num = self.get_sequence_number(pool, selected.id, message.id).await?;

                // Build fetch response
                let mut response_parts = Vec::new();

                for item in &items {
                    match item {
                        FetchItem::All => {
                            // FLAGS INTERNALDATE RFC822.SIZE ENVELOPE
                            response_parts.push(format!("FLAGS (\\Seen)"));
                            response_parts.push(format!("INTERNALDATE \"{}\"", 
                                message.created_at.format("%d-%b-%Y %H:%M:%S %z")));
                            response_parts.push(format!("RFC822.SIZE {}", message.size));
                            // TODO: Add ENVELOPE
                        }
                        FetchItem::Fast => {
                            // FLAGS INTERNALDATE RFC822.SIZE
                            response_parts.push(format!("FLAGS (\\Seen)"));
                            response_parts.push(format!("INTERNALDATE \"{}\"", 
                                message.created_at.format("%d-%b-%Y %H:%M:%S %z")));
                            response_parts.push(format!("RFC822.SIZE {}", message.size));
                        }
                        FetchItem::Full => {
                            // FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY
                            response_parts.push(format!("FLAGS (\\Seen)"));
                            response_parts.push(format!("INTERNALDATE \"{}\"", 
                                message.created_at.format("%d-%b-%Y %H:%M:%S %z")));
                            response_parts.push(format!("RFC822.SIZE {}", message.size));
                            // TODO: Add ENVELOPE and BODY
                        }
                        FetchItem::Flags => {
                            response_parts.push("FLAGS (\\Seen)".to_string());
                        }
                        FetchItem::InternalDate => {
                            response_parts.push(format!("INTERNALDATE \"{}\"", 
                                message.created_at.format("%d-%b-%Y %H:%M:%S %z")));
                        }
                        FetchItem::Rfc822Size => {
                            response_parts.push(format!("RFC822.SIZE {}", message.size));
                        }
                        FetchItem::Uid => {
                            response_parts.push(format!("UID {}", message.uid));
                        }
                        FetchItem::Body => {
                            // Get message content from S3
                            if let Some(key) = object::get_key_by_id(pool, message.object_id).await? {
                                if let Ok(content) = object::get_content(&self.runtime, &key).await {
                                    response_parts.push(format!("BODY {{{}}}", content.len()));
                                    response_parts.push(content);
                                }
                            }
                        }
                        FetchItem::Rfc822 => {
                            // Same as BODY[]
                            if let Some(key) = object::get_key_by_id(pool, message.object_id).await? {
                                if let Ok(content) = object::get_content(&self.runtime, &key).await {
                                    response_parts.push(format!("RFC822 {{{}}}", content.len()));
                                    response_parts.push(content);
                                }
                            }
                        }
                        FetchItem::Envelope => {
                            // TODO: Parse and format envelope
                            response_parts.push("ENVELOPE (\"Mon, 1 Jan 2024 00:00:00 +0000\" \"Test\" ((\"Sender\" NIL \"sender\" \"example.com\")) ((\"Sender\" NIL \"sender\" \"example.com\")) ((\"Sender\" NIL \"sender\" \"example.com\")) NIL NIL NIL \"<test@example.com>\")".to_string());
                        }
                        _ => {
                            // Other items not implemented yet
                        }
                    }
                }

                if !response_parts.is_empty() {
                    let response = format!("* {} FETCH ({})", sequence_num, response_parts.join(" "));
                    writer.write_all(format!("{}\r\n", response).as_bytes()).await?;
                }
            }
        }

        let response = format!("{} OK FETCH completed\r\n", tag);
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;

        Ok(())
    }

    async fn handle_search(
        &self,
        tag: &str,
        criteria: SearchCriteria,
        charset: Option<String>,
        is_uid: bool,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let session = self.session.lock().await;

        if session.state != ImapState::Selected {
            self.send_error(writer, tag, "BAD", "No mailbox selected").await?;
            return Ok(());
        }

        // Handle charset if provided
        if let Some(cs) = charset {
            if cs.to_uppercase() != "UTF-8" && cs.to_uppercase() != "US-ASCII" {
                self.send_error(writer, tag, "NO", "Unsupported charset").await?;
                return Ok(());
            }
        }

        let selected = session.selected_mailbox
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No mailbox selected"))?;

        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();

        // For now, only handle ALL criteria - return all messages
        let mut matching_ids = Vec::new();

        match criteria {
            SearchCriteria::All => {
                // Get all messages in the mailbox
                let messages: Vec<message::Message> = message::get_messages(
                    pool, selected.id, 1000, 0
                ).await?;
                
                if is_uid {
                    matching_ids.extend(messages.iter().map(|m| m.uid));
                } else {
                    // Convert to sequence numbers
                    for message in messages {
                        let seq = self.get_sequence_number(pool, selected.id, message.id).await?;
                        matching_ids.push(seq);
                    }
                }
            }
            _ => {
                // TODO: Implement other search criteria
                // For now, return empty result
            }
        }

        // Sort and format response
        matching_ids.sort();
        let ids_str = matching_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(" ");
        
        let response = format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", ids_str, tag);
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;

        Ok(())
    }

    async fn handle_logout(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let mut session = self.session.lock().await;
        session.logout();

        let response = "* BYE IMAP server logging out\r\n";
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(format!("{} OK LOGOUT completed\r\n", tag).as_bytes()).await?;
        writer.flush().await?;

        Ok(())
    }

    async fn handle_noop(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        // NOOP is a no-operation, just send OK
        let response = format!("{} OK NOOP completed\r\n", tag);
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_idle(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let mut session = self.session.lock().await;

        if session.state != ImapState::Selected {
            self.send_error(writer, tag, "BAD", "No mailbox selected").await?;
            return Ok(());
        }

        session.start_idle();
        writer.write_all(b"+ idling\r\n").await?;
        writer.flush().await?;

        // Note: IDLE continuation is handled separately
        Ok(())
    }

    async fn handle_id_done(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let mut session = self.session.lock().await;
        session.stop_idle();

        let response = format!("{} OK IDLE terminated\r\n", tag);
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_create(
        &self,
        tag: &str,
        name: String,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let session = self.session.lock().await;

        if session.state == ImapState::NotAuthenticated {
            self.send_error(writer, tag, "NO", "Authentication required").await?;
            return Ok(());
        }

        let user_id = session.authenticated_user_id.ok_or_else(||
            anyhow::anyhow!("No authenticated user")
        )?;
        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();

        let mailbox = mailbox::state::Mailbox {
            id: 0,
            account_id: user_id,
            name: name.clone(),
            uidvalidity: Some(generate_uidvalidity()),
            flags: "\\HasNoChildren".to_string(),
            quota: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        match mailbox::create_mailbox(&pool, &mailbox).await {
            Ok(_) => {
                let response = format!("{} OK CREATE completed\r\n", tag);
                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;
                Ok(())
            }
            Err(e) => {
                error!("Create mailbox failed: {}", e);
                self.send_error(writer, tag, "NO", "Cannot create mailbox").await
            }
        }
    }

    async fn handle_list(
        &self,
        tag: &str,
        reference: &str,
        pattern: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> anyhow::Result<()> {
        let session = self.session.lock().await;

        if session.state == ImapState::NotAuthenticated {
            self.send_error(writer, tag, "NO", "Authentication required").await?;
            return Ok(());
        }

        let user_id = session.authenticated_user_id.ok_or_else(||
            anyhow::anyhow!("No authenticated user")
        )?;

        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("DB not initialized"))?;
        let pool = db.pool();

        match mailbox::list_mailboxes(pool, user_id, reference, pattern).await {
            Ok(mailboxes) => {
                let delimiter = "/";

                for mb in mailboxes {
                    println!("Mailbox: {:?}", mb);

                    let mut flags: Vec<String> = mb.flags
                        .split_whitespace()
                        .map(|f| f.to_string())
                        .collect();

                    // RFC: INBOX is always selectable
                    if mb.name.eq_ignore_ascii_case("INBOX") {
                        flags.retain(|f| f != "\\Noselect");
                    }

                    let response = format!(
                        "* {} ({}) \"{}\" \"{}\"\r\n",
                        "LIST",
                        flags.join(" "),
                        delimiter,
                        mb.name
                    );

                    writer.write_all(response.as_bytes()).await?;
                }
            }
            Err(e) => {
                error!("List mailboxes failed: {}", e);
                self.send_error(writer, tag, "NO", "Cannot list mailboxes").await?;
                return Ok(());
            }
        }

        writer.write_all(format!("{} OK LIST completed\r\n", tag).as_bytes()).await?;

        writer.flush().await?;
        Ok(())
    }

    async fn handle_lsub(
        &self,
        tag: &str,
        _reference: &str,
        _pattern: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        // Minimal LSUB: acknowledge without returning subscriptions yet
        writer.write_all(format!("{} OK LSUB completed\r\n", tag).as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_literal_start(
        &self,
        session: &mut ImapSession,
        remaining: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        // Parse literal size: {123}
        if let Some(start) = remaining.find('{') {
            if let Some(end) = remaining[start..].find('}') {
                let mut size_str = remaining[start + 1..start + end].to_string();
                // Detect non-synchronizing literal: {size+}
                let mut non_sync = false;
                if size_str.ends_with('+') {
                    non_sync = true;
                    size_str.pop();
                }
                if let Ok(size) = size_str.parse::<usize>() {
                    session.in_literal = true;
                    session.literal_remaining = size;
                    session.literal_buffer.clear();

                    // Send continuation only for synchronizing literals
                    // If client used LITERAL+ ({size+}), don't send continuation
                    if !non_sync {
                        writer.write_all(b"+ Ready for literal data\r\n").await?;
                        writer.flush().await?;
                    }
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!("Invalid literal syntax"))
    }

    // Consume exactly the declared literal bytes from the stream and process the pending command
    async fn read_literal_bytes<R: tokio::io::AsyncRead + Unpin>(
        &self,
        session: &mut ImapSession,
        reader: &mut BufReader<R>,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let remaining = session.literal_remaining;
        if remaining == 0 {
            session.in_literal = false;
            return Ok(());
        }

        let mut buf = vec![0u8; remaining];
        reader.read_exact(&mut buf).await?;
        session.literal_buffer.push_str(&String::from_utf8_lossy(&buf));
        session.literal_remaining = 0;
        session.in_literal = false;

        // After literal is fully read, process the pending command (typically APPEND)
        if let Some(cmd_line) = session.pending_commands.pop() {
            if let Some(tag) = session.pending_commands.pop() {
                match parse_command(&cmd_line) {
                    Ok((_rem, (_t, cmd))) => {
                        match cmd {
                            ImapCommand::Append { mailbox, flags, date_time, .. } => {
                                let message = std::mem::take(&mut session.literal_buffer);
                                let user_id = session.authenticated_user_id.unwrap_or(0);
                                let selected_id = session.selected_mailbox.as_ref().map(|s| s.id);
                                // Process APPEND without needing the session lock
                                self.append_internal(&tag, mailbox, user_id, flags, date_time, message, selected_id, writer).await?;
                            }
                            _ => {
                                // For unsupported literal-followed commands, acknowledge with BAD
                                self.send_error(writer, &tag, "BAD", "Literal followed by unsupported command").await?;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse pending literal command: {}", e);
                        self.send_error(writer, &tag, "BAD", "Invalid command after literal").await?;
                    }
                }
            }
        }

        Ok(())
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_literal_continuation(
        &self,
        session: &mut ImapSession,
        line: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let line_len = line.len();
        if session.literal_remaining == 0 {
            // Nothing expected; ignore
            return Ok(());
        }

        if line_len >= session.literal_remaining {
            // Consume exactly the remaining bytes; leftover (likely CRLF) is ignored here
            let take = session.literal_remaining;
            session.literal_buffer.push_str(&line[..take]);
            session.literal_remaining = 0;
        } else {
            session.literal_buffer.push_str(line);
            session.literal_remaining -= line_len;
        }

        if session.literal_remaining == 0 {
            // Literal complete, process pending command
            session.in_literal = false;

            if let Some(cmd_line) = session.pending_commands.pop() {
                if let Some(tag) = session.pending_commands.pop() {
                    debug!("Literal data complete: {} bytes", session.literal_buffer.len());
                    // Attempt to parse the original command line
                    match parse_command(&cmd_line) {
                        Ok((_rem, (_t, cmd))) => {
                            match cmd {
                                ImapCommand::Append { mailbox, flags, date_time, .. } => {
                                    // Use buffered literal as message content
                                    let message = std::mem::take(&mut session.literal_buffer);
                                    // Collect context
                                    let user_id = session.authenticated_user_id.unwrap_or(0);
                                    let selected_id = session.selected_mailbox.as_ref().map(|s| s.id);
                                    // Process APPEND without locking session
                                    let _ = self.append_internal(&tag, mailbox, user_id, flags, date_time, message, selected_id, writer).await?;
                                }
                                _ => {
                                    // Fallback: process normally after returning
                                    // We cannot call process_command here safely due to session locking; acknowledge literal.
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse pending literal command: {}", e);
                            self.send_error(writer, &tag, "BAD", "Invalid command after literal").await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn send_error(
        &self,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>,
        tag: &str,
        response_type: &str,
        message: &str
    ) -> Result<()> {
        let response = format!("{} {} {}\r\n", tag, response_type, message);
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;

        // Count failed/bad attempts and disconnect if threshold exceeded
        let is_failure = response_type.eq_ignore_ascii_case("BAD") || response_type.eq_ignore_ascii_case("NO");
        if is_failure {
            let mut session = self.session.lock().await;
            session.failed_attempts = session.failed_attempts.saturating_add(1);

            let max_failed = self.runtime.config.get_int("imap", "max_failed_attempts", 5);
            if (session.failed_attempts as i32) >= max_failed {
                // Send BYE and mark logout
                writer.write_all(b"* BYE Too many failed commands\r\n").await?;
                writer.flush().await?;
                session.state = super::state::ImapState::Logout;
            }
        }

        Ok(())
    }

    // Additional handler methods would be implemented similarly...
    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_store(
        &self,
        tag: &str,
        sequence_set: SequenceSet,
        flags: Vec<String>,
        operation: StoreOperation,
        is_uid: bool,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let session = self.session.lock().await;
        if session.state != ImapState::Selected {
            self.send_error(writer, tag, "BAD", "No mailbox selected").await?;
            return Ok(());
        }
        let selected = session.selected_mailbox.as_ref().ok_or_else(|| anyhow::anyhow!("No mailbox selected"))?;
        let selected_id = selected.id;
        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();
        drop(session);

        let msg_ids = self.resolve_sequence_set(&sequence_set, selected_id, is_uid, pool).await?;

        // Normalize requested flags
        let mut req_flags: Vec<String> = flags.into_iter().map(|f| f.to_string()).collect();
        req_flags.sort();
        req_flags.dedup();

        for mid in msg_ids {
            // Fetch current flags
            let current = crate::storage::models::message::get_flags(pool, mid).await.unwrap_or(None).unwrap_or_default();
            let mut set: Vec<String> = current
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();

            match operation {
                StoreOperation::Add => {
                    for f in &req_flags {
                        if !set.iter().any(|x| x.eq_ignore_ascii_case(f)) {
                            set.push(f.clone());
                        }
                    }
                }
                StoreOperation::Remove => {
                    set.retain(|x| !req_flags.iter().any(|f| x.eq_ignore_ascii_case(f)));
                }
                StoreOperation::Replace | StoreOperation::Set => {
                    set = req_flags.clone();
                }
            }

            let new_flags = if set.is_empty() { String::new() } else { set.join(" ") };
            crate::storage::models::message::update_flags(pool, mid, &new_flags).await?;

            // Send updated FLAGS untagged fetch response
            let seq = self.get_sequence_number(pool, selected_id, mid).await?;
            let display_flags = if set.is_empty() { String::new() } else { set.join(" ") };
            let resp = format!("* {} FETCH (FLAGS ({}))\r\n", seq, display_flags);
            writer.write_all(resp.as_bytes()).await?;
        }

        writer.write_all(format!("{} OK STORE completed\r\n", tag).as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_close(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let mut session = self.session.lock().await;
        session.unselect_mailbox();
        self.send_error(writer, tag, "OK", "CLOSE completed").await
    }

    async fn handle_expunge(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let session = self.session.lock().await;
        if session.state != ImapState::Selected {
            drop(session);
            return self.send_error(writer, tag, "BAD", "No mailbox selected").await;
        }
        let selected = match session.selected_mailbox.as_ref() { Some(s) => s, None => {
            drop(session);
            return self.send_error(writer, tag, "BAD", "No mailbox selected").await;
        }};
        let selected_id = selected.id;
        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();
        drop(session);

        // Find messages flagged as \Deleted and not yet soft-deleted
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT id FROM messages WHERE mailbox_id = ? AND deleted_at IS NULL AND (flags LIKE '%\\\\Deleted%' OR flags LIKE '%Deleted%') ORDER BY id"
        )
        .bind(selected_id)
        .fetch_all(pool).await?;

        for (mid,) in rows {
            // Sequence number before removal
            let seq = self.get_sequence_number(pool, selected_id, mid).await?;
            // Mark soft-deleted
            crate::storage::models::message::mark_deleted(pool, mid).await?;
            // Emit untagged EXPUNGE
            let line = format!("* {} EXPUNGE\r\n", seq);
            writer.write_all(line.as_bytes()).await?;
        }

        writer.write_all(format!("{} OK EXPUNGE completed\r\n", tag).as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_check(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        self.send_error(writer, tag, "OK", "CHECK completed").await
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_copy(
        &self,
        tag: &str,
        sequence_set: SequenceSet,
        mailbox: String,
        is_move: bool,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        let session = self.session.lock().await;
        if session.state != ImapState::Selected {
            self.send_error(writer, tag, "BAD", "No mailbox selected").await?;
            return Ok(());
        }
        let selected = session.selected_mailbox.as_ref().ok_or_else(|| anyhow::anyhow!("No mailbox selected"))?;
        let selected_id = selected.id;
        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();

        // Resolve destination mailbox
        let user_id = session.authenticated_user_id.ok_or_else(|| anyhow::anyhow!("No authenticated user"))?;
        let dest = match mailbox::find_by_name(&pool, &user_id, &mailbox).await? {
            Some(m) => m,
            None => {
                self.send_error(writer, tag, "NO", "Destination mailbox does not exist").await?;
                return Ok(());
            }
        };
        drop(session);

        // Resolve message IDs
        let msg_ids = self.resolve_sequence_set(&sequence_set, selected_id, false, pool).await?;
        for mid in msg_ids {
            let _new_msg = crate::storage::models::message::copy_message_to_mailbox(pool, mid, dest.id).await?;
            if is_move {
                crate::storage::models::message::delete_message(pool, mid).await?;
            }
        }

        let action = if is_move { "MOVE" } else { "COPY" };
        writer.write_all(format!("{} OK {} completed\r\n", tag, action).as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_delete(
        &self,
        tag: &str,
        mailbox: String,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        self.send_error(writer, tag, "OK", "DELETE completed (stub)").await
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_rename(
        &self,
        tag: &str,
        from: String,
        to: String,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        self.send_error(writer, tag, "OK", "RENAME completed (stub)").await
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_status(
        &self,
        tag: &str,
        mailbox: String,
        items: Vec<String>,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        // Must be authenticated
        let session = self.session.lock().await;
        if session.state == ImapState::NotAuthenticated {
            self.send_error(writer, tag, "NO", "Authentication required").await?;
            return Ok(());
        }

        let user_id = session.authenticated_user_id.ok_or_else(|| anyhow::anyhow!("No authenticated user"))?;
        let db = self.runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();

        // Resolve mailbox
        let mbox = match mailbox::find_by_name(&pool, &user_id, &mailbox).await? {
            Some(m) => m,
            None => {
                self.send_error(writer, tag, "NO", "Mailbox does not exist").await?;
                return Ok(());
            }
        };

        let stats = mailbox::get_mailbox_stats(&pool, mbox.id).await?;

        // Build STATUS response based on requested items
        let mut pairs: Vec<String> = Vec::new();
        let req = if items.is_empty() { vec!["MESSAGES","RECENT","UNSEEN","UIDNEXT","UIDVALIDITY"].into_iter().map(String::from).collect() } else { items.clone() };
        for item in req {
            match item.to_uppercase().as_str() {
                "MESSAGES" => pairs.push(format!("MESSAGES {}", stats.total)),
                "RECENT" => pairs.push(format!("RECENT {}", stats.recent)),
                "UNSEEN" => pairs.push(format!("UNSEEN {}", stats.unseen)),
                "UIDNEXT" => {
                    // Predict next UID as max(id)+1, using total as approximation if unknown
                    let uid_next = stats.total + 1;
                    pairs.push(format!("UIDNEXT {}", uid_next));
                }
                "UIDVALIDITY" => {
                    let uidv = mbox.uidvalidity.unwrap_or(1);
                    pairs.push(format!("UIDVALIDITY {}", uidv));
                }
                other => {
                    // Ignore unsupported items gracefully
                    tracing::debug!("STATUS item not implemented: {}", other);
                }
            }
        }

        let response = format!("* STATUS {} ({})\r\n{} OK STATUS completed\r\n", mailbox, pairs.join(" "), tag);
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_append(
        &self,
        tag: &str,
        mailbox: String,
        flags: Vec<String>,
        date_time: Option<String>,
        message: String,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        // Lock session just to collect context
        let session_guard = self.session.lock().await;
        if session_guard.state == ImapState::NotAuthenticated {
            return self.send_error(writer, tag, "NO", "Authentication required").await;
        }
        let user_id = match session_guard.authenticated_user_id { Some(id) => id, None => {
            return self.send_error(writer, tag, "BAD", "No authenticated user").await;
        }};
        let selected_id = session_guard.selected_mailbox.as_ref().map(|s| s.id);
        let content = if !message.is_empty() { message } else { session_guard.literal_buffer.clone() };
        drop(session_guard);

        self.append_internal(tag, mailbox, user_id, flags, date_time, content, selected_id, writer).await
    }

    async fn append_internal(
        &self,
        tag: &str,
        mailbox: String,
        user_id: i64,
        flags: Vec<String>,
        date_time: Option<String>,
        content: String,
        selected_mailbox_id: Option<i64>,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        if content.is_empty() {
            return self.send_error(writer, tag, "BAD", "Message literal required").await;
        }

        let runtime = self.runtime.clone();
        let db = runtime.db.get().ok_or_else(|| anyhow::anyhow!("No database connection"))?;
        let pool = db.pool();

        // Resolve target mailbox
        let mbox = match mailbox::find_by_name(&pool, &user_id, &mailbox).await? {
            Some(m) => m,
            None => {
                return self.send_error(writer, tag, "NO", "Mailbox does not exist").await;
            }
        };

        // Optional antivirus scan
        let av_enabled = runtime.config.get_bool("antivirus", "enabled", false);
        let mut infected_name: Option<String> = None;
        if av_enabled {
            if let Ok(res) = self.scan_with_clamav(content.as_bytes()).await {
                if let Some(v) = res { infected_name = Some(v); }
            }
        }

        // Determine AV mode
        let av_mode = runtime.config.get_value("antivirus", "mode").unwrap_or("tag");
        if infected_name.is_some() && av_mode.eq_ignore_ascii_case("reject") {
            return self.send_error(writer, tag, "NO", "APPEND rejected: virus detected").await;
        }

        // If quarantine mode and infected, switch mailbox to Quarantine
        let mut target_mbox = mbox;
        if let Some(_virus) = infected_name.as_ref() {
            if av_mode.eq_ignore_ascii_case("quarantine") {
                if let Some(qm) = mailbox::find_by_name(&pool, &user_id, &"Quarantine".to_string()).await? {
                    target_mbox = qm;
                } else {
                    let new_mb = crate::storage::models::mailbox::state::Mailbox {
                        id: 0,
                        account_id: user_id,
                        name: "Quarantine".to_string(),
                        flags: "".to_string(),
                        quota: None,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        uidvalidity: None,
                    };
                    target_mbox = mailbox::create_mailbox(&pool, &new_mb).await?;
                }
            }
        }

        // Upload to S3 and insert object key
        let key = format!("{}/{}-{}.eml", target_mbox.id, chrono::Utc::now().timestamp(), crate::utils::uuid7());
        let obj = object::add_object_bytes(&runtime, &key, content.as_bytes()).await?;

        // Minimal header extraction
        let mut from = String::new();
        let mut subject = String::new();
        for line in content.lines().take(64) {
            if from.is_empty() && line.to_ascii_lowercase().starts_with("from:") {
                from = line[5..].trim().to_string();
            }
            if subject.is_empty() && line.to_ascii_lowercase().starts_with("subject:") {
                subject = line[8..].trim().to_string();
            }
            if !from.is_empty() && !subject.is_empty() { break; }
        }

        let header_json = serde_json::json!({
            "from": from,
            "subject": subject,
            "date_time": date_time,
            "infected": infected_name,
        });

        let new_msg = message::Message {
            id: 0,
            mailbox_id: target_mbox.id,
            object_id: obj.id,
            sender: from.clone(),
            subject: subject.clone(),
            header: sqlx::types::Json(header_json),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            size: obj.size,
            uid: 0,
        };
        let created = message::create_message(&pool, &new_msg).await?;

        // Apply flags
        let mut final_flags = flags.clone();
        if infected_name.is_some() && av_mode.eq_ignore_ascii_case("tag") {
            final_flags.push("$Virus".to_string());
        }
        if !final_flags.is_empty() {
            let flags_str = final_flags.join(" ");
            let _ = message::update_flags(&pool, created.id, &flags_str).await;
        }

        // Emit EXISTS/RECENT if selected mailbox matches
        if let Some(sel_id) = selected_mailbox_id {
            if sel_id == target_mbox.id {
                let stats = mailbox::get_mailbox_stats(&pool, target_mbox.id).await?;
                writer.write_all(format!("* {} EXISTS\r\n", stats.total).as_bytes()).await?;
                writer.write_all(format!("* {} RECENT\r\n", stats.recent).as_bytes()).await?;
            }
        }

        // UIDPLUS APPENDUID
        let uidv = target_mbox.uidvalidity.unwrap_or(1);
        writer.write_all(format!("{} OK [APPENDUID {} {}] APPEND completed\r\n", tag, uidv, created.id).as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn scan_with_clamav(&self, bytes: &[u8]) -> Result<Option<String>> {
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let host = self.runtime.config.get_value("antivirus", "host").unwrap_or("localhost");
        let port = self.runtime.config.get_int("antivirus", "port", 3310);
        let addr = format!("{}:{}", host, port);
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                // INSTREAM protocol
                stream.write_all(b"INSTREAM\n").await?;
                let mut offset = 0usize;
                while offset < bytes.len() {
                    let chunk = &bytes[offset..bytes.len().min(offset + 8192)];
                    let len = (chunk.len() as u32).to_be_bytes();
                    stream.write_all(&len).await?;
                    stream.write_all(chunk).await?;
                    offset += chunk.len();
                }
                // zero-length chunk to terminate
                stream.write_all(&0u32.to_be_bytes()).await?;
                stream.flush().await?;

                // Read response
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]).to_string();
                // Example: "stream: OK" or "stream: Eicar-Test-Signature FOUND"
                if resp.contains("FOUND") {
                    // extract virus name
                    if let Some(colon) = resp.find(':') {
                        let s = resp[colon+1..].trim();
                        let name = s.trim_end_matches("FOUND").trim().to_string();
                        return Ok(Some(name));
                    }
                    return Ok(Some("UNKNOWN".to_string()));
                }
                Ok(None)
            }
            Err(_) => {
                // Treat as clean if AV server unavailable
                Ok(None)
            }
        }
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_subscribe(
        &self,
        tag: &str,
        mailbox: String,
        subscribe: bool,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        self.send_error(writer, tag, "OK", if subscribe {
            "SUBSCRIBE"
        } else {
            "UNSUBSCRIBE"
        }).await
    }

    async fn handle_starttls(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        // STARTTLS is not supported for on-the-fly upgrade in this handler yet
        // Only advertise when SSL is enabled to be RFC-friendly, but respond BAD here.
        self.send_error(writer, tag, "BAD", "STARTTLS not implemented").await
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_authenticate(
        &self,
        tag: &str,
        mechanism: String,
        initial_response: Option<String>,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        self.send_error(writer, tag, "NO", "AUTHENTICATE not supported").await
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    async fn handle_enable(
        &self,
        tag: &str,
        features: Vec<String>,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        self.send_error(writer, tag, "OK", "ENABLE completed (stub)").await
    }

    async fn handle_namespace(
        &self,
        tag: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        self.send_error(writer, tag, "OK", "NAMESPACE completed (stub)").await
    }
}
