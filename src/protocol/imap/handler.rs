// src/protocol/imap/handler.rs
use crate::runtime::Runtime;
use crate::storage::models::{ account, mailbox };
use crate::utils::generate_uidvalidity;

use account::state::AuthError::{ InvalidCredentials, Database, Crypto };
use super::state::{ ImapSession, ImapState, SelectedMailbox };
use super::command::{
    state::{ ImapCommand, UidCommand, SearchCriteria, SequenceSet, FetchItem, StoreOperation },
    parse_command,
};
use std::sync::Arc;
use chrono::{ Utc };
use tokio::io::{ AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter };
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

            let trimmed = line.trim_end_matches("\r\n");
            if trimmed.is_empty() {
                continue;
            }

            // Check for literal continuation
            let mut session = self.session.lock().await;
            if session.in_literal {
                self.handle_literal_continuation(&mut session, trimmed, &mut writer).await?;
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
                        // Store command for processing after literal
                        session.pending_commands.push(tag.clone());
                        session.pending_commands.push(format!("{:?}", command));
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

        let greeting =
            format!("* OK [CAPABILITY IMAP4rev1 STARTTLS] {} IMAP server ready\r\n", hostname);
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

        // Validate credentials
        let database = self.runtime.db
            .get()
            .ok_or_else(|| anyhow::anyhow!("No database connection"))?;
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

                // Send SELECT response
                let response = format!(
                    "* {} EXISTS\r\n* {} RECENT\r\n* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n* OK [UIDNEXT {}] Predicted next UID\r\n* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Limited\r\n{} OK [READ-{}] SELECT completed\r\n",
                    stats.total,
                    stats.recent,
                    stats.total + 1,
                    tag,
                    if read_only {
                        "ONLY"
                    } else {
                        "WRITE"
                    }
                );

                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;

                info!("Mailbox selected: {}", mailbox_name);
                Ok(())
            }
            Ok(None) => { self.send_error(writer, tag, "NO", "Mailbox does not exist").await }
            Err(e) => {
                error!("Database error: {}", e);
                self.send_error(writer, tag, "NO", "Temporary failure").await
            }
        }
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
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

        // Get messages in sequence set
        // TODO: Implement sequence set parsing and message retrieval
        // For now, just send a basic response

        let response = format!("{} OK FETCH completed\r\n", tag);
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;

        Ok(())
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
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

        // TODO: Implement search criteria parsing and database query
        // For now, return empty result

        let prefix = if is_uid { "* SEARCH" } else { "* SEARCH" };
        let response = format!("{} \r\n{} OK SEARCH completed\r\n", prefix, tag);

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

    async fn handle_literal_start(
        &self,
        session: &mut ImapSession,
        remaining: &str,
        writer: &mut BufWriter<impl AsyncWriteExt + Unpin>
    ) -> Result<()> {
        // Parse literal size: {123}
        if let Some(start) = remaining.find('{') {
            if let Some(end) = remaining[start..].find('}') {
                let size_str = &remaining[start + 1..start + end];
                if let Ok(size) = size_str.parse::<usize>() {
                    session.in_literal = true;
                    session.literal_remaining = size;
                    session.literal_buffer.clear();

                    // Send continuation request
                    if session.session_flags.literal_plus_supported {
                        // Literal+ allows sending without waiting for continuation
                        // But we still need to track it
                    } else {
                        writer.write_all(b"+ Ready for literal data\r\n").await?;
                        writer.flush().await?;
                    }
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!("Invalid literal syntax"))
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

        if line_len > session.literal_remaining {
            // Too much data
            session.in_literal = false;
            session.literal_remaining = 0;
            session.literal_buffer.clear();
            return Err(anyhow::anyhow!("Literal data exceeds declared size"));
        }

        session.literal_buffer.push_str(line);
        session.literal_remaining -= line_len;

        if session.literal_remaining == 0 {
            // Literal complete, process pending command
            session.in_literal = false;

            if let Some(cmd_str) = session.pending_commands.pop() {
                if let Some(tag) = session.pending_commands.pop() {
                    // Parse and process the command
                    // This is simplified - you'd need to reconstruct the full command
                    debug!("Literal data received: {} bytes", session.literal_buffer.len());

                    // For APPEND command, the literal contains the message
                    // For other commands, it might be search criteria, etc.
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
        // Implementation for STORE command
        self.send_error(writer, tag, "OK", "STORE completed (stub)").await
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
        self.send_error(writer, tag, "OK", "EXPUNGE completed (stub)").await
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
        self.send_error(writer, tag, "OK", if is_move { "MOVE" } else { "COPY" }).await
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
        self.send_error(writer, tag, "OK", "STATUS completed (stub)").await
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
        self.send_error(writer, tag, "OK", "APPEND completed (stub)").await
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
        self.send_error(writer, tag, "BAD", "STARTTLS not available").await
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
