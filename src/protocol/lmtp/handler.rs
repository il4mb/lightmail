use serde_json::{ json, Value };

use tokio::io::{ AsyncBufReadExt, AsyncWriteExt, BufReader };
use tracing::{ debug, error, info, warn, instrument };
use uuid::{ NoContext, Timestamp, Uuid };
use crate::{ runtime::Runtime, storage::models::{ account, message, mailbox, object } };
use anyhow::{ Context, Result };
use std::{ collections::HashMap, sync::Arc };
use sqlx::{ MySqlPool, types::Json };
use chrono::{ Utc };
use mail_parser::{ Addr, Message, MessageParser };

/// Handler for LMTP (Local Mail Transfer Protocol) connections.
///
/// LMTP is specified in RFC 2033 and is designed for final delivery to mailboxes
/// within the same system. Key characteristics:
/// - Runs over UNIX sockets (e.g., /var/run/lmtp.sock) for local delivery only
/// - Requires per-recipient responses after DATA command
/// - No queue management - messages delivered immediately or rejected
/// - Used by MTAs like Postfix for local mailbox delivery
///
/// Protocol flow for this handler:
/// 1. Client connects via UNIX socket (already authenticated by filesystem permissions)
/// 2. Send 220 greeting
/// 3. Process commands in loop: LHLO → MAIL FROM → RCPT TO → DATA → per-recipient responses
/// 4. Reset for next message or QUIT
///
/// Note: UNIX socket connections don't have a client address in the traditional sense.
/// The socket file permissions control access (e.g., Postfix running as postfix user).
#[instrument(skip_all, fields(client = "local"))]
pub async fn handle_client(
    socket: tokio::net::UnixStream,
    runtime: Arc<Runtime>
) -> anyhow::Result<()> {
    // LMTP runs on UNIX sockets - peer_addr() typically returns None
    // Filesystem permissions on the socket file provide access control
    // Protocol error counter - disconnect after too many errors
    let mut protocol_error_count = 0;
    const MAX_PROTOCOL_ERRORS: u8 = 5;

    // Get database pool and configuration
    let pool = runtime.db.get().context("Database pool not available")?.pool();
    let hostname = runtime.config.get_value("system", "hostname").unwrap_or("localhost");
    let max_message_size: usize = runtime.config
        .get_value("lmtp", "max_message_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50 * 1024 * 1024); // 50MB default

    // Split socket for concurrent reading/writing
    let (read_half, mut write_half) = socket.into_split();
    let mut reader = BufReader::new(read_half);

    info!("LMTP client connected");

    // === PHASE 1: CONNECTION GREETING ===
    // RFC 2033 Section 4.1: Send 220 greeting immediately
    write_half.write_all(format!("220 {} LMTP Service Ready\r\n", hostname).as_bytes()).await?;

    // Transaction state for current message delivery
    let mut transaction = LmtpTransaction::new(max_message_size);
    // Protocol state: GreetingSent → LhloReceived → MailFromReceived → DataReceived → Complete
    let mut protocol_state = LmtpProtocolState::GreetingSent;

    loop {
        // === PHASE 2: COMMAND READING ===
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            debug!("LMTP client disconnected");
            break;
        }

        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue; // Empty line, ignore
        }

        debug!("LMTP command: {}", trimmed);

        // Parse command (LMTP commands are case-insensitive)
        let command = match parse_lmtp_command(trimmed) {
            Ok(cmd) => cmd,
            Err(e) => {
                warn!("Failed to parse LMTP command: {}", e);
                protocol_error_count += 1;
                if protocol_error_count >= MAX_PROTOCOL_ERRORS {
                    write_half.write_all(b"421 4.7.0 Too many protocol errors\r\n").await?;
                    break;
                }
                write_half.write_all(b"500 5.5.2 Syntax error\r\n").await?;
                continue;
            }
        };

        // === PHASE 3: COMMAND PROCESSING ===
        match (&protocol_state, &command) {
            // Valid state transitions

            // After greeting, accept LHLO/HELO
            | (LmtpProtocolState::GreetingSent, LmtpCommand::Lhlo(domain))
            | (LmtpProtocolState::LhloReceived, LmtpCommand::Lhlo(domain)) => {
                info!("LMTP LHLO from: {}", domain);
                protocol_state = LmtpProtocolState::LhloReceived;
                send_lhlo_response(&mut write_half, &hostname).await?;
            }

            | (LmtpProtocolState::GreetingSent, LmtpCommand::Helo)
            | (LmtpProtocolState::LhloReceived, LmtpCommand::Helo) => {
                warn!("Client using deprecated HELO command");
                protocol_state = LmtpProtocolState::LhloReceived;
                write_half.write_all(format!("250 {}\r\n", hostname).as_bytes()).await?;
            }

            // After LHLO, start transaction with MAIL FROM
            (LmtpProtocolState::LhloReceived, LmtpCommand::MailFrom(sender)) => {
                // Validate sender format (empty sender allowed for bounces)
                if !sender.is_empty() && !is_valid_email(sender) {
                    write_half.write_all(b"501 5.1.7 Invalid sender address\r\n").await?;
                    continue;
                }

                transaction.start(sender.clone());
                protocol_state = LmtpProtocolState::MailFromReceived;
                write_half.write_all(b"250 2.1.0 Sender OK\r\n").await?;
            }

            // After MAIL FROM, accept recipients
            (LmtpProtocolState::MailFromReceived, LmtpCommand::RcptTo(recipient)) => {
                // Validate recipient format
                if !is_valid_email(recipient) {
                    write_half.write_all(b"501 5.1.3 Invalid recipient syntax\r\n").await?;
                    continue;
                }

                // Check if recipient exists in database
                match validate_recipient(pool, recipient).await {
                    Ok(Some((account_id, mailbox_id))) => {
                        transaction.add_recipient(recipient.clone(), account_id, mailbox_id);
                        write_half.write_all(b"250 2.1.5 Recipient OK\r\n").await?;
                    }
                    Ok(None) => {
                        // LMTP must reject unknown recipients immediately
                        write_half.write_all(b"550 5.1.1 User unknown\r\n").await?;
                    }
                    Err(e) => {
                        error!("Database error: {}", e);
                        write_half.write_all(b"451 4.3.0 Temporary lookup failure\r\n").await?;
                    }
                }
            }

            // After at least one recipient, accept DATA
            (LmtpProtocolState::MailFromReceived, LmtpCommand::Data) => {
                if transaction.recipients.is_empty() {
                    write_half.write_all(b"503 5.5.1 Need RCPT command\r\n").await?;
                    continue;
                }

                protocol_state = LmtpProtocolState::DataReceived;
                write_half.write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n").await?;
            }

            // During DATA phase, collect message content
            (LmtpProtocolState::DataReceived, LmtpCommand::DataContent(content)) => {
                // Handle dot-stuffing: ".." at start means literal "."
                let processed = if content.starts_with("..") { &content[1..] } else { content };

                if let Err(_) = transaction.append_data(processed) {
                    // Message too large
                    write_half.write_all(
                        b"552 5.3.4 Message size exceeds fixed maximum\r\n"
                    ).await?;
                    transaction.reset();
                    protocol_state = LmtpProtocolState::LhloReceived;
                }
            }

            // End of DATA, deliver message
            (LmtpProtocolState::DataReceived, LmtpCommand::DataEnd) => {
                // === PHASE 4: MESSAGE DELIVERY ===
                // LMTP requires immediate delivery attempt

                let delivery_results = deliver_message_to_recipients(
                    pool,
                    &transaction,
                    &runtime
                ).await;

                // Send per-recipient responses (RFC 2033 Section 4.4)
                let mut all_success = true;
                for (recipient, result) in delivery_results {
                    match result {
                        DeliveryResult::Success(_) => {
                            write_half.write_all(
                                format!("250 2.0.0 OK for {}\r\n", recipient).as_bytes()
                            ).await?;
                        }
                        DeliveryResult::MailboxFull => {
                            write_half.write_all(
                                format!("452 4.2.2 Mailbox full for {}\r\n", recipient).as_bytes()
                            ).await?;
                            all_success = false;
                        }
                        DeliveryResult::DatabaseError(_) => {
                            write_half.write_all(
                                format!("451 4.3.0 Temporary failure for {}\r\n", recipient).as_bytes()
                            ).await?;
                            all_success = false;
                        }
                        DeliveryResult::StorageError(_) => {
                            write_half.write_all(
                                format!("451 4.3.0 Storage failure for {}\r\n", recipient).as_bytes()
                            ).await?;
                            all_success = false;
                        }
                        DeliveryResult::ParseError => {
                            write_half.write_all(
                                format!("451 4.3.0 Parse error for {}\r\n", recipient).as_bytes()
                            ).await?;
                            all_success = false;
                        }
                    }
                }

                if all_success {
                    info!(
                        "Message delivered: {} -> {} recipients ({} bytes)",
                        transaction.sender,
                        transaction.recipients.len(),
                        transaction.data.len()
                    );
                }

                // Reset for next transaction
                transaction.reset();
                protocol_state = LmtpProtocolState::LhloReceived;
            }

            // Protocol reset
            (_, LmtpCommand::Rset) => {
                transaction.reset();
                protocol_state = LmtpProtocolState::LhloReceived;
                write_half.write_all(b"250 2.0.0 Reset OK\r\n").await?;
            }

            // No operation
            (_, LmtpCommand::Noop) => {
                write_half.write_all(b"250 2.0.0 OK\r\n").await?;
            }

            // Verify (not really supported in LMTP)
            (_, LmtpCommand::Vrfy(_)) => {
                write_half.write_all(b"252 2.1.5 Cannot VRFY user\r\n").await?;
            }

            // Graceful termination
            (_, LmtpCommand::Quit) => {
                info!("LMTP client requested QUIT");
                write_half.write_all(b"221 2.0.0 Bye\r\n").await?;
                break;
            }

            // Invalid state - wrong command for current state
            _ => {
                warn!("Invalid command for current protocol state");
                write_half.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                protocol_error_count += 1;
                if protocol_error_count >= MAX_PROTOCOL_ERRORS {
                    write_half.write_all(b"421 4.7.0 Too many protocol errors\r\n").await?;
                    break;
                }
            }
        }
    }

    info!("LMTP session completed");
    Ok(())
}

// ==================== HELPER FUNCTIONS ====================

/// Send LHLO response with supported LMTP extensions
async fn send_lhlo_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    hostname: &str
) -> Result<()> {
    // RFC 2033 Section 4.2: List supported extensions
    writer.write_all(format!("250-{}\r\n", hostname).as_bytes()).await?;
    writer.write_all(b"250-8BITMIME\r\n").await?;
    writer.write_all(b"250-PIPELINING\r\n").await?;
    writer.write_all(b"250 SIZE 52428800\r\n").await?; // 50MB
    Ok(())
}

/// Validate recipient exists and return (account_id, mailbox_id)
async fn validate_recipient(pool: &MySqlPool, recipient_email: &str) -> Result<Option<(i64, i64)>> {
    // Find account by email
    match account::find_account(pool, recipient_email).await? {
        Some(account) => {
            let uid = account.id;
            // Get user's INBOX
            match mailbox::find_by_name(pool, &uid, "INBOX").await? {
                Some(mailbox) => Ok(Some((uid, mailbox.id))),
                None => {
                    error!("Account {} has no INBOX", account.id);
                    Ok(None)
                }
            }
        }
        None => Ok(None),
    }
}

/// Deliver message to all recipients, return per-recipient results
async fn deliver_message_to_recipients(
    pool: &MySqlPool,
    transaction: &LmtpTransaction,
    runtime: &Arc<Runtime>
) -> Vec<(String, DeliveryResult)> {
    let mut results = Vec::new();

    let parser = MessageParser::default();
    let parsed_message = match parser.parse(transaction.data.as_bytes()) {
        Some(msg) => msg,
        None => {
            error!("Failed to parse email message");
            // Return failure for all recipients
            for recipient in &transaction.recipients {
                results.push((recipient.email.clone(), DeliveryResult::ParseError));
            }
            return results;
        }
    };

    let senders = get_sender_string(&parsed_message);
    let subject = parsed_message.subject();
    let header_json = headers_to_json(&parsed_message);

    let ts = Timestamp::from_unix(NoContext, 1497624119, 1234);
    let object_key = &Uuid::new_v7(ts).to_string();

    let rf = runtime.as_ref();
    let data = &transaction.data.clone();
    let object = match object::add_object(rf, &object_key, data).await {
        Ok(obj) => obj,
        Err(e) => {
            error!("Failed to store message object: {}", e);
            for r in &transaction.recipients {
                results.push((
                    r.email.clone(),
                    DeliveryResult::StorageError("Failed to store message object".to_string()),
                ));
            }
            return results;
        }
    };

    for recipient in &transaction.recipients {
        // Check mailbox quota
        match mailbox::check_quota(pool, recipient.mailbox_id).await {
            Ok(false) => {
                results.push((recipient.email.clone(), DeliveryResult::MailboxFull));
                continue;
            }
            Err(e) => {
                error!("Quota check failed: {}", e);
                results.push((
                    recipient.email.clone(),
                    DeliveryResult::DatabaseError(e.to_string()),
                ));
                continue;
            }
            _ => {} // Quota OK
        }

        let header = header_json.clone();
        // Create message
        let message = message::Message {
            id: 0, // auto-increment
            mailbox_id: recipient.mailbox_id,
            object_id: object.id, //
            sender: senders.clone(),
            subject: subject.unwrap_or("").to_string(),
            header: Json(header),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        match message::create_message(pool, &message).await {
            Ok(_) => {
                results.push((recipient.email.clone(), DeliveryResult::Success(message.id)));
            }
            Err(e) => {
                error!("Failed to create message: {}", e);
                results.push((
                    recipient.email.clone(),
                    DeliveryResult::DatabaseError(e.to_string()),
                ));
            }
        }
    }

    results
}

fn headers_to_json(msg: &mail_parser::Message) -> serde_json::Value {
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();

    for header in msg.headers().iter() {
        let name = header.name().to_string();

        let value = header.value().as_text().unwrap_or("").to_string();

        headers.entry(name).or_default().push(value);
    }

    json!(headers)
}

fn addr_to_string(addr: &Addr) -> String {
    match (addr.name(), addr.address()) {
        (Some(name), Some(email)) => format!("{} <{}>", name, email),
        (None, Some(email)) => email.to_string(),
        (Some(name), None) => name.to_string(), // rare but valid
        (None, None) => String::new(),
    }
}

fn get_sender_string(msg: &Message) -> String {
    msg.from()
        .map(|from| { from.iter().map(addr_to_string).collect::<Vec<_>>().join(", ") })
        .unwrap_or_default()
}

/// Parse LMTP command line
fn parse_lmtp_command(line: &str) -> Result<LmtpCommand> {
    let line_upper = line.to_uppercase();

    if line_upper.starts_with("LHLO ") {
        Ok(LmtpCommand::Lhlo(line[5..].trim().to_string()))
    } else if line_upper == "HELO" {
        Ok(LmtpCommand::Helo)
    } else if line_upper.starts_with("MAIL FROM:") {
        let sender = extract_email_address(&line[10..])?;
        Ok(LmtpCommand::MailFrom(sender))
    } else if line_upper.starts_with("RCPT TO:") {
        let recipient = extract_email_address(&line[8..])?;
        Ok(LmtpCommand::RcptTo(recipient))
    } else if line_upper == "DATA" {
        Ok(LmtpCommand::Data)
    } else if line_upper == "RSET" {
        Ok(LmtpCommand::Rset)
    } else if line_upper == "NOOP" {
        Ok(LmtpCommand::Noop)
    } else if line_upper.starts_with("VRFY ") {
        Ok(LmtpCommand::Vrfy(line[5..].trim().to_string()))
    } else if line_upper == "QUIT" {
        Ok(LmtpCommand::Quit)
    } else if line == "." {
        Ok(LmtpCommand::DataEnd)
    } else {
        // During DATA phase, treat as message content
        Ok(LmtpCommand::DataContent(line.to_string()))
    }
}

/// Extract email from SMTP parameter (supports <email@domain> format)
fn extract_email_address(param: &str) -> Result<String> {
    let param = param.trim();

    if param.starts_with('<') && param.ends_with('>') {
        Ok(param[1..param.len() - 1].trim().to_string())
    } else {
        Ok(param.to_string())
    }
}

/// Basic email validation
fn is_valid_email(email: &str) -> bool {
    if email.is_empty() {
        return true; // Empty sender allowed for bounces
    }

    let parts: Vec<&str> = email.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() && parts[1].contains('.')
}

// ==================== LMTP PROTOCOL TYPES ====================

/// Protocol state machine
#[derive(Debug, Clone, Copy, PartialEq)]
enum LmtpProtocolState {
    GreetingSent, // After 220 greeting
    LhloReceived, // After successful LHLO
    MailFromReceived, // After MAIL FROM
    DataReceived, // After DATA command (collecting message)
}

/// LMTP command types
#[derive(Debug)]
enum LmtpCommand {
    Lhlo(String), // LHLO domain
    Helo, // HELO (deprecated)
    MailFrom(String), // MAIL FROM:<sender>
    RcptTo(String), // RCPT TO:<recipient>
    Data, // DATA
    DataContent(String), // Message content line
    DataEnd, // "." ending DATA
    Rset, // RSET
    Noop, // NOOP
    Vrfy(String), // VRFY address
    Quit, // QUIT
}

/// Transaction state for current message
#[derive(Debug)]
struct LmtpTransaction {
    sender: String,
    recipients: Vec<RecipientInfo>,
    data: String,
    max_message_size: usize,
}

impl LmtpTransaction {
    fn new(max_message_size: usize) -> Self {
        Self {
            sender: String::new(),
            recipients: Vec::new(),
            data: String::new(),
            max_message_size,
        }
    }

    fn start(&mut self, sender: String) {
        self.sender = sender;
        self.recipients.clear();
        self.data.clear();
    }

    fn add_recipient(&mut self, email: String, account_id: i64, mailbox_id: i64) {
        self.recipients.push(RecipientInfo {
            email,
            account_id,
            mailbox_id,
        });
    }

    fn append_data(&mut self, content: &str) -> Result<()> {
        // Check size limit
        if self.data.len() + content.len() > self.max_message_size {
            return Err(anyhow::anyhow!("Message size limit exceeded"));
        }

        self.data.push_str(content);
        self.data.push_str("\r\n");
        Ok(())
    }

    fn reset(&mut self) {
        self.start(String::new());
    }
}

/// Recipient information
#[derive(Debug)]
struct RecipientInfo {
    email: String,
    account_id: i64,
    mailbox_id: i64,
}

/// Delivery result for each recipient
#[derive(Debug)]
enum DeliveryResult {
    Success(i64), // message_id
    MailboxFull,
    DatabaseError(String),
    StorageError(String),
    ParseError,
}
