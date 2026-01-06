use std::{net::SocketAddr, path::PathBuf, sync::Arc, task::{Context, Poll}};

use anyhow::{anyhow, Result};
use chrono::Utc;
use mail_parser::{Message, MessageParser};
use serde_json::json;
use sqlx::{MySqlPool, types::Json};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_rustls::{
    rustls::{self, pki_types::{CertificateDer, PrivateKeyDer}},
    TlsAcceptor,
};
use tracing::{error, info, warn};

use crate::{
    runtime::Runtime,
    storage::models::{account, mailbox, message, object},
    utils::uuid7,
};

/// Inbound SMTP/Submission server.
///
/// Implements core RFC 5321 flow (EHLO/HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT)
/// and advertises/implements these ESMTP extensions:
/// - PIPELINING
/// - SIZE
/// - STARTTLS (upgrade)
/// - AUTH (PLAIN, LOGIN)
///
/// This server delivers locally (stores message blob to object storage and metadata to DB).
/// It does not implement queueing/retry for remote delivery.
pub async fn run_smtp_server(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    // Ensure rustls has an active crypto provider (required by rustls 0.23+).
    // Ignore errors if already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = &runtime.config;

    if !cfg.is_section_exists("smtp_server") {
        return Ok(());
    }

    let bind = cfg.get_value("smtp_server", "bind").unwrap_or("0.0.0.0").to_string();
    let port: u16 = cfg.get_value("smtp_server", "port").unwrap_or("25").parse().unwrap_or(25);
    let submission_port: u16 = cfg
        .get_value("smtp_server", "submission_port")
        .unwrap_or("587")
        .parse()
        .unwrap_or(587);
    let smtps_port: u16 = cfg
        .get_value("smtp_server", "smtps_port")
        .unwrap_or("465")
        .parse()
        .unwrap_or(465);

    let max_connections: usize = cfg
        .get_value("smtp_server", "max_connections")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let enable_ssl = cfg.get_bool("smtp_server", "enable_ssl", false);
    let enable_starttls = cfg.get_bool("smtp_server", "enable_starttls", true);

    let max_message_size: usize = cfg
        .get_value("smtp_server", "max_message_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50 * 1024 * 1024);

    let require_auth_submission = cfg.get_bool("smtp_server", "require_auth_submission", true);
    let require_auth_smtp = cfg.get_bool("smtp_server", "require_auth_smtp", false);
    let auth_require_tls = cfg.get_bool("smtp_server", "auth_require_tls", false);
    let enable_auth = cfg.get_bool("smtp_server", "enable_auth", true);

    if !enable_auth && (require_auth_submission || require_auth_smtp) {
        return Err(anyhow!(
            "smtp_server.enable_auth=false is incompatible with require_auth_* (AUTH is disabled)"
        ));
    }

    let tls_acceptor = if enable_ssl {
        let cert_path = cfg
            .get_value("smtp_server", "tls_cert")
            .ok_or_else(|| anyhow!("smtp_server.tls_cert missing"))?;
        let key_path = cfg
            .get_value("smtp_server", "tls_key")
            .ok_or_else(|| anyhow!("smtp_server.tls_key missing"))?;
        Some(create_tls_acceptor(cert_path, key_path)?)
    } else {
        None
    };

    let semaphore = Arc::new(Semaphore::new(max_connections));

    // Port 25 listener (server-to-server)
    {
        let addr = format!("{}:{}", bind, port);
        let listener = TcpListener::bind(&addr).await?;
        info!("SMTP listening on {}", addr);

        let runtime = runtime.clone();
        let semaphore = semaphore.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            accept_loop(
                listener,
                runtime,
                semaphore,
                ListenerKind::PlainSmtp {
                    enable_starttls,
                    enable_ssl: tls_acceptor.is_some(),
                    require_auth: require_auth_smtp,
                    enable_auth,
                    auth_require_tls,
                    max_message_size,
                },
                tls_acceptor,
            )
            .await;
        });
    }

    // Submission (587) listener
    if submission_port != 0 {
        let addr = format!("{}:{}", bind, submission_port);
        let listener = TcpListener::bind(&addr).await?;
        info!("SMTP Submission listening on {}", addr);

        let runtime = runtime.clone();
        let semaphore = semaphore.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            accept_loop(
                listener,
                runtime,
                semaphore,
                ListenerKind::Submission {
                    enable_starttls: enable_starttls && tls_acceptor.is_some(),
                    enable_ssl: tls_acceptor.is_some(),
                    require_auth: require_auth_submission,
                    enable_auth,
                    auth_require_tls,
                    max_message_size,
                },
                tls_acceptor,
            )
            .await;
        });
    }

    // SMTPS (465) listener
    if smtps_port != 0 {
        if let Some(acceptor) = tls_acceptor.clone() {
            let addr = format!("{}:{}", bind, smtps_port);
            let listener = TcpListener::bind(&addr).await?;
            info!("SMTPS (implicit TLS) listening on {}", addr);

            let runtime = runtime.clone();
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                accept_loop(
                    listener,
                    runtime,
                    semaphore,
                    ListenerKind::Smtps {
                        require_auth: require_auth_submission,
                        enable_auth,
                        auth_require_tls: false,
                        max_message_size,
                    },
                    Some(acceptor),
                )
                .await;
            });
        } else {
            warn!("smtp_server.smtps_port set but enable_ssl=false; SMTPS listener disabled");
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum ListenerKind {
    PlainSmtp {
        enable_starttls: bool,
        enable_ssl: bool,
        require_auth: bool,
        enable_auth: bool,
        auth_require_tls: bool,
        max_message_size: usize,
    },
    Submission {
        enable_starttls: bool,
        enable_ssl: bool,
        require_auth: bool,
        enable_auth: bool,
        auth_require_tls: bool,
        max_message_size: usize,
    },
    Smtps {
        require_auth: bool,
        enable_auth: bool,
        auth_require_tls: bool,
        max_message_size: usize,
    },
}

async fn accept_loop(
    listener: TcpListener,
    runtime: Arc<Runtime>,
    semaphore: Arc<Semaphore>,
    kind: ListenerKind,
    tls_acceptor: Option<TlsAcceptor>,
) {
    loop {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };

        match listener.accept().await {
            Ok((stream, peer)) => {
                let runtime = runtime.clone();
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(stream, peer, runtime, kind, tls_acceptor).await {
                        warn!("SMTP session ended with error: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("SMTP accept failed: {}", e);
            }
        }
    }
}

#[derive(Debug)]
struct RecipientInfo {
    mailbox_id: i64,
}

#[derive(Debug)]
struct Transaction {
    mail_from: Option<String>,
    recipients: Vec<RecipientInfo>,
    data_file: Option<PathBuf>,
    size: usize,
    max_message_size: usize,
    declared_size: Option<usize>,
}

impl Transaction {
    fn new(max_message_size: usize) -> Self {
        Self {
            mail_from: None,
            recipients: Vec::new(),
            data_file: None,
            size: 0,
            max_message_size,
            declared_size: None,
        }
    }

    async fn reset(&mut self) {
        if let Some(path) = &self.data_file {
            let _ = tokio::fs::remove_file(path).await;
        }
        self.mail_from = None;
        self.recipients.clear();
        self.data_file = None;
        self.size = 0;
        self.declared_size = None;
    }

    async fn append_data_line(&mut self, line: &str) -> Result<()> {
        if self.data_file.is_none() {
            self.data_file = Some(PathBuf::from(format!("/tmp/lightmail-smtp-{}.eml", uuid7())));
        }

        // includes CRLF that we add
        let additional = line.as_bytes().len() + 2;
        if self.size + additional > self.max_message_size {
            return Err(anyhow!("message size limit exceeded"));
        }

        let path = self.data_file.as_ref().unwrap();
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\r\n").await?;
        self.size += additional;
        Ok(())
    }
}

#[derive(Debug)]
struct Session {
    helo_name: Option<String>,
    authenticated: bool,
    auth_user: Option<String>,
    tls_active: bool,
    data_mode: bool,
    transaction: Transaction,
}

impl Session {
    fn new(max_message_size: usize, tls_active: bool) -> Self {
        Self {
            helo_name: None,
            authenticated: false,
            auth_user: None,
            tls_active,
            data_mode: false,
            transaction: Transaction::new(max_message_size),
        }
    }
}

enum AnyStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl Unpin for AnyStream {}

impl AsyncRead for AnyStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            AnyStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            AnyStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AnyStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            AnyStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, data),
            AnyStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, data),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            AnyStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            AnyStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            AnyStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            AnyStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    kind: ListenerKind,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<()> {
    let hostname = runtime.config.get_value("system", "hostname").unwrap_or("localhost");

    let (implicit_tls, enable_starttls, enable_ssl, require_auth, enable_auth, auth_require_tls, max_message_size) = match kind {
        ListenerKind::PlainSmtp {
            enable_starttls,
            enable_ssl,
            require_auth,
            enable_auth,
            auth_require_tls,
            max_message_size,
        } => (false, enable_starttls, enable_ssl, require_auth, enable_auth, auth_require_tls, max_message_size),
        ListenerKind::Submission {
            enable_starttls,
            enable_ssl,
            require_auth,
            enable_auth,
            auth_require_tls,
            max_message_size,
        } => (false, enable_starttls, enable_ssl, require_auth, enable_auth, auth_require_tls, max_message_size),
        ListenerKind::Smtps {
            require_auth,
            enable_auth,
            auth_require_tls,
            max_message_size,
        } => (true, false, true, require_auth, enable_auth, auth_require_tls, max_message_size),
    };

    let stream = if implicit_tls {
        let acceptor = tls_acceptor.clone().ok_or_else(|| anyhow!("TLS acceptor missing"))?;
        let tls = acceptor.accept(stream).await?;
        AnyStream::Tls(tls)
    } else {
        AnyStream::Plain(stream)
    };

    let mut session = Session::new(max_message_size, implicit_tls);

    // Split into buffered halves
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    // Greeting
    write_line(&mut writer, format!("220 {} ESMTP LightMail", hostname)).await?;

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }

        if session.data_mode {
            if trimmed == "." {
                session.data_mode = false;

                let resp = finish_data(&runtime, &mut session).await;
                match resp {
                    Ok(()) => write_line(&mut writer, "250 2.0.0 OK".to_string()).await?,
                    Err(e) => {
                        warn!("SMTP delivery failed: {}", e);
                        write_line(&mut writer, "451 4.3.0 Temporary failure".to_string()).await?;
                    }
                }

                session.transaction.reset().await;
                continue;
            }

            // Dot unstuffing
            let processed = if let Some(rest) = trimmed.strip_prefix("..") { rest } else { trimmed };

            if let Err(_) = session.transaction.append_data_line(processed).await {
                // size exceeded; abort transaction
                session.data_mode = false;
                write_line(&mut writer, "552 5.3.4 Message size exceeds fixed maximum".to_string()).await?;
                session.transaction.reset().await;
            }
            continue;
        }

        // Command handling
        let upper = trimmed.to_ascii_uppercase();

        if upper.starts_with("EHLO ") {
            session.helo_name = Some(trimmed[5..].trim().to_string());
            write_line(&mut writer, format!("250-{}", hostname)).await?;
            write_line(&mut writer, "250-PIPELINING".to_string()).await?;
            write_line(&mut writer, format!("250-SIZE {}", max_message_size)).await?;

            if enable_ssl && enable_starttls && !session.tls_active {
                write_line(&mut writer, "250-STARTTLS".to_string()).await?;
            }

            if enable_auth {
                write_line(&mut writer, "250-AUTH PLAIN LOGIN".to_string()).await?;
            }
            write_line(&mut writer, "250 OK".to_string()).await?;
            continue;
        }

        if upper.starts_with("HELO ") {
            session.helo_name = Some(trimmed[5..].trim().to_string());
            write_line(&mut writer, format!("250 {}", hostname)).await?;
            continue;
        }

        if upper == "NOOP" {
            write_line(&mut writer, "250 2.0.0 OK".to_string()).await?;
            continue;
        }

        if upper == "RSET" {
            session.transaction.reset().await;
            session.data_mode = false;
            write_line(&mut writer, "250 2.0.0 OK".to_string()).await?;
            continue;
        }

        if upper == "QUIT" {
            write_line(&mut writer, "221 2.0.0 Bye".to_string()).await?;
            break;
        }

        if upper.starts_with("VRFY ") {
            write_line(&mut writer, "252 2.1.5 Cannot VRFY user".to_string()).await?;
            continue;
        }

        if upper == "STARTTLS" {
            if session.tls_active {
                write_line(&mut writer, "454 4.7.0 TLS not available".to_string()).await?;
                continue;
            }
            if !(enable_ssl && enable_starttls) {
                write_line(&mut writer, "454 4.7.0 TLS not available".to_string()).await?;
                continue;
            }

            // STARTTLS upgrade
            let acceptor = tls_acceptor.clone().ok_or_else(|| anyhow!("TLS acceptor missing"))?;
            write_line(&mut writer, "220 2.0.0 Ready to start TLS".to_string()).await?;
            writer.flush().await?;

            // Reconstruct AnyStream from halves
            let stream = reader.into_inner().unsplit(writer.into_inner());

            let tcp = match stream {
                AnyStream::Plain(tcp) => tcp,
                AnyStream::Tls(_) => return Err(anyhow!("unexpected TLS stream before STARTTLS")),
            };

            // Reject pipelining after STARTTLS if buffered bytes exist (best-effort)
            // (A compliant client should not send further commands until TLS is active.)

            let tls_stream = acceptor.accept(tcp).await?;
            let new_stream = AnyStream::Tls(tls_stream);
            session.tls_active = true;

            let (r, w) = tokio::io::split(new_stream);
            reader = BufReader::new(r);
            writer = BufWriter::new(w);

            continue;
        }

        if upper.starts_with("AUTH ") {
            if !enable_auth {
                write_line(&mut writer, "502 5.5.1 AUTH not available".to_string()).await?;
                continue;
            }
            if auth_require_tls && !session.tls_active {
                write_line(&mut writer, "538 5.7.11 Encryption required for requested authentication mechanism".to_string()).await?;
                continue;
            }

            match handle_auth(&runtime, &mut reader, &mut writer, trimmed).await {
                Ok(user) => {
                    session.authenticated = true;
                    session.auth_user = Some(user);
                    write_line(&mut writer, "235 2.7.0 Authentication successful".to_string()).await?;
                }
                Err(e) => {
                    warn!("SMTP auth failed from {}: {}", peer, e);
                    write_line(&mut writer, "535 5.7.8 Authentication credentials invalid".to_string()).await?;
                }
            }
            continue;
        }

        if upper.starts_with("MAIL FROM:") {
            if require_auth && !session.authenticated {
                write_line(&mut writer, "530 5.7.0 Authentication required".to_string()).await?;
                continue;
            }
            if session.helo_name.is_none() {
                write_line(&mut writer, "503 5.5.1 Send EHLO/HELO first".to_string()).await?;
                continue;
            }

            let (sender, declared_size) = parse_mail_from(trimmed)?;

            if let Some(sz) = declared_size {
                if sz > max_message_size {
                    write_line(&mut writer, "552 5.3.4 Message size exceeds fixed maximum".to_string()).await?;
                    continue;
                }
            }

            session.transaction.reset().await;
            session.transaction.mail_from = Some(sender);
            session.transaction.declared_size = declared_size;

            write_line(&mut writer, "250 2.1.0 Sender OK".to_string()).await?;
            continue;
        }

        if upper.starts_with("RCPT TO:") {
            if session.transaction.mail_from.is_none() {
                write_line(&mut writer, "503 5.5.1 Need MAIL command".to_string()).await?;
                continue;
            }

            let rcpt = extract_email_address(&trimmed[8..])?;
            if !is_valid_email(&rcpt) {
                write_line(&mut writer, "501 5.1.3 Invalid recipient syntax".to_string()).await?;
                continue;
            }

            let pool = match runtime.db.get() {
                Some(db) => db.pool(),
                None => {
                    write_line(&mut writer, "451 4.3.0 Temporary lookup failure".to_string()).await?;
                    continue;
                }
            };

            match validate_recipient(&pool, &rcpt).await {
                Ok(Some((_account_id, mailbox_id))) => {
                    session.transaction.recipients.push(RecipientInfo { mailbox_id });
                    write_line(&mut writer, "250 2.1.5 Recipient OK".to_string()).await?;
                }
                Ok(None) => {
                    write_line(&mut writer, "550 5.1.1 User unknown".to_string()).await?;
                }
                Err(e) => {
                    error!("Recipient lookup failed: {}", e);
                    write_line(&mut writer, "451 4.3.0 Temporary lookup failure".to_string()).await?;
                }
            }
            continue;
        }

        if upper == "DATA" {
            if session.transaction.mail_from.is_none() {
                write_line(&mut writer, "503 5.5.1 Need MAIL command".to_string()).await?;
                continue;
            }
            if session.transaction.recipients.is_empty() {
                write_line(&mut writer, "503 5.5.1 Need RCPT command".to_string()).await?;
                continue;
            }

            write_line(&mut writer, "354 End data with <CRLF>.<CRLF>".to_string()).await?;
            session.data_mode = true;
            continue;
        }

        write_line(&mut writer, "500 5.5.2 Syntax error, command unrecognized".to_string()).await?;
    }

    session.transaction.reset().await;
    Ok(())
}

async fn handle_auth(
    runtime: &Arc<Runtime>,
    reader: &mut BufReader<tokio::io::ReadHalf<AnyStream>>,
    writer: &mut BufWriter<tokio::io::WriteHalf<AnyStream>>,
    line: &str,
) -> Result<String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    // AUTH <mechanism> [initial-response]
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("AUTH missing mechanism"));
    }

    let mech = parts[1].to_ascii_uppercase();

    match mech.as_str() {
        "PLAIN" => {
            let b64 = if parts.len() >= 3 {
                parts[2].to_string()
            } else {
                write_line(writer, "334 ".to_string()).await?;
                let mut resp = String::new();
                reader.read_line(&mut resp).await?;
                resp.trim_end_matches(['\r', '\n']).to_string()
            };

            let decoded = B64.decode(b64.as_bytes())?;
            let decoded = String::from_utf8_lossy(&decoded);
            // format: \0user\0pass (or authzid\0user\0pass)
            let fields: Vec<&str> = decoded.split('\u{0}').collect();
            let (user, pass) = if fields.len() >= 3 {
                (fields[1], fields[2])
            } else {
                return Err(anyhow!("AUTH PLAIN invalid payload"));
            };

            authenticate_user(runtime, user, pass).await?;
            Ok(user.to_string())
        }
        "LOGIN" => {
            // AUTH LOGIN [initial-response]
            // If initial-response is present it is usually username.
            let username = if parts.len() >= 3 {
                let u = B64.decode(parts[2].as_bytes())?;
                String::from_utf8_lossy(&u).to_string()
            } else {
                write_line(writer, "334 VXNlcm5hbWU6".to_string()).await?; // "Username:"
                let mut resp = String::new();
                reader.read_line(&mut resp).await?;
                let resp = resp.trim_end_matches(['\r', '\n']);
                let u = B64.decode(resp.as_bytes())?;
                String::from_utf8_lossy(&u).to_string()
            };

            write_line(writer, "334 UGFzc3dvcmQ6".to_string()).await?; // "Password:"
            let mut resp = String::new();
            reader.read_line(&mut resp).await?;
            let resp = resp.trim_end_matches(['\r', '\n']);
            let p = B64.decode(resp.as_bytes())?;
            let password = String::from_utf8_lossy(&p).to_string();

            authenticate_user(runtime, &username, &password).await?;
            Ok(username)
        }
        _ => Err(anyhow!("unsupported AUTH mechanism")),
    }
}

async fn authenticate_user(runtime: &Arc<Runtime>, username: &str, password: &str) -> Result<i64> {
    let db = runtime.db.get().ok_or_else(|| anyhow!("DB not initialized"))?;
    match account::authenticate(db.pool(), username, password).await {
        Ok(id) => Ok(id),
        Err(_) => Err(anyhow!("invalid credentials")),
    }
}

fn parse_mail_from(line: &str) -> Result<(String, Option<usize>)> {
    // MAIL FROM:<addr> [SIZE=n]
    let after = line
        .get(10..)
        .ok_or_else(|| anyhow!("MAIL FROM missing"))?
        .trim();

    let mut parts = after.split_whitespace();
    let addr_part = parts.next().unwrap_or("");
    let sender = extract_email_address(addr_part)?;

    let mut declared_size: Option<usize> = None;
    for p in parts {
        let up = p.to_ascii_uppercase();
        if let Some(sz) = up.strip_prefix("SIZE=") {
            if let Ok(n) = sz.parse::<usize>() {
                declared_size = Some(n);
            }
        }
    }

    Ok((sender, declared_size))
}

fn extract_email_address(param: &str) -> Result<String> {
    let param = param.trim();
    if param.starts_with('<') && param.ends_with('>') {
        Ok(param[1..param.len() - 1].trim().to_string())
    } else {
        Ok(param.to_string())
    }
}

fn is_valid_email(email: &str) -> bool {
    if email.is_empty() {
        return true;
    }
    let parts: Vec<&str> = email.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() && parts[1].contains('.')
}

async fn validate_recipient(pool: &MySqlPool, recipient_email: &str) -> Result<Option<(i64, i64)>> {
    match account::find_account(pool, recipient_email).await? {
        Some(account) => {
            let uid = account.id;
            match mailbox::find_by_name(pool, &uid, "INBOX").await? {
                Some(mb) => Ok(Some((uid, mb.id))),
                None => Ok(None),
            }
        }
        None => Ok(None),
    }
}

async fn finish_data(runtime: &Arc<Runtime>, session: &mut Session) -> Result<()> {
    let data_path = session
        .transaction
        .data_file
        .as_ref()
        .ok_or_else(|| anyhow!("no message data"))?
        .clone();

    let data_bytes = tokio::fs::read(&data_path).await?;

    let pool = runtime.db.get().ok_or_else(|| anyhow!("DB not initialized"))?.pool();

    // Antivirus scan + delivery to each recipient mailbox
    deliver_message_to_recipients(&pool, runtime, &session.transaction.recipients, &data_bytes, &data_path).await?;
    Ok(())
}

async fn deliver_message_to_recipients(
    pool: &MySqlPool,
    runtime: &Arc<Runtime>,
    recipients: &[RecipientInfo],
    data_bytes: &[u8],
    data_path: &std::path::Path,
) -> Result<()> {
    // Antivirus scan (reuse LMTP behavior; reject/quarantine/tag)
    let mut virus_detected = false;
    let mut virus_response = String::new();
    let antivirus_mode = runtime
        .config
        .get_value("antivirus", "mode")
        .unwrap_or("reject")
        .to_lowercase();
    let clamav_enabled = runtime.config.get_bool("antivirus", "enabled", false);

    if clamav_enabled {
        use clamav_client::{clean};
        use clamav_client::tokio::{scan_stream, Tcp as ClamTcp};
        use tokio_util::io::ReaderStream;

        let clamav_host = runtime
            .config
            .get_value("antivirus", "host")
            .unwrap_or("localhost")
            .to_string();
        let clamav_port = runtime.config.get_int("antivirus", "port", 3310);
        let clamd_addr = format!("{}:{}", clamav_host, clamav_port);

        let scan_file = tokio::fs::File::open(data_path).await?;
        let stream = ReaderStream::new(scan_file);
        let response = scan_stream(stream, ClamTcp { host_address: clamd_addr }, None).await?;

        match clean(&response) {
            Ok(true) => {}
            Ok(false) => {
                virus_detected = true;
                virus_response = String::from_utf8_lossy(&response).to_string();
                if antivirus_mode == "reject" {
                    return Err(anyhow!("virus detected: {}", virus_response));
                }
            }
            Err(e) => return Err(anyhow!("clamav response parse failed: {}", e)),
        }
    }

    let parser = MessageParser::default();
    let parsed_message = parser
        .parse(data_bytes)
        .ok_or_else(|| anyhow!("failed to parse email"))?;

    let sender = get_sender_string(&parsed_message);
    let subject = parsed_message.subject().map(|s| s.to_string()).unwrap_or_default();
    let header_json = headers_to_json(&parsed_message);

    let base_key = uuid7();
    let (subject, header_json, object_key) = apply_antivirus_policy(
        subject,
        header_json,
        base_key,
        virus_detected,
        &antivirus_mode,
        &virus_response,
    );

    let rf = runtime.as_ref();
    let obj = object::add_object_bytes(rf, &object_key, data_bytes).await?;

    for r in recipients {
        // quota check
        if !mailbox::check_quota(pool, r.mailbox_id).await? {
            return Err(anyhow!("mailbox full"));
        }

        let msg = message::Message {
            id: 0,
            mailbox_id: r.mailbox_id,
            object_id: obj.id,
            sender: sender.clone(),
            subject: subject.clone(),
            header: Json(header_json.clone()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            size: data_bytes.len() as i64,
            uid: 0,
        };

        let _ = message::create_message(pool, &msg).await?;
    }

    Ok(())
}

fn headers_to_json(msg: &mail_parser::Message) -> serde_json::Value {
    use std::collections::HashMap;
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();

    for header in msg.headers().iter() {
        let name = header.name().to_string();
        let value = header.value().as_text().unwrap_or("").to_string();
        headers.entry(name).or_default().push(value);
    }

    json!(headers)
}

fn get_sender_string(msg: &Message) -> String {
    use mail_parser::Addr;

    fn addr_to_string(addr: &Addr) -> String {
        match (addr.name(), addr.address()) {
            (Some(name), Some(email)) => format!("{} <{}>", name, email),
            (None, Some(email)) => email.to_string(),
            (Some(name), None) => name.to_string(),
            (None, None) => String::new(),
        }
    }

    msg.from()
        .map(|from| from.iter().map(addr_to_string).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

fn apply_antivirus_policy(
    mut subject: String,
    mut header_json: serde_json::Value,
    base_key: String,
    virus_detected: bool,
    antivirus_mode: &str,
    virus_response: &str,
) -> (String, serde_json::Value, String) {
    let object_key = if virus_detected && antivirus_mode == "quarantine" {
        format!("quarantine/{}.eml", base_key)
    } else {
        base_key
    };

    if virus_detected {
        match antivirus_mode {
            "quarantine" => {
                subject = format!("[QUARANTINE] {}", subject);
                header_json["quarantine_reason"] = json!([virus_response.to_string()]);
            }
            "tag" => {
                subject = format!("[VIRUS] {}", subject);
                header_json["X-Virus-Status"] = json!([virus_response.to_string()]);
            }
            _ => {}
        }
    }

    (subject, header_json, object_key)
}

async fn write_line(writer: &mut BufWriter<tokio::io::WriteHalf<AnyStream>>, line: String) -> Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await?;
    Ok(())
}

fn create_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    use std::{fs::File, io::BufReader as StdBufReader};

    let cert_file = File::open(cert_path)?;
    let mut cert_reader = StdBufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("invalid cert: {}", e))?;

    let key_file = File::open(key_path)?;
    let mut key_reader = StdBufReader::new(key_file);

    let mut key: Option<PrivateKeyDer<'static>> = None;
    for item in rustls_pemfile::read_all(&mut key_reader) {
        let item = item.map_err(|e| anyhow!("invalid key: {}", e))?;
        match item {
            rustls_pemfile::Item::Pkcs1Key(k) => {
                key = Some(PrivateKeyDer::Pkcs1(k));
                break;
            }
            rustls_pemfile::Item::Pkcs8Key(k) => {
                key = Some(PrivateKeyDer::Pkcs8(k));
                break;
            }
            rustls_pemfile::Item::Sec1Key(k) => {
                key = Some(PrivateKeyDer::Sec1(k));
                break;
            }
            _ => {}
        }
    }
    let key = key.ok_or_else(|| anyhow!("no private key found"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("tls config: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
