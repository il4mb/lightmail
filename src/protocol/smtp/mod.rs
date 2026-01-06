use std::sync::Arc;
use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use crate::runtime::Runtime;
use tracing::info;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

pub mod server;

pub async fn send_email(runtime: Arc<Runtime>, from: &str, to: &[String], data: &str) -> Result<()> {
    let host = runtime.config.get_value("smtp", "host").unwrap_or("127.0.0.1").to_string();
    let use_smtps = runtime.config.get_bool("smtp", "use_smtps", false);
    let port = if use_smtps {
        runtime.config.get_value("smtp", "smtps_port").unwrap_or("465").to_string()
    } else {
        runtime.config.get_value("smtp", "port").unwrap_or("25").to_string()
    };
    let addr = format!("{}:{}", host, port);

    let hostname = runtime.config.get_value("system", "hostname").unwrap_or("localhost");
    let mut reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>;
    let mut writer: BufWriter<Box<dyn AsyncWrite + Unpin + Send>>;

    // Auto-fallback when enabled: try STARTTLS first, then SMTPS if it fails
    let auto_fallback = runtime.config.get_bool("smtp", "auto_tls_fallback", true);

    if use_smtps {
        // TLS on connect (SMTPS)
        let cx = native_tls::TlsConnector::new().map_err(|e| anyhow!("TLS init: {}", e))?;
        let connector = tokio_native_tls::TlsConnector::from(cx);
        let domain = hostname;
        let tcp = TcpStream::connect(addr).await?;
        info!("SMTP SMTPS handshake using host: {}", domain);
        let tls_stream = connector.connect(domain, tcp).await.map_err(|e| anyhow!("SMTPS connect failed: {}", e))?;
        let (r2, w2) = tokio::io::split(tls_stream);
        reader = BufReader::new(Box::new(r2));
        writer = BufWriter::new(Box::new(w2));
        read_expect(&mut reader, 220).await?;
        ehlo(&mut writer, &mut reader, hostname).await?;
    } else {
        // Plain TCP first
        let tcp = TcpStream::connect(addr).await?;
        let (r, w) = tokio::io::split(tcp);
        let mut local_reader = BufReader::new(r);
        let mut local_writer = BufWriter::new(w);
        read_expect(&mut local_reader, 220).await?;
        ehlo(&mut local_writer, &mut local_reader, hostname).await?;

        if runtime.config.get_bool("smtp", "use_starttls", false) {
            // Try STARTTLS
            let starttls_attempt = async {
                write_line(&mut local_writer, "STARTTLS".to_string()).await?;
                read_expect(&mut local_reader, 220).await?;
                let cx = native_tls::TlsConnector::new().map_err(|e| anyhow!("TLS init: {}", e))?;
                let connector = tokio_native_tls::TlsConnector::from(cx);
                let domain = hostname;
                let stream = local_reader.into_inner().unsplit(local_writer.into_inner());
                info!("SMTP STARTTLS handshake using host: {}", domain);
                let tls_stream = connector.connect(domain, stream).await.map_err(|e| anyhow!("STARTTLS failed: {}", e))?;
                let (r2, w2) = tokio::io::split(tls_stream);
                let mut reader_tls = BufReader::new(r2);
                let mut writer_tls = BufWriter::new(w2);
                ehlo(&mut writer_tls, &mut reader_tls, hostname).await?;
                Ok::<(BufReader<tokio::io::ReadHalf<_>>, BufWriter<tokio::io::WriteHalf<_>>), anyhow::Error>((reader_tls, writer_tls))
            }.await;

            match starttls_attempt {
                Ok((r_tls, w_tls)) => {
                    reader = BufReader::new(Box::new(r_tls.into_inner()));
                    writer = BufWriter::new(Box::new(w_tls.into_inner()));
                }
                Err(e) => {
                    if auto_fallback {
                        // Fallback to SMTPS
                        let smtps_port = runtime.config.get_value("smtp", "smtps_port").unwrap_or("465").to_string();
                        let smtps_addr = format!("{}:{}", host, smtps_port);
                        let cx = native_tls::TlsConnector::new().map_err(|e| anyhow!("TLS init: {}", e))?;
                        let connector = tokio_native_tls::TlsConnector::from(cx);
                        let domain = hostname;
                        let tcp2 = TcpStream::connect(smtps_addr).await?;
                        info!("SMTP fallback SMTPS handshake using host: {}", domain);
                        let tls_stream = connector.connect(domain, tcp2).await.map_err(|e| anyhow!("SMTPS connect failed: {}", e))?;
                        let (r3, w3) = tokio::io::split(tls_stream);
                        reader = BufReader::new(Box::new(r3));
                        writer = BufWriter::new(Box::new(w3));
                        read_expect(&mut reader, 220).await?;
                        ehlo(&mut writer, &mut reader, hostname).await?;
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            // No STARTTLS: keep plain halves
            reader = BufReader::new(Box::new(local_reader.into_inner()));
            writer = BufWriter::new(Box::new(local_writer.into_inner()));
        }
    }

    // AUTH if configured (works for either plain or TLS connection)
    if let (Some(user), Some(pass)) = (
        runtime.config.get_value("smtp", "username"),
        runtime.config.get_value("smtp", "password")
    ) {
        let method = runtime.config.get_value("smtp", "auth_method").unwrap_or("plain");
        match method.to_ascii_lowercase().as_str() {
            "login" => {
                // AUTH LOGIN
                write_line(&mut writer, "AUTH LOGIN".to_string()).await?;
                let l1 = read_line(&mut reader).await?; // expect 334
                if !l1.starts_with("334") { return Err(anyhow!("AUTH LOGIN expected 334, got: {}", l1)); }
                let u_b64 = B64.encode(user);
                write_line(&mut writer, u_b64).await?;
                let l2 = read_line(&mut reader).await?;
                if !l2.starts_with("334") { return Err(anyhow!("AUTH LOGIN expected 334 (pass), got: {}", l2)); }
                let p_b64 = B64.encode(pass);
                write_line(&mut writer, p_b64).await?;
                read_expect(&mut reader, 235).await?;
            }
            _ => {
                // AUTH PLAIN \0user\0pass
                let payload = format!("\u{0000}{}\u{0000}{}", user, pass);
                let b64 = B64.encode(payload);
                write_line(&mut writer, format!("AUTH PLAIN {}", b64)).await?;
                read_expect(&mut reader, 235).await?;
            }
        }
    }

    write_line(&mut writer, format!("MAIL FROM:<{}>", from)).await?;
    read_expect(&mut reader, 250).await?;

    for rcpt in to {
        write_line(&mut writer, format!("RCPT TO:<{}>", rcpt)).await?;
        read_expect(&mut reader, 250).await?;
    }

    write_line(&mut writer, "DATA".to_string()).await?;
    read_expect(&mut reader, 354).await?;

    let mut body = normalize_crlf(data);
    body = dot_stuff(&body);
    write_raw(&mut writer, body.as_bytes()).await?;
    write_line(&mut writer, ".".to_string()).await?;
    read_expect(&mut reader, 250).await?;

    write_line(&mut writer, "QUIT".to_string()).await?;
    let _ = read_any(&mut reader).await; // ignore final
    Ok(())
}

async fn ehlo<W, R>(writer: &mut BufWriter<W>, reader: &mut BufReader<R>, hostname: &str) -> Result<()>
where W: AsyncWrite + Unpin, R: AsyncRead + Unpin {
    write_line(writer, format!("EHLO {}", hostname)).await?;
    // Read multiline 250 responses
    loop {
        let line = read_line(reader).await?;
        if !line.starts_with("250") { return Err(anyhow!("Unexpected EHLO response: {}", line)); }
        if line.starts_with("250 ") { break; }
        if !line.starts_with("250-") { break; }
        // continue reading capability lines
    }
    Ok(())
}

fn normalize_crlf(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for line in s.split('\n') {
        let l = line.trim_end_matches('\r');
        out.push_str(l);
        out.push_str("\r\n");
    }
    out
}

fn dot_stuff(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.split("\r\n") {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

async fn write_line<W>(writer: &mut BufWriter<W>, line: String) -> Result<()>
where W: AsyncWrite + Unpin {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_raw<W>(writer: &mut BufWriter<W>, bytes: &[u8]) -> Result<()>
where W: AsyncWrite + Unpin {
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_line<R>(reader: &mut BufReader<R>) -> Result<String>
where R: AsyncRead + Unpin {
    let mut buf = String::new();
    reader.read_line(&mut buf).await?;
    Ok(buf.trim_end_matches("\r\n").to_string())
}

async fn read_expect<R>(reader: &mut BufReader<R>, code: u16) -> Result<String>
where R: AsyncRead + Unpin {
    let line = read_line(reader).await?;
    let ok = line.starts_with(&code.to_string());
    if !ok { return Err(anyhow!("SMTP expected {} got: {}", code, line)); }
    Ok(line)
}

async fn read_any<R>(reader: &mut BufReader<R>) -> Result<String>
where R: AsyncRead + Unpin {
    read_line(reader).await
}
