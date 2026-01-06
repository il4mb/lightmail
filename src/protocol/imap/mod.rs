pub mod handler;
pub mod state;
pub mod command;
pub mod parser;

use std::sync::Arc;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;

use crate::runtime::Runtime;
use handler::ImapHandler;
use state::ImapSession;

use tokio::net::{ TcpListener, TcpStream };
use tokio::sync::Mutex;
use tokio_rustls::rustls::{ self, pki_types::{ CertificateDer, PrivateKeyDer } };
use tokio_rustls::TlsAcceptor;

use anyhow::Result;
use tracing::{ error, info };

pub async fn run_imap(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let config = &runtime.config;
    let bind_addr = config.get_value("imap", "bind").unwrap_or("0.0.0.0").to_string();
    let port = config.get_value("imap", "port").unwrap_or("143").to_string();
    let ssl_port = config.get_value("imap", "ssl_port").unwrap_or("993").to_string();
    let enable_ssl = config
        .get_value("imap", "enable_ssl")
        .map(|v| v == "true" || v == "1" )
        .unwrap_or(false);
    let max_connections: usize = config
        .get_value("imap", "max_connections")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    info!("Starting IMAP server...");
    info!("IMAP port: {}, IMAPS port: {}", port, ssl_port);

    // Create connection limiter
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_connections));

    // --- 1. Prepare TLS (Add error logging) ---
    let tls_acceptor = if enable_ssl {
        let cert_path = config
            .get_value("imap", "tls_cert")
            .ok_or_else(|| anyhow::anyhow!("TLS cert missing"))?;
        let key_path = config
            .get_value("imap", "tls_key")
            .ok_or_else(|| anyhow::anyhow!("TLS key missing"))?;

        match create_tls_acceptor(&cert_path, &key_path) {
            Ok(a) => Some(a),
            Err(e) => {
                error!("Failed to load TLS certificates: {}", e);
                return Err(e);
            }
        }
    } else {
        None
    };

    let tls_only = config.get_bool("imap", "tls_only", false);

    // --- 2. Start Plain IMAP unless TLS-only ---
    if !tls_only {
        let plain_addr = format!("{}:{}", bind_addr, port);
        info!("Attempting to bind IMAP to {}", plain_addr); // Debug log

        let plain_listener = match TcpListener::bind(&plain_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("FATAL: Could not bind to IMAP port {}: {}", plain_addr, e);
                return Err(e.into());
            }
        };
        info!("IMAP listening on: {}", plain_addr);

        let runtime_plain = runtime.clone();
        let semaphore_plain = semaphore.clone();

        // Spawn Plain Listener
        tokio::spawn(async move {
            accept_connections(plain_listener, runtime_plain, semaphore_plain, None).await;
        });
    } else {
        info!("TLS-only mode enabled: Plain IMAP listener disabled");
        if tls_acceptor.is_none() {
            error!("TLS-only requires 'enable_ssl=true' and valid cert/key");
            return Err(anyhow::anyhow!("TLS-only enabled without SSL configuration"));
        }
    }

    // Start IMAPS if enabled
    if let Some(acceptor) = tls_acceptor {
        let ssl_addr = format!("{}:{}", bind_addr, ssl_port);
        let ssl_listener = TcpListener::bind(&ssl_addr).await?;
        info!("IMAPS listening on: {}", ssl_addr);

        let runtime_ssl = runtime.clone();
        let semaphore_ssl = semaphore.clone();

        // Spawn SSL Listener
        tokio::spawn(async move {
            accept_connections(ssl_listener, runtime_ssl, semaphore_ssl, Some(acceptor)).await;
        });
    } else if tls_only {
        // In TLS-only mode, IMAPS must be available
        error!("TLS-only mode enabled but IMAPS listener not started");
        return Err(anyhow::anyhow!("IMAPS not available in TLS-only mode"));
    }

    Ok(())
}

/**
 * --------------------------------------------------------------
 * ---------------- IMAP Connection Listener. -------------------
 * --------------------------------------------------------------
 */
async fn accept_connections(
    listener: TcpListener,
    runtime: Arc<Runtime>,
    semaphore: Arc<tokio::sync::Semaphore>,
    tls_acceptor: Option<TlsAcceptor> // Passed in to avoid reloading certs every connection
) {
    loop {
        // Acquire semaphore permit
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                error!("Connection semaphore closed");
                break;
            }
        };

        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New IMAP connection from: {}", peer_addr);

                let runtime_clone = runtime.clone();
                let acceptor_clone = tls_acceptor.clone();

                tokio::spawn(async move {
                    handle_imap_connection(stream, runtime_clone, acceptor_clone, peer_addr).await;
                    drop(permit); // Release semaphore permit
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/**
 * --------------------------------------------------------------
 * ----------------- Handle IMAP Connection. --------------------
 * --------------------------------------------------------------
 */
async fn handle_imap_connection(
    stream: TcpStream,
    runtime: Arc<Runtime>,
    tls_acceptor: Option<TlsAcceptor>,
    peer_addr: SocketAddr
) {
    let client_id = format!("{}", peer_addr);
    let session = Arc::new(Mutex::new(ImapSession::new(client_id.clone())));
    let handler = ImapHandler::new(runtime.clone(), session.clone());

    if let Some(acceptor) = tls_acceptor {
        // --- Handle TLS Connection ---
        match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                // Mark session as TLS-active
                {
                    let mut s = session.lock().await;
                    s.tls_active = true;
                }
                // Assuming ImapHandler::handle_connection accepts generic AsyncRead + AsyncWrite
                if let Err(e) = handler.handle_connection(tls_stream).await {
                    error!("IMAPS connection error for {}: {}", client_id, e);
                }
            }
            Err(e) => {
                error!("TLS handshake failed for {}: {}", client_id, e);
            }
        }
    } else {
        // --- Handle Plain Connection ---
        {
            let mut s = session.lock().await;
            s.tls_active = false;
        }
        if let Err(e) = handler.handle_connection(stream).await {
            error!("IMAP connection error for {}: {}", client_id, e);
        }
    }

    info!("IMAP connection closed: {}", client_id);
}

/**
 * -------------------------------------------------------------
 * ---------------------- Helper Functions. --------------------
 * -------------------------------------------------------------
 */

fn create_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = rustls::ServerConfig
        ::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let cert_file = File::open(path)?;
    let mut reader = BufReader::new(cert_file);
    // rustls-pemfile 1.0+ syntax
    let certs = rustls_pemfile
        ::certs(&mut reader)
        .filter_map(Result::ok)
        .map(CertificateDer::from)
        .collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let key_file = File::open(path)?;
    let mut reader = BufReader::new(key_file);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs1(key.into()));
            }
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key.into()));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(PrivateKeyDer::Sec1(key.into()));
            }
            None => {
                break;
            } // EOF
            _ => {
                continue;
            } // skip certs, CRLs, etc
        }
    }

    Err(anyhow::anyhow!("No valid private key found in {}", path))
}
