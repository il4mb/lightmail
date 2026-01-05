pub mod handler;

use std::sync::Arc;
use std::net::SocketAddr;
use crate::runtime::Runtime;
use handler::Pop3Handler;
use tokio::net::TcpListener;
use tracing::{info, error};
use anyhow::Result;

pub async fn run_pop3(runtime: Arc<Runtime>) -> Result<()> {
    let config = &runtime.config;
    let bind_addr = config.get_value("pop3", "bind").unwrap_or("0.0.0.0").to_string();
    let port = config.get_value("pop3", "port").unwrap_or("110").to_string();
    
    let addr = format!("{}:{}", bind_addr, port);
    let listener = TcpListener::bind(&addr).await?;
    
    info!("POP3 server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let runtime = Arc::clone(&runtime);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, addr, runtime).await {
                        error!("POP3 connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("POP3 accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::TcpStream, addr: SocketAddr, runtime: Arc<Runtime>) -> Result<()> {
    info!("New POP3 connection from {}", addr);
    let mut handler = Pop3Handler::new(runtime, addr);
    handler.run(stream).await
}
