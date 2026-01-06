pub mod handler;

use tokio::{ net::UnixListener };
use std::{ path::Path, sync::Arc };
use tracing::{info, error};

use crate::runtime::Runtime;

pub async fn run_lmtp(runtime: Arc<Runtime>) {
    info!("Starting LMTP server");

    let config = &runtime.config;
    // let db = runtime.db.get().unwrap();

    let path = Path::new(config.get_value("lmtp", "socket").unwrap_or("/tmp/lmtp.sock"));

    if path.exists() && path.is_dir() {
        error!("LMTP socket path is a directory: {:?}", path);
        return; // do not crash the whole server
    }
    if path.exists() {
        match std::fs::remove_file(path) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to remove existing LMTP socket {:?}: {}", path, e);
                return; // skip starting LMTP rather than panicking
            }
        }
    }

    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind LMTP socket {:?}: {}", path, e);
            return;
        }
    };
    info!("LMTP server listening on {path:?}");

    loop {
        
        let runtime = runtime.clone();
        let client = listener.accept().await;
        let (socket, _) = client.unwrap();

        tokio::spawn(async move {
            let _ = handler::handle_client(socket, runtime).await;
        });
    }
}
