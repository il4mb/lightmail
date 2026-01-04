pub mod handler;

use tokio::{ net::UnixListener, runtime };
use std::{ path::Path, sync::Arc };
use tracing::info;

use crate::runtime::Runtime;

pub async fn run_lmtp(runtime: Arc<Runtime>) {
    info!("Starting LMTP server");

    let config = &runtime.config;
    let db = runtime.db.get().unwrap();

    let path = Path::new(config.get_value("lmtp", "socket").unwrap_or("/tmp/lmtp.sock"));

    if path.exists() && path.is_dir() {
        panic!("LMTP socket path must not be a directory");
    }
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }

    let listener = UnixListener::bind(path).unwrap();
    info!("LMTP server listening on {path:?}");

    loop {
        
        let runtime = runtime.clone();
        let client = listener.accept().await;
        let (socket, _) = client.unwrap();

        tokio::spawn(async move {
            handler::handle_client(socket, runtime).await;
        });
    }
}
