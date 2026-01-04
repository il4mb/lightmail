use tokio::net::TcpListener;
use std::net::SocketAddr;

pub async fn listen(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (socket, peer) = listener.accept().await?;
        tracing::info!(%peer, "new connection");

        tokio::spawn(async move {
            // protocol dispatch later
            drop(socket);
        });
    }
}
