//! yrl-relay <bind addr:port>  -  a meeting point for servers behind NAT. It sees only ciphertext and keeps nothing but counters.
#[tokio::main]
async fn main() {
    let Some(bind) = std::env::args().nth(1) else {
        eprintln!("usage: yrl-relay <addr:port>");
        std::process::exit(2);
    };
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let relay = yrl::relay::serve(listener, yrl::relay::RelayConfig::default()).await;
    eprintln!("[yrl-relay] listening on {bind}");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        eprintln!("[yrl-relay] pairs so far: {}, dropped: {}", relay.stats.pairs.load(std::sync::atomic::Ordering::SeqCst), relay.stats.dropped.load(std::sync::atomic::Ordering::SeqCst));
    }
}
