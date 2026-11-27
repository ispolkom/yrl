//! Manual cross-build handshake probe for Stage 8 acceptance.
//! Run two separately compiled copies against each other on a lab loopback.
use anyhow::{Context as _, Result};
use std::{path::Path, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use yrl::{crypto_profile::{Context, Policy}, keys, session};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let run = async { match args.as_slice() {
        [_, mode, address, key_dir] if mode == "server" => {
            let keys = keys::load(Path::new(key_dir))?;
            let listener = TcpListener::bind(address).await?;
            println!("READY");
            let (mut stream, _) = listener.accept().await?;
            session::server_handshake_open_context(
                &mut stream, &keys, &[], session::REKEY_EVERY, true,
                Context::Gatekeeper, Policy::default(),
            ).await.map(|(secure, _)| secure.profile()).map_err(|_| anyhow::anyhow!("server rejected handshake"))
        }
        [_, mode, address, key_dir, peer] if mode == "client" => {
            let keys = keys::load(Path::new(key_dir))?;
            let peer = hex::decode(peer)?;
            let mut stream = TcpStream::connect(address).await?;
            session::client_handshake_context(
                &mut stream, &keys, &peer, session::REKEY_EVERY,
                Context::Gatekeeper, Policy::default(),
            ).await.map(|secure| secure.profile())
        }
        _ => anyhow::bail!("usage: wire_compat_probe server <address> <server-key-dir> | client <address> <client-key-dir> <server-public-hex>"),
    }};
    let profile = tokio::time::timeout(Duration::from_secs(5), run)
        .await.context("handshake timeout")??;
    println!("OK {profile:#010x}");
    Ok(())
}
