//! Client side of tunnels: one tunnel = one TCP connection made by the server; plus the two ways to use them
//! (a local port that leads to a fixed destination, and a SOCKS5 proxy that leads wherever the application asks).
use crate::client::{Client, ServerError};
use crate::tunwire::*;
use crate::wire::{self, split_id, with_id, Frame};
use anyhow::{bail, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

pub struct Tunnel {
    client: Arc<Client>,
    id: u64,
    rx: tokio::sync::Mutex<mpsc::Receiver<Frame>>,
}

impl Client {
    /// asks the server to connect to host:port (if its rules allow); returns when the connection is made
    pub async fn tunnel_open(self: &Arc<Self>, host: &str, port: u16, wait: Duration) -> Result<Tunnel> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let open = encode_open(id, host, port).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let (tx, mut rx) = mpsc::channel(256);
        self.waiting.lock().await.insert(id, tx);
        let r = async {
            self.send(&Frame::new(TUN_OPEN, 0, open)).await?;
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(f)) if f.kind == TUN_READY => Ok(()),
                Ok(Some(f)) if f.kind == wire::ERROR => match split_id(&f.payload) {
                    Ok((_, r)) if r.len() >= 2 => Err(ServerError(u16::from_be_bytes([r[0], r[1]]), String::from_utf8_lossy(&r[2..]).into_owned()).into()),
                    _ => bail!("malformed error"),
                },
                _ => bail!("no answer to the tunnel request"),
            }
        }
        .await;
        if let Err(e) = r {
            self.waiting.lock().await.remove(&id);
            return Err(e);
        }
        Ok(Tunnel { client: self.clone(), id, rx: tokio::sync::Mutex::new(rx) })
    }
}

impl Tunnel {
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        for part in data.chunks(CHUNK) {
            self.client.send(&Frame::new(TUN_DATA, 0, with_id(self.id, part))).await?;
        }
        Ok(())
    }
    /// no more bytes from our side; the other side may still talk
    pub async fn eof(&self) -> Result<()> {
        self.client.send(&Frame::new(TUN_EOF, 0, with_id(self.id, &[]))).await
    }
    /// the next bytes from the destination; None when it has nothing more to say (or the tunnel is gone)
    pub async fn recv(&self) -> Option<Vec<u8>> {
        let mut rx = self.rx.lock().await;
        loop {
            let f = rx.recv().await?;
            let Ok((_, rest)) = split_id(&f.payload) else { continue };
            match f.kind {
                TUN_DATA => return Some(rest.to_vec()),
                TUN_EOF | TUN_CLOSE => return None,
                _ => {}
            }
        }
    }
    pub async fn close(self) {
        let _ = self.client.send(&Frame::new(TUN_CLOSE, 0, with_id(self.id, &[]))).await;
        self.client.waiting.lock().await.remove(&self.id);
    }
}

/// copies between a local connection and a tunnel until both directions are done
pub async fn bridge(tunnel: Tunnel, stream: TcpStream) {
    let (mut rd, mut wr) = stream.into_split();
    let mut buf = vec![0u8; CHUNK];
    let (mut local_done, mut remote_done) = (false, false);
    while !(local_done && remote_done) {
        tokio::select! {
            n = rd.read(&mut buf), if !local_done => match n {
                Ok(n) if n > 0 => { if tunnel.send(&buf[..n]).await.is_err() { break; } }
                _ => { local_done = true; if tunnel.eof().await.is_err() { break; } }
            },
            d = tunnel.recv(), if !remote_done => match d {
                Some(d) => { if wr.write_all(&d).await.is_err() { break; } }
                None => { remote_done = true; let _ = wr.shutdown().await; }
            },
        }
    }
    tunnel.close().await;
}

/// every connection to `listener` is carried to host:port from the server's side
pub async fn forward_local(client: Arc<Client>, listener: TcpListener, host: String, port: u16) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let (c, h) = (client.clone(), host.clone());
        tokio::spawn(async move {
            if let Ok(t) = c.tunnel_open(&h, port, Duration::from_secs(20)).await {
                bridge(t, stream).await;
            }
        });
    }
}

/// a SOCKS5 proxy (no authentication: bind it to a loopback address only), CONNECT only
pub async fn socks5(client: Arc<Client>, listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let c = client.clone();
        tokio::spawn(async move {
            let _ = socks5_one(c, stream).await;
        });
    }
}

async fn socks5_one(client: Arc<Client>, mut s: TcpStream) -> Result<()> {
    let t = Duration::from_secs(10);
    let mut head = [0u8; 2];
    tokio::time::timeout(t, s.read_exact(&mut head)).await??;
    if head[0] != 5 {
        bail!("not socks5");
    }
    let mut methods = vec![0u8; head[1] as usize];
    tokio::time::timeout(t, s.read_exact(&mut methods)).await??;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xFF]).await?;
        bail!("no acceptable method");
    }
    s.write_all(&[5, 0]).await?;
    let mut req = [0u8; 4];
    tokio::time::timeout(t, s.read_exact(&mut req)).await??;
    let reply = |code: u8| [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
    if req[0] != 5 || req[2] != 0 {
        bail!("bad request");
    }
    if req[1] != 1 {
        s.write_all(&reply(7)).await?; // command not supported
        bail!("only CONNECT");
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            tokio::time::timeout(t, s.read_exact(&mut a)).await??;
            std::net::Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            tokio::time::timeout(t, s.read_exact(&mut a)).await??;
            std::net::Ipv6Addr::from(a).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            tokio::time::timeout(t, s.read_exact(&mut n)).await??;
            let mut name = vec![0u8; n[0] as usize];
            tokio::time::timeout(t, s.read_exact(&mut name)).await??;
            String::from_utf8(name)?
        }
        _ => {
            s.write_all(&reply(8)).await?; // address type not supported
            bail!("bad address type");
        }
    };
    let mut p = [0u8; 2];
    tokio::time::timeout(t, s.read_exact(&mut p)).await??;
    match client.tunnel_open(&host, u16::from_be_bytes(p), Duration::from_secs(20)).await {
        Ok(tunnel) => {
            s.write_all(&reply(0)).await?;
            bridge(tunnel, s).await;
            Ok(())
        }
        Err(e) => {
            let code = match e.downcast_ref::<ServerError>().map(|s| s.0) {
                Some(E_DENIED) | Some(1) => 2, // not allowed by ruleset
                Some(E_CONNECT) => 5,          // connection refused
                _ => 1,                        // general failure
            };
            s.write_all(&reply(code)).await?;
            Err(e)
        }
    }
}
