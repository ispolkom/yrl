//! Server side of tunnels: what may be reached is decided by the file `<dir>/tunnels` (nothing is allowed by default), the bytes are then just copied.
//! File format, one rule per line: `<login|*> <host|*> <port|low-high|*>`; `#` comments. Read afresh at every request; a file open to others is ignored.
use crate::tunwire::*;
use crate::wire::{self, with_id, Frame};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub enum TunIn {
    Data(Vec<u8>),
    Eof,
    Close,
}

pub fn permits(rules_text: &str, login: &str, host: &str, port: u16) -> bool {
    rules_text.lines().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')).any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() != 3 {
            return false; // a damaged rule allows nothing
        }
        let port_ok = match f[2] {
            "*" => true,
            p => match p.split_once('-') {
                Some((a, b)) => matches!((a.parse::<u16>(), b.parse::<u16>()), (Ok(a), Ok(b)) if a <= port && port <= b),
                None => p.parse::<u16>().is_ok_and(|p| p == port),
            },
        };
        (f[0] == "*" || f[0] == login) && (f[1] == "*" || f[1].eq_ignore_ascii_case(host)) && port_ok
    })
}

pub fn read_rules(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(m) if crate::keys::mode_ok_for_reading(m.mode()) => std::fs::read_to_string(path).unwrap_or_default(),
        _ => String::new(),
    }
}

fn err(id: u64, code: u16, text: &str) -> Frame {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(text.as_bytes());
    Frame::new(wire::ERROR, 0, with_id(id, &p))
}

pub async fn run(id: u64, host: String, port: u16, connect_timeout: Duration, mut rx: mpsc::Receiver<TunIn>, tx: mpsc::Sender<Frame>) {
    let stream = match tokio::time::timeout(connect_timeout, TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(s)) => s,
        _ => {
            let _ = tx.send(err(id, E_CONNECT, "cannot connect")).await;
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    let _ = tx.send(Frame::new(TUN_READY, 0, with_id(id, &[]))).await;
    let (mut rd, mut wr) = stream.into_split();
    let tx2 = tx.clone();
    let mut reader = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = tx2.send(Frame::new(TUN_EOF, 0, with_id(id, &[]))).await;
                    return;
                }
                Ok(n) => {
                    if tx2.send(Frame::new(TUN_DATA, 0, with_id(id, &buf[..n]))).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    let (mut client_done, mut remote_done) = (false, false);
    while !(client_done && remote_done) {
        tokio::select! {
            m = rx.recv(), if !client_done => match m {
                Some(TunIn::Data(d)) => {
                    if wr.write_all(&d).await.is_err() {
                        break;
                    }
                }
                Some(TunIn::Eof) => {
                    let _ = wr.shutdown().await;
                    client_done = true;
                }
                Some(TunIn::Close) | None => break,
            },
            _ = &mut reader, if !remote_done => remote_done = true,
        }
        if client_done && !remote_done {
            // only the remote side can still speak; a Close from the client must still end it
            tokio::select! {
                _ = &mut reader => remote_done = true,
                m = rx.recv() => if matches!(m, Some(TunIn::Close) | None) { break },
            }
        }
    }
    reader.abort();
    let _ = tx.send(Frame::new(TUN_CLOSE, 0, with_id(id, &[]))).await;
}
