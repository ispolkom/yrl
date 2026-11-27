//! The server side of a transfer: one task per transfer drives a helper process (see fshelper.rs) that runs as the account's system user.
use crate::exec::prepare;
use crate::filewire::*;
use crate::identity::Target;
use crate::wire::{self, with_id, Frame};
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;

pub enum FileIn {
    Data(Vec<u8>),
    End,
    Abort,
}

fn err(id: u64, code: u16, text: &str) -> Frame {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(text.as_bytes());
    Frame::new(wire::ERROR, 0, with_id(id, &p))
}

fn code_text(code: u16) -> &'static str {
    match code {
        E_OPEN => "cannot open the file",
        E_VERIFY => "the file did not arrive intact",
        E_TOO_BIG => "the file is too big",
        E_REQUEST => "bad request",
        E_OFFSET => "offset beyond the end of the file",
        E_QUOTA => "disk quota exhausted",
        E_NO_SPACE => "not enough free disk space",
        _ => "input/output error",
    }
}

async fn spawn_helper(helper: &Path, target: &Target, cgroup: Option<&crate::cgroup::Attachment>) -> Option<(Child, ChildStdin, BufReader<ChildStdout>)> {
    let mut cmd = Command::new(helper);
    cmd.arg("fs-helper").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    if let Some(cg) = cgroup { crate::cgroup::SessionCgroup::attach(&mut cmd, cg); }
    prepare(&mut cmd, target);
    let mut child = cmd.spawn().ok()?;
    let (i, o) = (child.stdin.take()?, child.stdout.take()?);
    Some((child, i, BufReader::with_capacity(1 << 20, o)))
}

async fn read_line(r: &mut BufReader<ChildStdout>) -> Option<String> {
    let mut s = String::new();
    // a helper line is short; a longer one means something is wrong
    let n = r.take(200).read_line(&mut s).await.ok()?;
    if n == 0 || !s.ends_with('\n') {
        return None;
    }
    Some(s.trim_end().to_string())
}

fn helper_error(line: &str) -> u16 {
    line.strip_prefix("ERR ").and_then(|c| c.parse().ok()).unwrap_or(E_IO)
}

#[allow(clippy::too_many_arguments)]
pub async fn put(req: PutReq, target: Target, helper: std::path::PathBuf, max_size: u64, disk: std::sync::Arc<crate::disk::DiskManager>, key: Vec<u8>, account: String, mut rx: mpsc::Receiver<FileIn>, tx: mpsc::Sender<Frame>, cgroup: Option<crate::cgroup::Attachment>) {
    let id = req.id;
    if req.size > max_size {
        let _ = tx.send(err(id, E_TOO_BIG, code_text(E_TOO_BIG))).await;
        return;
    }
    let reservation = match disk.reserve(&key, &account, &target, &req.path, req.size) {
        Ok(r) => r,
        Err(crate::disk::Refusal::Quota | crate::disk::Refusal::Busy) => {
            let _ = tx.send(err(id, E_QUOTA, code_text(E_QUOTA))).await; return;
        }
        Err(crate::disk::Refusal::NoSpace) => {
            let _ = tx.send(err(id, E_NO_SPACE, code_text(E_NO_SPACE))).await; return;
        }
        Err(crate::disk::Refusal::State) => {
            let _ = tx.send(err(id, E_IO, code_text(E_IO))).await; return;
        }
    };
    let Some((_child, mut stdin, mut out)) = spawn_helper(&helper, &target, cgroup.as_ref()).await else {
        let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
        return;
    };
    let head = format!("PUT {:o} {} {} {} {}\n", req.mode, req.size, hex::encode(req.hash), reservation.token_hex(), hex::encode(&req.path));
    if stdin.write_all(head.as_bytes()).await.is_err() {
        let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
        return;
    }
    let offset = match read_line(&mut out).await.as_deref().map(|l| (l.strip_prefix("OFFSET ").and_then(|n| n.parse::<u64>().ok()), l.to_string())) {
        Some((Some(n), _)) if n <= req.size => n,
        Some((_, l)) => {
            let c = helper_error(&l);
            let _ = tx.send(err(id, c, code_text(c))).await;
            return;
        }
        None => {
            let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
            return;
        }
    };
    let _ = tx.send(Frame::new(FILE_READY, 0, with_id(id, &offset.to_be_bytes()))).await;
    let expected = req.size - offset;
    let mut got = 0u64;
    loop {
        match rx.recv().await {
            Some(FileIn::Data(d)) => {
                reservation.touch();
                got += d.len() as u64;
                if got > expected {
                    let _ = tx.send(err(id, E_VERIFY, "more data than announced")).await;
                    return;
                }
                if stdin.write_all(&d).await.is_err() {
                    break; // the helper stopped: its reason follows
                }
            }
            Some(FileIn::End) => {
                if got != expected {
                    let _ = tx.send(err(id, E_VERIFY, "the data ended early")).await;
                    return; // the helper is killed with its pipe; the part stays for a resume
                }
                break;
            }
            Some(FileIn::Abort) => return,
            None => {
                reservation.preserve();
                return;
            }
        }
    }
    drop(stdin);
    match read_line(&mut out).await.as_deref() {
        Some("OK") => {
            reservation.complete();
            let _ = tx.send(Frame::new(FILE_END, 0, with_id(id, &[]))).await;
        }
        Some(l) => {
            let c = helper_error(l);
            if c == E_NO_SPACE {
                // The helper already opened the tagged partial. Keep its
                // charge and token so the same owner can retry after freeing
                // space or increasing the filesystem quota.
                reservation.preserve();
            }
            let _ = tx.send(err(id, c, code_text(c))).await;
        }
        None => {
            let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
        }
    }
}

pub async fn get(req: GetReq, target: Target, helper: std::path::PathBuf, mut rx: mpsc::Receiver<FileIn>, tx: mpsc::Sender<Frame>, cgroup: Option<crate::cgroup::Attachment>) {
    let id = req.id;
    let Some((_child, mut stdin, mut out)) = spawn_helper(&helper, &target, cgroup.as_ref()).await else {
        let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
        return;
    };
    let head = format!("GET {} {}\n", req.offset, hex::encode(&req.path));
    if stdin.write_all(head.as_bytes()).await.is_err() {
        let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
        return;
    }
    drop(stdin);
    let size = match read_line(&mut out).await.as_deref().map(|l| (l.strip_prefix("SIZE ").and_then(|n| n.parse::<u64>().ok()), l.to_string())) {
        Some((Some(n), _)) if n >= req.offset => n,
        Some((_, l)) => {
            let c = helper_error(&l);
            let _ = tx.send(err(id, c, code_text(c))).await;
            return;
        }
        None => {
            let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
            return;
        }
    };
    let _ = tx.send(Frame::new(FILE_READY, 0, with_id(id, &size.to_be_bytes()))).await;
    let mut left = size - req.offset;
    let mut buf = vec![0u8; CHUNK];
    while left > 0 {
        let want = (CHUNK as u64).min(left) as usize;
        let n = tokio::select! {
            r = out.read(&mut buf[..want]) => match r { Ok(n) if n > 0 => n, _ => {
                let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
                return;
            } },
            m = rx.recv() => match m { Some(FileIn::Abort) | None => return, _ => continue },
        };
        left -= n as u64;
        if tx.send(Frame::new(FILE_DATA, 0, with_id(id, &buf[..n]))).await.is_err() {
            return;
        }
    }
    match read_line(&mut out).await.as_deref().and_then(|l| l.strip_prefix("HASH ").and_then(|h| hex::decode(h).ok())) {
        Some(h) if h.len() == 32 => {
            let _ = tx.send(Frame::new(FILE_END, 0, with_id(id, &h))).await;
        }
        _ => {
            let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
        }
    }
}
