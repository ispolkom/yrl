//! Structured execution: argv without any shell, no stdin, output streamed in chunks, a hard timeout, bounded output.
use crate::identity::Target;
use crate::wire::{self, with_id, ExecReq, Frame};
use std::os::unix::ffi::OsStrExt;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::mpsc;

pub const DEFAULT_TIMEOUT_MS: u32 = 60_000;
pub const MAX_TIMEOUT_MS: u32 = 3_600_000;
pub const MAX_OUTPUT: usize = 64 << 20;
const CHUNK: usize = 16 * 1024;

pub async fn run(req: ExecReq, target: Target, tx: mpsc::Sender<Frame>) {
    let id = req.request_id;
    let err = |code: u16, text: &str| {
        let mut p = code.to_be_bytes().to_vec();
        p.extend_from_slice(text.as_bytes());
        Frame::new(wire::ERROR, 0, with_id(id, &p))
    };
    let prog = std::ffi::OsStr::from_bytes(&req.argv[0]);
    let mut cmd = Command::new(prog);
    cmd.args(req.argv[1..].iter().map(|a| std::ffi::OsStr::from_bytes(a))).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    prepare(&mut cmd, &target);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            let _ = tx.send(err(2, "cannot start the program")).await;
            return;
        }
    };
    let (so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let budget = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pump = |mut r: tokio::process::ChildStdout, kind: u8, tx: mpsc::Sender<Frame>, budget: std::sync::Arc<std::sync::atomic::AtomicUsize>| async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if budget.fetch_add(n, std::sync::atomic::Ordering::SeqCst) + n > MAX_OUTPUT {
                return true; // over the limit
            }
            if tx.send(Frame::new(kind, 0, with_id(id, &buf[..n]))).await.is_err() {
                break;
            }
        }
        false
    };
    // stderr is a different type: copy the same loop
    let tx2 = tx.clone();
    let b2 = budget.clone();
    let err_task = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match se.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if b2.fetch_add(n, std::sync::atomic::Ordering::SeqCst) + n > MAX_OUTPUT {
                return true;
            }
            if tx2.send(Frame::new(wire::STDERR, 0, with_id(id, &buf[..n]))).await.is_err() {
                break;
            }
        }
        false
    });
    let out_task = tokio::spawn(pump(so, wire::STDOUT, tx.clone(), budget.clone()));
    let limit = Duration::from_millis(if req.timeout_ms == 0 { DEFAULT_TIMEOUT_MS } else { req.timeout_ms.min(MAX_TIMEOUT_MS) } as u64);
    let waited = tokio::time::timeout(limit, child.wait()).await;
    let (code, note) = match waited {
        Ok(Ok(status)) => (status.code().unwrap_or(-1), None),
        _ => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            (-1, Some((3u16, "timed out and killed")))
        }
    };
    let over = out_task.await.unwrap_or(false) | err_task.await.unwrap_or(false);
    if over {
        let _ = child.start_kill();
        let _ = tx.send(err(4, "output limit exceeded")).await;
    }
    if let Some((c, t)) = note {
        let _ = tx.send(err(c, t)).await;
    }
    let _ = tx.send(Frame::new(wire::EXIT, 0, with_id(id, &code.to_be_bytes()))).await;
}

/// the same for every program a session starts: a small known environment, the user's home, and the switch to the user's identity (from root only)
pub fn prepare(cmd: &mut Command, target: &Target) {
    // nothing of the server's environment reaches the program (no LD_PRELOAD, no secrets): a small known one
    cmd.env_clear().env("HOME", &target.pw.home).env("USER", &target.pw.name).env("LOGNAME", &target.pw.name).env("PATH", "/usr/local/bin:/usr/bin:/bin");
    // The working directory is entered by the program itself, AFTER it has become the user: the part that starts it may be unable to enter a home that belongs to
    // someone else (it keeps no right to walk through other people's directories), and a home that cannot be entered must not stop the program from starting: "/" then.
    let home = std::ffi::CString::new(target.pw.home.clone()).unwrap_or_default();
    let (uid, gid, switch) = (target.pw.uid, target.pw.gid, target.switch);
    let cname = std::ffi::CString::new(target.pw.name.clone()).unwrap_or_default();
    // runs in the child between fork and exec: groups first, then gid, then uid; afterwards the way back to root must be closed
    unsafe {
        cmd.pre_exec(move || {
            if switch {
                if libc::initgroups(cname.as_ptr(), gid) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if uid != 0 && libc::setuid(0) == 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
            }
            if home.as_bytes().is_empty() || libc::chdir(home.as_ptr()) != 0 {
                libc::chdir(b"/\0".as_ptr() as *const libc::c_char);
            }
            Ok(())
        });
    }
}
