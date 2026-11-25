//! An interactive terminal: the user's own login shell on a pseudo-terminal. Input and output are plain bytes (the terminal's own line discipline handles Ctrl-C, Ctrl-Z, echo),
//! window size changes are separate frames. When the link or the session ends the shell gets a hangup and, if it ignores it, a kill.
use crate::exec::{prepare, ProcessGroup};
use crate::identity::{usable_shell, Target};
use crate::wire::{self, with_id, Frame};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::process::Command;
use tokio::sync::mpsc;

pub enum PtyCmd {
    Input(Vec<u8>),
    Resize(u16, u16),
    Hangup,
}

const CHUNK: usize = 16 * 1024;

/// a terminal type is a short word; anything else is replaced, never passed on (it goes into the environment of the shell)
pub fn clean_term(t: &[u8]) -> String {
    let ok = !t.is_empty() && t.len() <= wire::MAX_TERM && t.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'+'));
    if ok { String::from_utf8_lossy(t).into_owned() } else { "xterm".into() }
}

fn error_frame(id: u64, code: u16, text: &str) -> Frame {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(text.as_bytes());
    Frame::new(wire::ERROR, 0, with_id(id, &p))
}

fn winsize(rows: u16, cols: u16) -> libc::winsize {
    libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 }
}

struct Master(OwnedFd);
impl AsRawFd for Master {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

fn open_pair(rows: u16, cols: u16) -> std::io::Result<(OwnedFd, OwnedFd)> {
    let (mut m, mut s) = (-1, -1);
    let ws = winsize(rows, cols);
    if unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (m, s) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
    for fd in [m.as_raw_fd(), s.as_raw_fd()] {
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    unsafe {
        let fl = libc::fcntl(m.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(m.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    Ok((m, s))
}

pub async fn run(id: u64, rows: u16, cols: u16, term: String, target: Target, mut cmds: mpsc::Receiver<PtyCmd>, tx: mpsc::Sender<Frame>) {
    let shells = std::fs::read_to_string("/etc/shells").unwrap_or_default();
    if !usable_shell(&target.pw.shell, &shells) {
        let _ = tx.send(error_frame(id, 6, "no usable login shell for this account")).await;
        return;
    }
    let Ok((master, slave)) = open_pair(rows, cols) else {
        let _ = tx.send(error_frame(id, 6, "cannot open a terminal")).await;
        return;
    };
    if target.switch {
        unsafe {
            libc::fchown(slave.as_raw_fd(), target.pw.uid, target.pw.gid);
        }
    }
    let dup = |fd: &OwnedFd| fd.try_clone().map(Stdio::from);
    let (Ok(i), Ok(o), Ok(e)) = (dup(&slave), dup(&slave), dup(&slave)) else {
        let _ = tx.send(error_frame(id, 6, "cannot open a terminal")).await;
        return;
    };
    let name = std::path::Path::new(&target.pw.shell).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut cmd = Command::new(&target.pw.shell);
    cmd.arg0(format!("-{name}")).stdin(i).stdout(o).stderr(e);
    // own session with the terminal as its controlling one: this is what makes Ctrl-C reach the foreground program
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    prepare(&mut cmd, &target);
    cmd.env("TERM", term).env("SHELL", &target.pw.shell);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            let _ = tx.send(error_frame(id, 6, "cannot start the shell")).await;
            return;
        }
    };
    drop(slave);
    drop(cmd);
    let pid = child.id().unwrap_or(0) as i32;
    let mut group = ProcessGroup::new(child.id());
    let Ok(fd) = AsyncFd::new(Master(master)) else { return };
    let mut buf = vec![0u8; CHUNK];
    let mut exited: Option<std::process::ExitStatus> = None;
    loop {
        tokio::select! {
            r = fd.readable() => {
                let Ok(mut g) = r else { break };
                match g.try_io(|f| {
                    let n = unsafe { libc::read(f.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                    if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
                }) {
                    Ok(Ok(0)) | Ok(Err(_)) => break, // EIO: nobody holds the other side any more
                    Ok(Ok(n)) => {
                        if tx.send(Frame::new(wire::PTY_OUT, 0, with_id(id, &buf[..n]))).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => continue, // would block
                }
            }
            c = cmds.recv() => match c {
                Some(PtyCmd::Input(bytes)) => {
                    if write_all(&fd, &bytes).await.is_err() {
                        break;
                    }
                }
                Some(PtyCmd::Resize(r, c)) => {
                    let ws = winsize(r, c);
                    unsafe { libc::ioctl(fd.get_ref().0.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
                }
                Some(PtyCmd::Hangup) | None => break,
            },
            st = child.wait(), if exited.is_none() => {
                exited = st.ok();
                // the shell is gone; what it printed last is still in the pipe: read it out, but do not wait for stragglers that keep the terminal open
                drain(&fd, &mut buf, id, &tx).await;
                break;
            }
        }
    }
    // hangup, then kill: nothing started in this session may outlive it
    if pid > 0 && exited.is_none() {
        unsafe { libc::kill(-pid, libc::SIGHUP) };
        match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
            Ok(st) => exited = st.ok(),
            Err(_) => {
                group.kill();
                exited = child.wait().await.ok();
            }
        }
    } else if pid > 0 {
        unsafe { libc::kill(-pid, libc::SIGHUP) }; // background jobs of an ended shell
    }
    group.kill(); // also stop descendants after a shell that has already exited
    let code = exited.map(|s| s.code().unwrap_or_else(|| 128 + std::os::unix::process::ExitStatusExt::signal(&s).unwrap_or(0))).unwrap_or(-1);
    let _ = tx.send(Frame::new(wire::PTY_EXIT, 0, with_id(id, &code.to_be_bytes()))).await;
}

async fn drain(fd: &AsyncFd<Master>, buf: &mut [u8], id: u64, tx: &mpsc::Sender<Frame>) {
    loop {
        let Ok(Ok(mut g)) = tokio::time::timeout(Duration::from_millis(150), fd.readable()).await else { return };
        match g.try_io(|f| {
            let n = unsafe { libc::read(f.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
        }) {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(n)) => {
                if tx.send(Frame::new(wire::PTY_OUT, 0, with_id(id, &buf[..n]))).await.is_err() {
                    return;
                }
            }
            Err(_) => {}
        }
    }
}

/// writes everything, or gives up after two seconds of a program that does not read (typed-ahead input must not stall the whole session)
async fn write_all(fd: &AsyncFd<Master>, mut data: &[u8]) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !data.is_empty() {
        let mut g = tokio::time::timeout_at(deadline, fd.writable()).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
        match g.try_io(|f| {
            let n = unsafe { libc::write(f.as_raw_fd(), data.as_ptr().cast(), data.len()) };
            if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
        }) {
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(e)) => return Err(e),
            Err(_) => {}
        }
    }
    Ok(())
}
