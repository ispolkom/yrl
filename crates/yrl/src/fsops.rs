//! Directory operations for the visual mode: list, stat, make a directory, remove (a file or an EMPTY directory), rename (never over an existing name).
//! Like file transfers they run in the helper process under the account's identity, so the operating system decides what is allowed.
//! REQ  `[id u64][op u8][a_len u16][a][b_len u16][b]` exact;  RESP `[id][count u16]` + entries;  DONE `[id]`.
//! Entry: `[kind u8: 0 file, 1 dir, 2 symlink, 3 other][size u64][mtime i64][mode u16][name_len u16][name]`
use crate::exec::prepare;
use crate::filewire::{E_IO, E_OPEN, E_REQUEST, E_TOO_BIG, MAX_PATH};
use crate::identity::Target;
use crate::wire::{self, with_id, Frame, WireError};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub const FS_REQ: u8 = 50;
pub const FS_RESP: u8 = 51;
pub const FS_DONE: u8 = 52;

pub const OP_LS: u8 = 1;
pub const OP_STAT: u8 = 2;
pub const OP_MKDIR: u8 = 3;
pub const OP_RM: u8 = 4;
pub const OP_MV: u8 = 5;
/// the canonical absolute path of a path (links resolved), as the name of one entry
pub const OP_REAL: u8 = 6;

pub const E_EXISTS: u16 = 16;
pub const E_NOTEMPTY: u16 = 17;
pub const MAX_ENTRIES: usize = 100_000;
const MAX_NAME: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub kind: Kind,
    pub size: u64,
    pub mtime: i64,
    pub mode: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FsReq {
    pub id: u64,
    pub op: u8,
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}

fn path_ok(p: &[u8]) -> bool {
    !p.is_empty() && p.len() <= MAX_PATH && !p.contains(&0)
}

impl FsReq {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let b_needed = matches!(self.op, OP_MKDIR | OP_MV);
        if !(OP_LS..=OP_REAL).contains(&self.op) || !path_ok(&self.a) || self.b.len() > MAX_PATH || (b_needed && self.b.is_empty()) || (!b_needed && !self.b.is_empty()) || self.b.contains(&0) {
            return Err(WireError::TooLarge);
        }
        let mut v = with_id(self.id, &[self.op]);
        v.extend_from_slice(&(self.a.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.a);
        v.extend_from_slice(&(self.b.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.b);
        Ok(v)
    }
    pub fn decode(b: &[u8]) -> Result<FsReq, WireError> {
        if b.len() < 13 {
            return Err(WireError::Short);
        }
        let (id, op) = (u64::from_be_bytes(b[..8].try_into().unwrap()), b[8]);
        let al = u16::from_be_bytes([b[9], b[10]]) as usize;
        if al > MAX_PATH || b.len() < 11 + al + 2 {
            return Err(if al > MAX_PATH { WireError::TooLarge } else { WireError::Short });
        }
        let a = b[11..11 + al].to_vec();
        let bl = u16::from_be_bytes([b[11 + al], b[12 + al]]) as usize;
        if bl > MAX_PATH {
            return Err(WireError::TooLarge);
        }
        if b.len() != 13 + al + bl {
            return Err(WireError::Malformed);
        }
        let bb = b[13 + al..].to_vec();
        let r = FsReq { id, op, a, b: bb };
        r.encode().map_err(|_| WireError::Malformed)?; // the same rules in both directions
        Ok(r)
    }
}

pub fn encode_entries(id: u64, entries: &[DirEntry]) -> Vec<u8> {
    let mut v = with_id(id, &(entries.len() as u16).to_be_bytes());
    for e in entries {
        v.push(match e.kind {
            Kind::File => 0,
            Kind::Dir => 1,
            Kind::Symlink => 2,
            Kind::Other => 3,
        });
        v.extend_from_slice(&e.size.to_be_bytes());
        v.extend_from_slice(&e.mtime.to_be_bytes());
        v.extend_from_slice(&e.mode.to_be_bytes());
        v.extend_from_slice(&(e.name.len() as u16).to_be_bytes());
        v.extend_from_slice(&e.name);
    }
    v
}

/// payload after the id; every length is checked before anything is taken
pub fn decode_entries(b: &[u8]) -> Result<Vec<DirEntry>, WireError> {
    if b.len() < 2 {
        return Err(WireError::Short);
    }
    let n = u16::from_be_bytes([b[0], b[1]]) as usize;
    let mut at = 2;
    let mut out = Vec::with_capacity(n.min(256));
    for _ in 0..n {
        if b.len() < at + 21 {
            return Err(WireError::Short);
        }
        let kind = match b[at] {
            0 => Kind::File,
            1 => Kind::Dir,
            2 => Kind::Symlink,
            3 => Kind::Other,
            _ => return Err(WireError::Malformed),
        };
        let size = u64::from_be_bytes(b[at + 1..at + 9].try_into().unwrap());
        let mtime = i64::from_be_bytes(b[at + 9..at + 17].try_into().unwrap());
        let mode = u16::from_be_bytes([b[at + 17], b[at + 18]]);
        let nl = u16::from_be_bytes([b[at + 19], b[at + 20]]) as usize;
        if nl > MAX_NAME {
            return Err(WireError::TooLarge);
        }
        at += 21;
        if b.len() < at + nl {
            return Err(WireError::Short);
        }
        out.push(DirEntry { name: b[at..at + nl].to_vec(), kind, size, mtime, mode });
        at += nl;
    }
    if at != b.len() {
        return Err(WireError::Malformed);
    }
    Ok(out)
}

// ---------------------------------------------------------------- helper side (runs as the account's system user)

fn io_code(e: &std::io::Error) -> u16 {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound | PermissionDenied | NotADirectory | IsADirectory => E_OPEN,
        AlreadyExists => E_EXISTS,
        DirectoryNotEmpty => E_NOTEMPTY,
        _ => E_IO,
    }
}

fn entry_line(name: &std::ffi::OsStr, m: &std::fs::Metadata) -> String {
    let ft = m.file_type();
    let kind = if ft.is_symlink() {
        'l'
    } else if ft.is_dir() {
        'd'
    } else if ft.is_file() {
        'f'
    } else {
        'o'
    };
    format!("E {kind} {} {} {:o} {}", m.len(), m.mtime(), m.permissions().mode() & 0o7777, hex::encode(name.as_bytes()))
}

fn hex_path(h: &str) -> Option<std::path::PathBuf> {
    let b = hex::decode(h).ok()?;
    if !path_ok(&b) {
        return None;
    }
    Some(std::path::PathBuf::from(std::ffi::OsString::from_vec(b)))
}

/// `LS <hex path>` / `STAT <hex path>` / `MKDIR <mode> <hex path>` / `RM <hex path>` / `MV <hex from> <hex to>`
pub fn helper_command(f: &[&str], out: &mut impl Write) -> Result<(), u16> {
    match (f[0], f.len()) {
        ("LS", 2) => {
            let dir = hex_path(f[1]).ok_or(E_REQUEST)?;
            let rd = std::fs::read_dir(&dir).map_err(|e| io_code(&e))?;
            let mut n = 0usize;
            for item in rd {
                let item = item.map_err(|e| io_code(&e))?;
                let Ok(m) = std::fs::symlink_metadata(item.path()) else { continue }; // vanished meanwhile
                n += 1;
                if n > MAX_ENTRIES {
                    return Err(E_TOO_BIG);
                }
                writeln!(out, "{}", entry_line(&item.file_name(), &m)).map_err(|_| E_IO)?;
            }
            writeln!(out, "END").map_err(|_| E_IO)
        }
        ("STAT", 2) => {
            let p = hex_path(f[1]).ok_or(E_REQUEST)?;
            let m = std::fs::symlink_metadata(&p).map_err(|e| io_code(&e))?;
            let name = p.file_name().map(|n| n.to_os_string()).unwrap_or_else(|| p.clone().into_os_string());
            writeln!(out, "{}", entry_line(&name, &m)).map_err(|_| E_IO)?;
            writeln!(out, "END").map_err(|_| E_IO)
        }
        ("MKDIR", 3) => {
            let mode = u32::from_str_radix(f[1], 8).map_err(|_| E_REQUEST)? & 0o777;
            let p = hex_path(f[2]).ok_or(E_REQUEST)?;
            std::fs::create_dir(&p).map_err(|e| io_code(&e))?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).map_err(|e| io_code(&e))?;
            writeln!(out, "END").map_err(|_| E_IO)
        }
        ("REAL", 2) => {
            let p = hex_path(f[1]).ok_or(E_REQUEST)?;
            let canon = std::fs::canonicalize(&p).map_err(|e| io_code(&e))?;
            if canon.as_os_str().len() > MAX_NAME {
                return Err(E_TOO_BIG);
            }
            let m = std::fs::metadata(&canon).map_err(|e| io_code(&e))?;
            writeln!(out, "{}", entry_line(canon.as_os_str(), &m)).map_err(|_| E_IO)?;
            writeln!(out, "END").map_err(|_| E_IO)
        }
        ("RM", 2) => {
            let p = hex_path(f[1]).ok_or(E_REQUEST)?;
            let m = std::fs::symlink_metadata(&p).map_err(|e| io_code(&e))?;
            // a link is removed itself, never followed; a directory only when empty
            if m.file_type().is_dir() { std::fs::remove_dir(&p) } else { std::fs::remove_file(&p) }.map_err(|e| io_code(&e))?;
            writeln!(out, "END").map_err(|_| E_IO)
        }
        ("MV", 3) => {
            let (from, to) = (hex_path(f[1]).ok_or(E_REQUEST)?, hex_path(f[2]).ok_or(E_REQUEST)?);
            rename_noreplace(&from, &to)?;
            writeln!(out, "END").map_err(|_| E_IO)
        }
        _ => Err(E_REQUEST),
    }
}

/// the new name must not exist: atomically (renameat2 with RENAME_NOREPLACE), so two renames cannot silently overwrite each other
fn rename_noreplace(from: &Path, to: &Path) -> Result<(), u16> {
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| E_REQUEST);
    let (a, b) = (c(from)?, c(to)?);
    let r = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, a.as_ptr(), libc::AT_FDCWD, b.as_ptr(), 1u32 /* RENAME_NOREPLACE */) };
    if r == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EEXIST) | Some(libc::ENOTEMPTY) => Err(E_EXISTS),
        Some(libc::EINVAL) | Some(libc::ENOSYS) => {
            // a file system without RENAME_NOREPLACE: the best that can be done is to check first
            if std::fs::symlink_metadata(to).is_ok() {
                return Err(E_EXISTS);
            }
            std::fs::rename(from, to).map_err(|e| io_code(&e))
        }
        _ => Err(io_code(&e)),
    }
}

// ---------------------------------------------------------------- server side

fn err(id: u64, code: u16, text: &str) -> Frame {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(text.as_bytes());
    Frame::new(wire::ERROR, 0, with_id(id, &p))
}

fn code_text(code: u16) -> &'static str {
    match code {
        E_OPEN => "cannot open (missing, not a directory, or not allowed)",
        E_EXISTS => "that name already exists",
        E_NOTEMPTY => "the directory is not empty",
        E_TOO_BIG => "too many entries",
        E_REQUEST => "bad request",
        _ => "input/output error",
    }
}

fn parse_entry(line: &str) -> Option<DirEntry> {
    let f: Vec<&str> = line.strip_prefix("E ")?.split(' ').collect();
    if f.len() != 5 {
        return None;
    }
    let kind = match f[0] {
        "f" => Kind::File,
        "d" => Kind::Dir,
        "l" => Kind::Symlink,
        "o" => Kind::Other,
        _ => return None,
    };
    let name = hex::decode(f[4]).ok()?;
    if name.len() > MAX_NAME {
        return None;
    }
    Some(DirEntry { name, kind, size: f[1].parse().ok()?, mtime: f[2].parse().ok()?, mode: (u32::from_str_radix(f[3], 8).ok()? & 0o7777) as u16 })
}

pub async fn run(req: FsReq, target: Target, helper: std::path::PathBuf, tx: mpsc::Sender<Frame>, cgroup: Option<crate::cgroup::Attachment>) {
    let id = req.id;
    let hx = |b: &[u8]| hex::encode(b);
    let head = match req.op {
        OP_LS => format!("LS {}\n", hx(&req.a)),
        OP_STAT => format!("STAT {}\n", hx(&req.a)),
        OP_REAL => format!("REAL {}\n", hx(&req.a)),
        OP_MKDIR => format!("MKDIR {} {}\n", String::from_utf8_lossy(&req.b).chars().filter(|c| c.is_digit(8)).take(4).collect::<String>(), hx(&req.a)),
        OP_RM => format!("RM {}\n", hx(&req.a)),
        OP_MV => format!("MV {} {}\n", hx(&req.a), hx(&req.b)),
        _ => {
            let _ = tx.send(err(id, E_REQUEST, code_text(E_REQUEST))).await;
            return;
        }
    };
    let mut cmd = Command::new(&helper);
    cmd.arg("fs-helper").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    if let Some(cg) = &cgroup { crate::cgroup::SessionCgroup::attach(&mut cmd, cg); }
    prepare(&mut cmd, &target);
    let Ok(mut child) = cmd.spawn() else {
        let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
        return;
    };
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else { return };
    if stdin.write_all(head.as_bytes()).await.is_err() {
        let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
        return;
    }
    drop(stdin);
    let mut rd = BufReader::new(stdout);
    let mut batch: Vec<DirEntry> = vec![];
    let mut batch_bytes = 0usize;
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        // a line is short (a name is at most 1024 bytes, hex-encoded); a longer one is not ours
        let n = (&mut rd).take(4096).read_line(&mut line).await.unwrap_or(0);
        let line = line.trim_end();
        if n == 0 || (!line.is_empty() && !line.starts_with("E ") && line != "END" && !line.starts_with("ERR ")) {
            let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
            return;
        }
        if let Some(code) = line.strip_prefix("ERR ") {
            let c = code.parse().unwrap_or(E_IO);
            let _ = tx.send(err(id, c, code_text(c))).await;
            return;
        }
        if line == "END" {
            break;
        }
        let Some(e) = parse_entry(line) else {
            let _ = tx.send(err(id, E_IO, code_text(E_IO))).await;
            return;
        };
        total += 1;
        if total > MAX_ENTRIES {
            let _ = tx.send(err(id, E_TOO_BIG, code_text(E_TOO_BIG))).await;
            return;
        }
        batch_bytes += 21 + e.name.len();
        batch.push(e);
        if batch.len() >= 500 || batch_bytes > 40_000 {
            if tx.send(Frame::new(FS_RESP, 0, encode_entries(id, &batch))).await.is_err() {
                return;
            }
            batch.clear();
            batch_bytes = 0;
        }
    }
    if !batch.is_empty() && tx.send(Frame::new(FS_RESP, 0, encode_entries(id, &batch))).await.is_err() {
        return;
    }
    let _ = tx.send(Frame::new(FS_DONE, 0, with_id(id, &[]))).await;
}
