//! The file side of a transfer runs in a small helper process that has been given the identity of the account (the same `prepare` as for commands),
//! so the operating system, not our code, decides what may be read or written. `yrld fs-helper` is that process; it talks to the server over its pipes:
//!   in : `PUT <mode octal> <size> <hex blake3> <hex path>\n` then exactly (size - offset) bytes     out: `OFFSET <n>\n` ... `OK\n` | `ERR <code>\n`
//!   in : `GET <offset> <hex path>\n`                                                                 out: `SIZE <n>\n` + (n - offset) bytes + `HASH <hex>\n` | `ERR <code>\n`
//! The final file appears only by rename of `<path>.yrl-part` after the hash of the whole part file matched; the part file is opened without following symbolic links.
use crate::filewire::{CHUNK, E_IO, E_OFFSET, E_OPEN, E_REQUEST, E_TOO_BIG, E_VERIFY};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

pub const MAX_FILE_SIZE: u64 = 1 << 40;

fn hex_path(h: &str) -> Option<PathBuf> {
    let b = hex::decode(h).ok()?;
    if b.is_empty() || b.len() > crate::filewire::MAX_PATH || b.contains(&0) {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(b)))
}

fn part_of(p: &PathBuf) -> PathBuf {
    let mut s = p.clone().into_os_string();
    s.push(".yrl-part");
    PathBuf::from(s)
}

fn hash_prefix(f: &mut File, len: u64, h: &mut blake3::Hasher) -> std::io::Result<()> {
    f.seek(SeekFrom::Start(0))?;
    let mut left = len;
    let mut buf = vec![0u8; 1 << 20];
    while left > 0 {
        let want = (buf.len() as u64).min(left) as usize;
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        h.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(())
}

pub fn main() -> i32 {
    let stdin = std::io::stdin();
    let mut input = std::io::BufReader::with_capacity(1 << 20, stdin.lock());
    let mut line = String::new();
    if input.read_line(&mut line).unwrap_or(0) == 0 || line.len() > 10_000 {
        return 2;
    }
    let f: Vec<&str> = line.trim_end().split(' ').collect();
    let mut out = std::io::stdout().lock();
    let code = match (f.first().copied(), f.len()) {
        (Some("PUT"), 5) => put(&f, &mut input, &mut out),
        (Some("GET"), 3) => get(&f, &mut out),
        (Some("LS" | "STAT" | "RM" | "REAL"), 2) | (Some("MKDIR" | "MV"), 3) => crate::fsops::helper_command(&f, &mut out),
        _ => Err(E_REQUEST),
    };
    if let Err(c) = code {
        let _ = writeln!(out, "ERR {c}");
    }
    let _ = out.flush();
    0
}

fn put(f: &[&str], input: &mut impl Read, out: &mut impl Write) -> Result<(), u16> {
    let mode = u32::from_str_radix(f[1], 8).map_err(|_| E_REQUEST)? & 0o777; // no setuid, setgid or sticky bit from the network
    let size: u64 = f[2].parse().map_err(|_| E_REQUEST)?;
    let want: [u8; 32] = hex::decode(f[3]).ok().and_then(|v| v.try_into().ok()).ok_or(E_REQUEST)?;
    let path = hex_path(f[4]).ok_or(E_REQUEST)?;
    if size > MAX_FILE_SIZE {
        return Err(E_TOO_BIG);
    }
    let part = part_of(&path);
    let mut file = match OpenOptions::new().read(true).write(true).create(true).custom_flags(libc::O_NOFOLLOW).mode(0o600).open(&part) {
        Ok(f) => f,
        Err(_) => return Err(E_OPEN),
    };
    let meta = file.metadata().map_err(|_| E_IO)?;
    // only a regular file of ours is resumed: not a device, not somebody else's file
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } {
        return Err(E_OPEN);
    }
    let have = if meta.len() > size { 0 } else { meta.len() };
    if have == 0 {
        file.set_len(0).map_err(|_| E_IO)?;
    }
    file.seek(SeekFrom::Start(have)).map_err(|_| E_IO)?;
    writeln!(out, "OFFSET {have}").and_then(|_| out.flush()).map_err(|_| E_IO)?;
    let mut left = size - have;
    let mut buf = vec![0u8; CHUNK];
    while left > 0 {
        let n = input.read(&mut buf[..(CHUNK as u64).min(left) as usize]).map_err(|_| E_IO)?;
        if n == 0 {
            return Err(E_VERIFY); // the sender went away: what arrived stays for a resume
        }
        file.write_all(&buf[..n]).map_err(|_| E_IO)?;
        left -= n as u64;
    }
    file.sync_data().map_err(|_| E_IO)?;
    let mut h = blake3::Hasher::new();
    hash_prefix(&mut file, size, &mut h).map_err(|_| E_IO)?;
    if *h.finalize().as_bytes() != want {
        let _ = fs::remove_file(&part);
        return Err(E_VERIFY);
    }
    file.set_permissions(fs::Permissions::from_mode(mode)).map_err(|_| E_IO)?;
    fs::rename(&part, &path).map_err(|_| E_IO)?;
    writeln!(out, "OK").map_err(|_| E_IO)
}

fn get(f: &[&str], out: &mut impl Write) -> Result<(), u16> {
    let offset: u64 = f[1].parse().map_err(|_| E_REQUEST)?;
    let path = hex_path(f[2]).ok_or(E_REQUEST)?;
    let mut file = File::open(&path).map_err(|_| E_OPEN)?;
    let meta = file.metadata().map_err(|_| E_IO)?;
    if !meta.is_file() {
        return Err(E_OPEN);
    }
    let size = meta.len();
    if offset > size {
        return Err(E_OFFSET);
    }
    writeln!(out, "SIZE {size}").map_err(|_| E_IO)?;
    let mut h = blake3::Hasher::new();
    hash_prefix(&mut file, offset, &mut h).map_err(|_| E_IO)?;
    let mut left = size - offset;
    let mut buf = vec![0u8; 1 << 20];
    while left > 0 {
        let want = (buf.len() as u64).min(left) as usize;
        let n = file.read(&mut buf[..want]).map_err(|_| E_IO)?;
        if n == 0 {
            return Err(E_IO); // the file got shorter while it was being read
        }
        h.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|_| E_IO)?;
        left -= n as u64;
    }
    writeln!(out, "HASH {}", hex::encode(h.finalize().as_bytes())).map_err(|_| E_IO)
}
