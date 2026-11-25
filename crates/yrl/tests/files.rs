//! File transfer: integrity, resume, atomic appearance, symlink safety, limits.
mod common;
use common::*;
use std::path::{Path, PathBuf};
use std::time::Duration;
use yrl::client::{Client, ServerError};
use yrl::filewire::{self as fw, GetReq, PutReq};
use yrl::wire::{self, Frame};

const W: Duration = Duration::from_secs(60);

async fn frig() -> Rig {
    rig("exec,root,shell,files,tunnel").await
}

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect()
}

fn path_bytes(p: &Path) -> Vec<u8> {
    p.to_str().unwrap().as_bytes().to_vec()
}

fn code(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<ServerError>().map(|s| s.0)
}

fn part(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".yrl-part");
    s.into()
}

#[tokio::test]
async fn f1_files_of_every_size_go_there_and_back_identical() {
    let r = frig().await;
    let c = open(&r).await;
    let d = r.dir.path();
    for (i, n) in [0usize, 1, fw::CHUNK - 1, fw::CHUNK, fw::CHUNK + 1, 3 * fw::CHUNK, 5_000_003].into_iter().enumerate() {
        let src = d.join(format!("src{i}"));
        std::fs::write(&src, data(n, i as u64 + 7)).unwrap();
        let remote = d.join(format!("remote{i}"));
        let t = c.put_file(&src, &path_bytes(&remote), 0o640, W).await.unwrap();
        assert_eq!((t.bytes, t.resumed_from), (n as u64, 0));
        assert_eq!(std::fs::read(&remote).unwrap(), std::fs::read(&src).unwrap(), "size {n} uploaded");
        assert!(!part(&remote).exists(), "no part file is left");
        let back = d.join(format!("back{i}"));
        let t = c.get_file(&path_bytes(&remote), &back, W).await.unwrap();
        assert_eq!((t.bytes, t.resumed_from), (n as u64, 0));
        assert_eq!(std::fs::read(&back).unwrap(), std::fs::read(&src).unwrap(), "size {n} downloaded");
        assert!(!part(&back).exists());
    }
}

#[tokio::test]
async fn f2_without_the_files_right_nothing_is_written_or_read() {
    let r = rig("exec,shell").await; // the key does not carry 'files'
    let c = open(&r).await;
    let d = r.dir.path();
    std::fs::write(d.join("src"), b"x").unwrap();
    std::fs::write(d.join("secret"), b"secret").unwrap();
    let e = c.put_file(&d.join("src"), &path_bytes(&d.join("dst")), 0o600, W).await.unwrap_err();
    assert_eq!(code(&e), Some(1));
    assert!(!d.join("dst").exists() && !part(&d.join("dst")).exists());
    let e = c.get_file(&path_bytes(&d.join("secret")), &d.join("got"), W).await.unwrap_err();
    assert_eq!(code(&e), Some(1));
    assert!(!d.join("got").exists());
}

#[tokio::test]
async fn f3_a_wrong_hash_never_replaces_the_target() {
    let r = frig().await;
    let c = open(&r).await;
    let d = r.dir.path();
    let (src, dst) = (d.join("src"), d.join("dst"));
    std::fs::write(&src, data(200_000, 1)).unwrap();
    std::fs::write(&dst, b"the old, good content").unwrap();
    let e = c.put_file_claiming(&src, &path_bytes(&dst), 0o600, 200_000, [7u8; 32], W).await.unwrap_err();
    assert_eq!(code(&e), Some(fw::E_VERIFY));
    assert_eq!(std::fs::read(&dst).unwrap(), b"the old, good content", "the target is untouched");
    assert!(!part(&dst).exists(), "a part file that failed verification is removed");
    // a size that lies (smaller than the real file) means the hash cannot match either
    let e = c.put_file_claiming(&src, &path_bytes(&dst), 0o600, 100, blake3::hash(b"x").into(), W).await.unwrap_err();
    assert_eq!(code(&e), Some(fw::E_VERIFY), "more data than announced");
    assert_eq!(std::fs::read(&dst).unwrap(), b"the old, good content");
}

#[tokio::test]
async fn f4_an_interrupted_upload_continues_and_sends_only_the_rest() {
    let r = frig().await;
    let d = r.dir.path();
    let (src, dst) = (d.join("src"), d.join("dst"));
    let bytes = data(1_000_000, 4);
    std::fs::write(&src, &bytes).unwrap();
    // first attempt: send about half by hand and vanish
    {
        let (mut s, sec) = raw(&r).await;
        raw_login(&mut s, &sec, "anna", PW).await;
        let req = PutReq { id: 1, mode: 0o600, size: 1_000_000, hash: blake3::hash(&bytes).into(), path: path_bytes(&dst) };
        send(&mut s, &sec, Frame::new(fw::FILE_PUT, 0, req.encode().unwrap())).await;
        assert_eq!(recv(&mut s, &sec).await.map(|f| f.kind), Some(fw::FILE_READY));
        for ch in bytes[..500_000].chunks(fw::CHUNK) {
            send(&mut s, &sec, Frame::new(fw::FILE_DATA, 0, wire::with_id(1, ch))).await;
        }
    } // connection dropped
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!dst.exists(), "an unfinished upload never appears as the file");
    let have = std::fs::metadata(part(&dst)).unwrap().len();
    assert!(have > 0 && have <= 500_000, "the part file holds what arrived: {have}");
    let c = open(&r).await;
    let t = c.put_file(&src, &path_bytes(&dst), 0o600, W).await.unwrap();
    assert_eq!(t.resumed_from, have);
    assert_eq!(t.bytes, 1_000_000 - have, "only the rest went over the link");
    assert_eq!(std::fs::read(&dst).unwrap(), bytes);
}

#[tokio::test]
async fn f5_download_resumes_and_a_corrupted_partial_copy_is_caught() {
    let r = frig().await;
    let c = open(&r).await;
    let d = r.dir.path();
    let (remote, local) = (d.join("remote"), d.join("local"));
    let bytes = data(900_000, 5);
    std::fs::write(&remote, &bytes).unwrap();
    std::fs::write(part(&local), &bytes[..400_000]).unwrap();
    let t = c.get_file(&path_bytes(&remote), &local, W).await.unwrap();
    assert_eq!((t.resumed_from, t.bytes), (400_000, 500_000));
    assert_eq!(std::fs::read(&local).unwrap(), bytes);
    // a partial copy with one wrong byte: the final check must catch it and drop it
    let local2 = d.join("local2");
    let mut bad = bytes[..400_000].to_vec();
    bad[1234] ^= 0x55;
    std::fs::write(part(&local2), &bad).unwrap();
    let e = c.get_file(&path_bytes(&remote), &local2, W).await.unwrap_err();
    assert!(e.to_string().contains("does not match"), "{e}");
    assert!(!local2.exists() && !part(&local2).exists(), "nothing wrong is left behind");
    let t = c.get_file(&path_bytes(&remote), &local2, W).await.unwrap();
    assert_eq!(t.resumed_from, 0);
    assert_eq!(std::fs::read(&local2).unwrap(), bytes, "and the next try is clean");
    // a partial copy longer than the file: start over
    let local3 = d.join("local3");
    std::fs::write(part(&local3), data(2_000_000, 9)).unwrap();
    let t = c.get_file(&path_bytes(&remote), &local3, W).await.unwrap();
    assert_eq!(t.resumed_from, 0);
    assert_eq!(std::fs::read(&local3).unwrap(), bytes);
}

#[tokio::test]
async fn f6_wrong_amounts_of_data_are_errors_and_nothing_appears() {
    let r = frig().await;
    let d = r.dir.path();
    for (name, announce, send_n, end) in [("more", 100u64, 200usize, true), ("less", 100, 40, true)] {
        let dst = d.join(name);
        let (mut s, sec) = raw(&r).await;
        raw_login(&mut s, &sec, "anna", PW).await;
        let content = vec![9u8; announce as usize];
        let req = PutReq { id: 1, mode: 0o600, size: announce, hash: blake3::hash(&content).into(), path: path_bytes(&dst) };
        send(&mut s, &sec, Frame::new(fw::FILE_PUT, 0, req.encode().unwrap())).await;
        assert_eq!(recv(&mut s, &sec).await.map(|f| f.kind), Some(fw::FILE_READY));
        send(&mut s, &sec, Frame::new(fw::FILE_DATA, 0, wire::with_id(1, &vec![9u8; send_n]))).await;
        if end {
            send(&mut s, &sec, Frame::new(fw::FILE_END, 0, wire::with_id(1, &[]))).await;
        }
        let f = recv(&mut s, &sec).await.expect("an answer");
        assert_eq!(f.kind, wire::ERROR, "{name}");
        assert!(!dst.exists(), "{name}: the file must not appear");
    }
}

#[tokio::test]
async fn f7_symbolic_links_cannot_be_used_to_write_elsewhere() {
    let r = frig().await;
    let c = open(&r).await;
    let d = r.dir.path();
    let (src, victim, dst) = (d.join("src"), d.join("victim"), d.join("dst"));
    std::fs::write(&src, b"attacker content").unwrap();
    std::fs::write(&victim, b"precious").unwrap();
    // the part file name is a link to the victim
    std::os::unix::fs::symlink(&victim, part(&dst)).unwrap();
    let e = c.put_file(&src, &path_bytes(&dst), 0o600, W).await.unwrap_err();
    assert_eq!(code(&e), Some(fw::E_OPEN));
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
    std::fs::remove_file(part(&dst)).unwrap();
    // the target is a link to the victim: the link is replaced, the victim is not written
    std::os::unix::fs::symlink(&victim, &dst).unwrap();
    c.put_file(&src, &path_bytes(&dst), 0o600, W).await.unwrap();
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious", "the victim behind the link is intact");
    assert_eq!(std::fs::read(&dst).unwrap(), b"attacker content");
    assert!(!std::fs::symlink_metadata(&dst).unwrap().file_type().is_symlink());
    // a directory or a device is not a file to download
    let e = c.get_file(&path_bytes(d), &d.join("x"), W).await.unwrap_err();
    assert_eq!(code(&e), Some(fw::E_OPEN));
    let e = c.get_file(b"/dev/zero", &d.join("z"), W).await.unwrap_err();
    assert_eq!(code(&e), Some(fw::E_OPEN));
}

#[tokio::test]
async fn f8_modes_are_masked_and_unreadable_files_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let r = frig().await;
    let c = open(&r).await;
    let d = r.dir.path();
    let (src, dst) = (d.join("src"), d.join("dst"));
    std::fs::write(&src, b"x").unwrap();
    c.put_file(&src, &path_bytes(&dst), 0o6755, W).await.unwrap();
    assert_eq!(std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777, 0o755, "setuid and setgid are not taken from the network");
    c.put_file(&src, &path_bytes(&dst), 0o1777, W).await.unwrap();
    assert_eq!(std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777, 0o777 & 0o777);
    let locked = d.join("locked");
    std::fs::write(&locked, b"no").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0)).unwrap();
    if unsafe { libc::geteuid() } != 0 {
        let e = c.get_file(&path_bytes(&locked), &d.join("g"), W).await.unwrap_err();
        assert_eq!(code(&e), Some(fw::E_OPEN), "the operating system decides");
    }
    let e = c.get_file(&path_bytes(&d.join("missing")), &d.join("g"), W).await.unwrap_err();
    assert_eq!(code(&e), Some(fw::E_OPEN));
    let e = c.put_file(&src, &path_bytes(&d.join("no-such-dir/x")), 0o600, W).await.unwrap_err();
    assert_eq!(code(&e), Some(fw::E_OPEN));
}

#[tokio::test]
async fn f9_odd_paths_are_data_not_commands() {
    let r = frig().await;
    let c = open(&r).await;
    let d = r.dir.path();
    let src = d.join("src");
    std::fs::write(&src, b"hello").unwrap();
    // a name with spaces, a newline and a protocol-looking text: it is hex on the way to the helper
    let odd = d.join("a b\nGET 0 deadbeef\n\"quote'; rm -rf x");
    c.put_file(&src, &path_bytes(&odd), 0o600, W).await.unwrap();
    assert_eq!(std::fs::read(&odd).unwrap(), b"hello");
    let names: Vec<_> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert!(names.iter().all(|n| !n.to_string_lossy().ends_with("deadbeef")), "no second file from an injected line");
    // refused before they leave the client or at the server's decoder
    for bad in [&b""[..], b"a\0b", &[b'a'; 4097]] {
        assert!(c.put_file(&src, bad, 0o600, W).await.is_err());
        assert!(c.get_file(bad, &d.join("o"), W).await.is_err());
    }
}

#[tokio::test]
async fn f10_size_and_count_limits() {
    let r = rig_with("exec,shell,files", |mut c| { c.max_file_size = 1000; c.max_transfers_per_connection = 1; c }).await;
    let d = r.dir.path();
    let c = open(&r).await;
    std::fs::write(d.join("big"), data(1001, 3)).unwrap();
    std::fs::write(d.join("ok"), data(1000, 3)).unwrap();
    let e = c.put_file(&d.join("big"), &path_bytes(&d.join("o1")), 0o600, W).await.unwrap_err();
    assert_eq!(code(&e), Some(fw::E_TOO_BIG));
    assert!(!d.join("o1").exists() && !part(&d.join("o1")).exists());
    c.put_file(&d.join("ok"), &path_bytes(&d.join("o2")), 0o600, W).await.unwrap();
    // a second transfer while the first one is still open is refused
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let mk = |id| PutReq { id, mode: 0o600, size: 10, hash: [0; 32], path: path_bytes(&d.join(format!("p{id}"))) }.encode().unwrap();
    send(&mut s, &sec, Frame::new(fw::FILE_PUT, 0, mk(1))).await;
    assert_eq!(recv(&mut s, &sec).await.map(|f| f.kind), Some(fw::FILE_READY));
    send(&mut s, &sec, Frame::new(fw::FILE_PUT, 0, mk(2))).await;
    let f = recv(&mut s, &sec).await.unwrap();
    assert_eq!((f.kind, &f.payload[8..10]), (wire::ERROR, &5u16.to_be_bytes()[..]));
    send(&mut s, &sec, Frame::new(fw::FILE_PUT, 0, mk(1))).await; // same id again
    let f = recv(&mut s, &sec).await.unwrap();
    assert_eq!(f.kind, wire::ERROR);
}

#[tokio::test]
async fn f11_nothing_works_before_the_login_and_garbage_frames_are_harmless() {
    let r = frig().await;
    let d = r.dir.path();
    let put = PutReq { id: 1, mode: 0o600, size: 0, hash: *blake3::hash(b"").as_bytes(), path: path_bytes(&d.join("pre")) }.encode().unwrap();
    for (kind, payload) in [(fw::FILE_PUT, put.clone()), (fw::FILE_GET, GetReq { id: 1, offset: 0, path: b"/etc/passwd".to_vec() }.encode().unwrap()), (fw::FILE_DATA, wire::with_id(1, b"x"))] {
        let (mut s, sec) = raw(&r).await;
        send(&mut s, &sec, Frame::new(kind, 0, payload)).await;
        assert!(recv(&mut s, &sec).await.is_none());
    }
    assert!(!d.join("pre").exists());
    // after the login: frames for ids that do not exist are ignored, malformed ones end the session
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    for k in [fw::FILE_DATA, fw::FILE_END, fw::FILE_ABORT] {
        send(&mut s, &sec, Frame::new(k, 0, wire::with_id(999, b"zz"))).await;
    }
    send(&mut s, &sec, Frame::new(wire::PING, 0, b"alive".to_vec())).await;
    assert_eq!(recv(&mut s, &sec).await.map(|f| f.payload), Some(b"alive".to_vec()));
    send(&mut s, &sec, Frame::new(fw::FILE_PUT, 0, vec![1, 2, 3])).await;
    send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
    assert!(recv(&mut s, &sec).await.is_none());
}

#[test]
fn f12_codecs_are_exact_and_never_panic() {
    let p = PutReq { id: 5, mode: 0o644, size: 99, hash: [3; 32], path: b"/a/b".to_vec() };
    let e = p.encode().unwrap();
    assert_eq!(PutReq::decode(&e).unwrap(), p);
    let mut longer = e.clone();
    longer.push(0);
    assert!(PutReq::decode(&longer).is_err() && PutReq::decode(&e[..e.len() - 1]).is_err() && PutReq::decode(&e[..51]).is_err());
    let g = GetReq { id: 6, offset: u64::MAX, path: b"x".to_vec() };
    let e = g.encode().unwrap();
    assert_eq!(GetReq::decode(&e).unwrap(), g);
    let mut z = e.clone();
    z[18] = 0; // a NUL inside the path
    assert!(GetReq::decode(&z).is_err());
    assert!(GetReq::decode(&e[..17]).is_err());
    let mut zero = PutReq { path: b"a".to_vec(), ..p }.encode().unwrap();
    zero[50] = 0;
    zero[51] = 0; // declared empty path
    zero.truncate(52);
    assert!(PutReq::decode(&zero).is_err());
    let mut x = 77u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..30_000 {
        let b: Vec<u8> = (0..(rnd() % 120) as usize).map(|_| rnd() as u8).collect();
        let _ = PutReq::decode(&b);
        let _ = GetReq::decode(&b);
    }
}

#[tokio::test]
async fn f13_throughput_on_the_loopback_is_reported_and_sane() {
    let r = frig().await;
    let c = open(&r).await;
    let d = r.dir.path();
    let n = 64 << 20;
    std::fs::write(d.join("big"), data(n, 11)).unwrap();
    let t = std::time::Instant::now();
    c.put_file(&d.join("big"), &path_bytes(&d.join("big2")), 0o600, W).await.unwrap();
    let up = n as f64 / 1048576.0 / t.elapsed().as_secs_f64();
    let t = std::time::Instant::now();
    c.get_file(&path_bytes(&d.join("big2")), &d.join("big3"), W).await.unwrap();
    let down = n as f64 / 1048576.0 / t.elapsed().as_secs_f64();
    eprintln!("[throughput] upload {up:.0} MiB/s, download {down:.0} MiB/s (64 MiB, loopback, test build)");
    assert!(up > 20.0 && down > 20.0, "far too slow: {up:.1} / {down:.1} MiB/s");
    assert_eq!(std::fs::read(d.join("big3")).unwrap().len(), n);
}

#[tokio::test]
async fn f14_a_dead_link_in_the_middle_of_a_download_leaves_the_server_healthy() {
    let r = frig().await;
    let d = r.dir.path();
    std::fs::write(d.join("big"), data(30 << 20, 12)).unwrap();
    {
        let (mut s, sec) = raw(&r).await;
        raw_login(&mut s, &sec, "anna", PW).await;
        let req = GetReq { id: 1, offset: 0, path: path_bytes(&d.join("big")) }.encode().unwrap();
        send(&mut s, &sec, Frame::new(fw::FILE_GET, 0, req)).await;
        assert_eq!(recv(&mut s, &sec).await.map(|f| f.kind), Some(fw::FILE_READY));
        recv(&mut s, &sec).await; // one chunk, then the client vanishes
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let c = open(&r).await;
    c.get_file(&path_bytes(&d.join("big")), &d.join("got"), W).await.unwrap();
    assert_eq!(std::fs::metadata(d.join("got")).unwrap().len(), 30 << 20);
    let _ = Client::connect; // keep the import used
}

#[test]
fn f15_the_helper_defends_itself_even_if_the_server_did_not() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let run = |input: &[u8]| {
        let mut ch = Command::new(env!("CARGO_BIN_EXE_yrld")).arg("fs-helper").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let _ = ch.stdin.take().unwrap().write_all(input);
        let o = ch.wait_with_output().unwrap();
        (o.status.code(), String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let d = tempfile::tempdir().unwrap();
    let hexp = hex::encode(d.path().join("x").to_str().unwrap());
    let zero = "0".repeat(64);
    assert_eq!(run(format!("PUT 600 {} {zero} {hexp}\n", (1u64 << 40) + 1).as_bytes()), (Some(0), format!("ERR {}", fw::E_TOO_BIG)));
    assert!(!d.path().join("x.yrl-part").exists(), "refused before anything was created");
    for bad in ["", "\n", "HELLO\n", "PUT\n", "PUT 600 1 zz 00\n", "PUT 9 1 00 00\n", "GET x y\n", "GET 0 \n", "GET 0 00\n", "GET 0 zz\n", "PUT 600 -1 aa bb\n"] {
        let (code, out) = run(bad.as_bytes());
        assert!(code == Some(0) || code == Some(2), "{bad:?}: no crash ({code:?})");
        assert!(out.is_empty() || out.starts_with("ERR "), "{bad:?}: {out}");
    }
    assert_eq!(run(format!("GET 0 {}\n", hex::encode(d.path().join("nothing").to_str().unwrap())).as_bytes()).1, format!("ERR {}", fw::E_OPEN));
    std::fs::write(d.path().join("f"), b"12345").unwrap();
    assert_eq!(run(format!("GET 9 {}\n", hex::encode(d.path().join("f").to_str().unwrap())).as_bytes()).1, format!("ERR {}", fw::E_OFFSET));
    let (_, out) = run(format!("GET 5 {}\n", hex::encode(d.path().join("f").to_str().unwrap())).as_bytes());
    assert!(out.starts_with("SIZE 5\nHASH ") || out.starts_with("SIZE 5\r\nHASH ") || out.contains("SIZE 5"), "{out}");
}
