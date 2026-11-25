//! Directory operations (the base of the visual mode).
mod common;
use common::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use yrl::client::ServerError;
use yrl::filewire as fw;
use yrl::fsops::{self, decode_entries, encode_entries, DirEntry, FsReq, Kind};
use yrl::wire::{self, Frame};

const W: Duration = Duration::from_secs(20);

fn code(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<ServerError>().map(|s| s.0)
}
fn b(p: &Path) -> Vec<u8> {
    p.as_os_str().as_bytes().to_vec()
}

#[tokio::test]
async fn d1_a_listing_tells_files_directories_links_and_others_apart() {
    let r = rig("files").await;
    let c = open(&r).await;
    let d = r.dir.path().join("lst");
    std::fs::create_dir(&d).unwrap();
    std::fs::write(d.join("plain"), b"12345").unwrap();
    std::fs::set_permissions(d.join("plain"), std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::create_dir(d.join("sub")).unwrap();
    symlink(r.dir.path(), d.join("link-to-dir")).unwrap();
    symlink("/nonexistent/target", d.join("dangling")).unwrap();
    let fifo = std::ffi::CString::new(d.join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    // names that would break any text protocol: spaces, a newline, a quote, invalid UTF-8
    std::fs::write(d.join("a b"), b"").unwrap();
    std::fs::write(d.join("new\nline"), b"").unwrap();
    std::fs::write(d.join("q'\"x"), b"").unwrap();
    std::fs::write(d.join(std::ffi::OsStr::from_bytes(b"bad-\xff\xfe")), b"").unwrap();
    let mut es = c.fs_list(&b(&d), W).await.unwrap();
    es.sort_by(|a, b| a.name.cmp(&b.name));
    let find = |n: &[u8]| es.iter().find(|e| e.name == n).unwrap_or_else(|| panic!("{:?} missing in {:?}", String::from_utf8_lossy(n), es.iter().map(|e| String::from_utf8_lossy(&e.name).into_owned()).collect::<Vec<_>>())).clone();
    let plain = find(b"plain");
    assert_eq!((plain.kind, plain.size, plain.mode), (Kind::File, 5, 0o640));
    assert!(plain.mtime > 1_600_000_000);
    assert_eq!(find(b"sub").kind, Kind::Dir);
    assert_eq!(find(b"link-to-dir").kind, Kind::Symlink, "a link is shown as a link, never followed");
    assert_eq!(find(b"dangling").kind, Kind::Symlink);
    assert_eq!(find(b"fifo").kind, Kind::Other);
    for n in [&b"a b"[..], b"new\nline", b"q'\"x", b"bad-\xff\xfe"] {
        assert_eq!(find(n).kind, Kind::File, "{:?}", String::from_utf8_lossy(n));
    }
    assert_eq!(es.len(), 9, "nothing extra appeared from the odd names");
    // an empty directory, a missing one, a file instead of a directory
    std::fs::create_dir(d.join("empty")).unwrap();
    assert!(c.fs_list(&b(&d.join("empty")), W).await.unwrap().is_empty());
    assert_eq!(code(&c.fs_list(&b(&d.join("none")), W).await.unwrap_err()), Some(fw::E_OPEN));
    assert_eq!(code(&c.fs_list(&b(&d.join("plain")), W).await.unwrap_err()), Some(fw::E_OPEN));
}

#[tokio::test]
async fn d2_a_big_directory_arrives_whole() {
    let r = rig("files").await;
    let c = open(&r).await;
    let d = r.dir.path().join("big");
    std::fs::create_dir(&d).unwrap();
    for i in 0..3000 {
        std::fs::write(d.join(format!("file-{i:05}-{}", "x".repeat(40))), b"").unwrap();
    }
    let es = c.fs_list(&b(&d), W).await.unwrap();
    assert_eq!(es.len(), 3000);
    let mut names: Vec<_> = es.iter().map(|e| e.name.clone()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 3000, "no entry twice");
}

#[tokio::test]
async fn d3_stat_tells_about_one_path() {
    let r = rig("files").await;
    let c = open(&r).await;
    let d = r.dir.path();
    std::fs::write(d.join("f"), b"abc").unwrap();
    symlink(d.join("f"), d.join("l")).unwrap();
    let f = c.fs_stat(&b(&d.join("f")), W).await.unwrap();
    assert_eq!((f.name.as_slice(), f.kind, f.size), (&b"f"[..], Kind::File, 3));
    assert_eq!(c.fs_stat(&b(&d.join("l")), W).await.unwrap().kind, Kind::Symlink);
    assert_eq!(c.fs_stat(&b(d), W).await.unwrap().kind, Kind::Dir);
    assert_eq!(c.fs_stat(b"/", W).await.unwrap().kind, Kind::Dir);
    assert_eq!(code(&c.fs_stat(&b(&d.join("nope")), W).await.unwrap_err()), Some(fw::E_OPEN));
}

#[tokio::test]
async fn d3b_real_path_resolves_links_and_dots() {
    let r = rig("files").await;
    let c = open(&r).await;
    let d = std::fs::canonicalize(r.dir.path()).unwrap();
    std::fs::create_dir(d.join("sub")).unwrap();
    symlink(d.join("sub"), d.join("ln")).unwrap();
    assert_eq!(c.fs_real(&b(&d.join("ln/../sub/.")), W).await.unwrap(), b(&d.join("sub")));
    let home = c.fs_real(b".", W).await.unwrap();
    assert!(home.starts_with(b"/"), "the starting point is an absolute path: {:?}", String::from_utf8_lossy(&home));
    assert_eq!(code(&c.fs_real(&b(&d.join("none")), W).await.unwrap_err()), Some(fw::E_OPEN));
}

#[tokio::test]
async fn d4_mkdir_makes_one_directory_with_a_masked_mode() {
    let r = rig("files").await;
    let c = open(&r).await;
    let d = r.dir.path();
    c.fs_mkdir(&b(&d.join("new")), 0o700, W).await.unwrap();
    assert_eq!(std::fs::metadata(d.join("new")).unwrap().permissions().mode() & 0o7777, 0o700);
    c.fs_mkdir(&b(&d.join("wide")), 0o7777, W).await.unwrap();
    assert_eq!(std::fs::metadata(d.join("wide")).unwrap().permissions().mode() & 0o7777, 0o777, "no setuid/setgid/sticky from the network");
    assert_eq!(code(&c.fs_mkdir(&b(&d.join("new")), 0o755, W).await.unwrap_err()), Some(fsops::E_EXISTS));
    assert_eq!(code(&c.fs_mkdir(&b(&d.join("a/b/c")), 0o755, W).await.unwrap_err()), Some(fw::E_OPEN), "only one level: no parents are invented");
    assert!(!d.join("a").exists());
}

#[tokio::test]
async fn d5_remove_takes_a_file_a_link_or_an_empty_directory_and_nothing_else() {
    let r = rig("files").await;
    let c = open(&r).await;
    let d = r.dir.path();
    std::fs::write(d.join("f"), b"x").unwrap();
    c.fs_remove(&b(&d.join("f")), W).await.unwrap();
    assert!(!d.join("f").exists());
    std::fs::create_dir(d.join("keep")).unwrap();
    std::fs::write(d.join("keep/precious"), b"data").unwrap();
    symlink(d.join("keep"), d.join("lnk")).unwrap();
    c.fs_remove(&b(&d.join("lnk")), W).await.unwrap();
    assert!(std::fs::symlink_metadata(d.join("lnk")).is_err());
    assert_eq!(std::fs::read(d.join("keep/precious")).unwrap(), b"data", "removing a link does not touch what it points to");
    assert_eq!(code(&c.fs_remove(&b(&d.join("keep")), W).await.unwrap_err()), Some(fsops::E_NOTEMPTY));
    assert_eq!(std::fs::read(d.join("keep/precious")).unwrap(), b"data", "a directory with content is never emptied by this call");
    std::fs::create_dir(d.join("empty")).unwrap();
    c.fs_remove(&b(&d.join("empty")), W).await.unwrap();
    assert!(!d.join("empty").exists());
    assert_eq!(code(&c.fs_remove(&b(&d.join("ghost")), W).await.unwrap_err()), Some(fw::E_OPEN));
}

#[tokio::test]
async fn d6_rename_never_replaces_anything() {
    let r = rig("files").await;
    let c = open(&r).await;
    let d = r.dir.path();
    std::fs::write(d.join("a"), b"A").unwrap();
    std::fs::write(d.join("b"), b"B").unwrap();
    std::fs::create_dir(d.join("dir")).unwrap();
    c.fs_rename(&b(&d.join("a")), &b(&d.join("a2")), W).await.unwrap();
    assert_eq!(std::fs::read(d.join("a2")).unwrap(), b"A");
    assert_eq!(code(&c.fs_rename(&b(&d.join("a2")), &b(&d.join("b")), W).await.unwrap_err()), Some(fsops::E_EXISTS));
    assert_eq!((std::fs::read(d.join("a2")).unwrap(), std::fs::read(d.join("b")).unwrap()), (b"A".to_vec(), b"B".to_vec()), "both survive");
    assert_eq!(code(&c.fs_rename(&b(&d.join("a2")), &b(&d.join("dir")), W).await.unwrap_err()), Some(fsops::E_EXISTS), "not into an existing directory name either");
    c.fs_rename(&b(&d.join("dir")), &b(&d.join("dir2")), W).await.unwrap();
    assert!(d.join("dir2").is_dir());
    assert_eq!(code(&c.fs_rename(&b(&d.join("none")), &b(&d.join("x")), W).await.unwrap_err()), Some(fw::E_OPEN));
    assert_eq!(code(&c.fs_rename(&b(&d.join("a2")), &b(&d.join("nodir/x")), W).await.unwrap_err()), Some(fw::E_OPEN));
}

#[tokio::test]
async fn d7_rights_and_malformed_requests() {
    let r = rig("exec").await; // no 'files'
    let c = open(&r).await;
    let d = r.dir.path();
    std::fs::write(d.join("f"), b"x").unwrap();
    for res in [c.fs_list(&b(d), W).await.map(|_| ()), c.fs_remove(&b(&d.join("f")), W).await, c.fs_mkdir(&b(&d.join("m")), 0o755, W).await, c.fs_rename(&b(&d.join("f")), &b(&d.join("g")), W).await] {
        assert_eq!(code(&res.unwrap_err()), Some(1));
    }
    assert!(d.join("f").exists() && !d.join("m").exists() && !d.join("g").exists(), "nothing was touched");
    let r = rig("files").await;
    let d = r.dir.path();
    // before the login
    let (mut s, sec) = raw(&r).await;
    let req = FsReq { id: 1, op: fsops::OP_RM, a: b(&d.join("x")), b: vec![] }.encode().unwrap();
    send(&mut s, &sec, Frame::new(fsops::FS_REQ, 0, req.clone())).await;
    assert!(recv(&mut s, &sec).await.is_none());
    // malformed ones end the session
    for bad in [vec![], vec![0; 12], { let mut v = req.clone(); v.push(0); v }, { let mut v = req.clone(); v[8] = 99; v }, { let mut v = req.clone(); v[8] = fsops::OP_MV; v }] {
        let (mut s, sec) = raw(&r).await;
        raw_login(&mut s, &sec, "anna", PW).await;
        send(&mut s, &sec, Frame::new(fsops::FS_REQ, 0, bad)).await;
        send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
        assert!(recv(&mut s, &sec).await.is_none());
    }
}

#[test]
fn d8_codecs_are_exact_and_never_panic() {
    let q = FsReq { id: 3, op: fsops::OP_MV, a: b"/a".to_vec(), b: b"/b".to_vec() };
    let e = q.encode().unwrap();
    assert_eq!(FsReq::decode(&e).unwrap(), q);
    let mut longer = e.clone();
    longer.push(0);
    assert!(FsReq::decode(&longer).is_err() && FsReq::decode(&e[..e.len() - 1]).is_err());
    let mut printable = e.clone();
    printable.push(b'x'); // a printable byte would pass as part of the second path if the length were not exact
    assert!(FsReq::decode(&printable).is_err());
    // a name longer than the limit is refused even when all its bytes are present
    let mut long_name = encode_entries(1, &[DirEntry { name: vec![b'n'; 1024], kind: Kind::File, size: 1, mtime: 1, mode: 0o644 }])[8..].to_vec();
    assert!(decode_entries(&long_name).is_ok());
    let at = 2 + 19;
    long_name[at..at + 2].copy_from_slice(&1025u16.to_be_bytes());
    long_name.push(b'n');
    assert!(decode_entries(&long_name).is_err(), "1025 bytes of name");
    assert!(FsReq { id: 1, op: fsops::OP_LS, a: b"/x".to_vec(), b: b"/y".to_vec() }.encode().is_err(), "LS takes one path");
    assert!(FsReq { id: 1, op: fsops::OP_MKDIR, a: b"/x".to_vec(), b: vec![] }.encode().is_err(), "MKDIR needs a mode");
    assert!(FsReq { id: 1, op: fsops::OP_LS, a: vec![], b: vec![] }.encode().is_err() && FsReq { id: 1, op: fsops::OP_LS, a: b"a\0b".to_vec(), b: vec![] }.encode().is_err());
    let es = vec![
        DirEntry { name: b"x".to_vec(), kind: Kind::Dir, size: 0, mtime: -5, mode: 0o755 },
        DirEntry { name: vec![0xff; 1024], kind: Kind::Other, size: u64::MAX, mtime: i64::MAX, mode: 0o7777 },
    ];
    let enc = encode_entries(9, &es);
    assert_eq!(decode_entries(&enc[8..]).unwrap(), es);
    assert!(decode_entries(&enc[8..enc.len() - 1]).is_err());
    let mut more = enc[8..].to_vec();
    more.push(0);
    assert!(decode_entries(&more).is_err());
    let mut bad_kind = enc[8..].to_vec();
    bad_kind[2] = 9;
    assert!(decode_entries(&bad_kind).is_err());
    let mut lie = vec![0xff, 0xff]; // 65535 entries announced, none present
    assert!(decode_entries(&lie).is_err());
    lie.extend_from_slice(&[0; 40]);
    assert!(decode_entries(&lie).is_err());
    let mut x = 321u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..30_000 {
        let v: Vec<u8> = (0..(rnd() % 80) as usize).map(|_| rnd() as u8).collect();
        let _ = FsReq::decode(&v);
        let _ = decode_entries(&v);
    }
}

#[tokio::test]
async fn d9_the_helper_answers_garbage_with_an_error_not_a_crash() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let run = |input: &str| {
        let mut ch = Command::new(env!("CARGO_BIN_EXE_yrld")).arg("fs-helper").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let _ = ch.stdin.take().unwrap().write_all(input.as_bytes());
        let o = ch.wait_with_output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    for bad in ["LS\n", "LS zz\n", "LS 00\n", "MKDIR x 00\n", "MKDIR 755 zz\n", "RM\n", "MV 00\n", "MV zz zz\n", "STAT\n", "LS 2f 2f\n"] {
        let out = run(bad);
        assert!(out.is_empty() || out.starts_with("ERR "), "{bad:?} -> {out:?}");
    }
    assert_eq!(run(&format!("RM {}\n", hex::encode("/definitely/not/here"))), format!("ERR {}", fw::E_OPEN));
    // the helper masks the mode itself, whatever the server sent
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("m");
    assert_eq!(run(&format!("MKDIR 7777 {}\n", hex::encode(target.to_str().unwrap()))), "END");
    assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777, 0o777);
}
