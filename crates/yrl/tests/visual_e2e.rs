//! The real `yrl visual` program in a real terminal (a pty), against a real server.
mod common;
use common::*;
use std::io::Write;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Term {
    master: std::fs::File,
    out: Arc<Mutex<Vec<u8>>>,
    child: Child,
}

impl Term {
    fn start(r: &Rig, cwd: &std::path::Path) -> Term {
        // a key pair for the command line client, authorized on the server
        let kdir = r.dir.path().join("cli");
        let kp = yrl::keys::init(&kdir).unwrap();
        yrl::keys::authorize(&r.server_dir().join("authorized_keys"), &hex::encode(&kp.public), "cli", "exec,shell,files").unwrap();
        let (mut m, mut s) = (-1, -1);
        let ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
        assert_eq!(unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws) }, 0);
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_yrl"));
        cmd.args(["visual", kdir.to_str().unwrap(), &r.addr, &hex::encode(&r.server_pub), "anna"]).current_dir(cwd).env("TERM", "xterm");
        cmd.stdin(Stdio::from(slave.try_clone().unwrap())).stdout(Stdio::from(slave.try_clone().unwrap())).stderr(Stdio::from(slave.try_clone().unwrap()));
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        drop(slave);
        let out = Arc::new(Mutex::new(Vec::new()));
        let (o2, mfd) = (out.clone(), master.try_clone().unwrap());
        std::thread::spawn(move || {
            use std::io::Read;
            let mut f = std::fs::File::from(OwnedFd::from(mfd));
            let mut b = vec![0u8; 8192];
            while let Ok(n) = f.read(&mut b) {
                if n == 0 {
                    break;
                }
                o2.lock().unwrap().extend_from_slice(&b[..n]);
            }
        });
        Term { master: std::fs::File::from(master), out, child }
    }
    fn send(&mut self, b: &[u8]) {
        self.master.write_all(b).unwrap();
        std::thread::sleep(Duration::from_millis(40));
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned()
    }
    fn wait_for(&self, needle: &str, secs: u64) {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if self.text().contains(needle) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("never saw {needle:?}; screen so far:\n{}", self.text().replace('\x1b', "<ESC>"));
    }
    fn mark(&self) -> usize {
        self.out.lock().unwrap().len()
    }
    fn wait_after(&self, mark: usize, needle: &str, secs: u64) {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            let o = self.out.lock().unwrap();
            if String::from_utf8_lossy(&o[mark..]).contains(needle) {
                return;
            }
            drop(o);
            std::thread::sleep(Duration::from_millis(25));
        }
        let o = self.out.lock().unwrap();
        panic!("never saw {needle:?} after the mark; new output:\n{}", String::from_utf8_lossy(&o[mark..]).replace('\x1b', "<ESC>"));
    }
    fn login(&mut self) {
        self.wait_for("password for anna", 20);
        self.send(format!("{}\n", String::from_utf8_lossy(PW)).as_bytes());
        self.wait_for("yrl visual", 20);
    }
    fn goto(&mut self, dir: &std::path::Path) {
        let m = self.mark();
        self.send(b"g");
        self.send(dir.to_str().unwrap().as_bytes());
        self.send(b"\r");
        self.wait_after(m, &format!("yrl visual   {} ", dir.display()), 20);
    }
    /// the header shows this directory (after the mark)
    fn wait_in(&self, mark: usize, dir: &std::path::Path) {
        self.wait_after(mark, &format!("yrl visual   {} ", dir.display()), 20);
    }
    fn finish(mut self) -> (Option<i32>, String) {
        let end = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s.code();
            }
            if Instant::now() > end {
                let _ = self.child.kill();
                panic!("the program did not exit");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        std::thread::sleep(Duration::from_millis(100));
        (status, self.text())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn e1_browse_download_create_rename_delete_and_quit_cleanly() {
    let r = rig("exec,shell,files").await;
    let base = r.dir.path().join("files");
    std::fs::create_dir_all(base.join("photos")).unwrap();
    std::fs::write(base.join("hello.txt"), b"hello from the other side").unwrap();
    let local = r.dir.path().join("here");
    std::fs::create_dir(&local).unwrap();
    let mut t = Term::start(&r, &local);
    t.login();
    t.goto(&base);
    t.wait_for("hello.txt", 10);
    t.wait_for("photos/", 10);
    // photos/ is the first entry after '..'; hello.txt the second
    t.send(b"\x1b[B\x1b[B");
    let m = t.mark();
    t.send(b"d");
    t.wait_after(m, "downloaded", 20);
    assert_eq!(std::fs::read(local.join("hello.txt")).unwrap(), b"hello from the other side");
    // a second download over the same name is refused, the first copy untouched
    let m = t.mark();
    t.send(b"d");
    t.wait_after(m, "already exists", 20);
    assert_eq!(std::fs::read(local.join("hello.txt")).unwrap(), b"hello from the other side");
    // make a directory, rename it, delete it
    let m = t.mark();
    t.send(b"m");
    t.send(b"made");
    t.send(b"\r");
    t.wait_after(m, "made/", 20);
    assert!(base.join("made").is_dir());
    // the reload put the selection back on hello.txt; the order is '..', made, photos, hello.txt
    t.send(b"\x1b[A"); // photos
    t.send(b"\x1b[A"); // made
    let m = t.mark();
    t.send(b"r");
    t.wait_after(m, "new name: made", 10);
    t.send(b"\x15renamed\r"); // Ctrl-U clears the old name
    t.wait_after(m, "renamed/", 20);
    assert!(base.join("renamed").is_dir() && !base.join("made").exists());
    let m = t.mark();
    t.send(b"x");
    t.wait_after(m, "delete renamed", 10);
    t.send(b"y");
    for _ in 0..100 {
        if !base.join("renamed").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!base.join("renamed").exists(), "deleted after the confirmation");
    t.send(b"q");
    let (code, screen) = t.finish();
    assert_eq!(code, Some(0));
    assert!(screen.contains("\x1b[?1049l") && screen.contains("\x1b[?1000l") && screen.contains("\x1b[?1006l") && screen.contains("\x1b[?25h"), "the terminal was given back: alternate screen left, mouse off, cursor on");
    assert!(r.sessions.is_empty() || { std::thread::sleep(Duration::from_millis(500)); r.sessions.is_empty() }, "the session was ended politely");
}

#[tokio::test(flavor = "multi_thread")]
async fn e2_names_that_are_terminal_commands_stay_text() {
    let r = rig("exec,shell,files").await;
    let base = r.dir.path().join("evil");
    std::fs::create_dir_all(&base).unwrap();
    for n in ["\x1b]0;pwned-title\x07file", "\x1b[2Jclear", "\x1b[?1049lalt", "\x1b[?1000hmouse", "\x1b]52;c;ZXZpbA==\x07clip"] {
        std::fs::write(base.join(n), b"x").unwrap();
    }
    std::fs::write(base.join("normal.txt"), b"x").unwrap();
    let mut t = Term::start(&r, r.dir.path());
    t.login();
    t.goto(&base);
    t.wait_for("normal.txt", 10);
    t.wait_for("pwned-title", 10);
    for _ in 0..8 {
        t.send(b"\x1b[B");
    }
    let before_quit = t.text();
    t.send(b"q");
    let (code, screen) = t.finish();
    assert_eq!(code, Some(0));
    assert!(!before_quit.contains("\x07"), "no bell/OSC terminator was ever written");
    assert!(!screen.contains("\x1b]0;pwned"), "the title sequence from the file name never reached the terminal");
    assert!(!screen.contains("\x1b]52;"), "nor the clipboard one");
    assert_eq!(screen.matches("\x1b[2J").count(), 1, "the only screen clear is the program's own, at the start");
    assert_eq!(screen.matches("\x1b[?1049l").count(), 1, "the only 'leave the alternate screen' is the program's own, at the end");
    assert_eq!(screen.matches("\x1b[?1000h").count(), 1, "the only 'mouse on' is the program's own");
}

#[tokio::test(flavor = "multi_thread")]
async fn e3_the_mouse_works_on_rows_and_on_the_buttons() {
    let r = rig("exec,shell,files").await;
    let base = r.dir.path().join("m");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::create_dir_all(base.join("sub")).unwrap();
    std::fs::write(base.join("only.txt"), b"clicked!").unwrap();
    std::fs::write(base.join("sub/deep.txt"), b"deep").unwrap();
    let local = r.dir.path().join("down");
    std::fs::create_dir(&local).unwrap();
    let mut t = Term::start(&r, &local);
    t.login();
    t.goto(&base);
    t.wait_for("only.txt", 10);
    // rows (1-based on the wire): 1 header, 2 titles, 3 '..', 4 'sub/', 5 'only.txt'; the bottom line (24) holds the buttons
    let click = |t: &mut Term, row: u16, col: u16| {
        t.send(format!("\x1b[<0;{col};{row}M\x1b[<0;{col};{row}m").as_bytes());
    };
    let m = t.mark();
    click(&mut t, 4, 10);
    click(&mut t, 4, 10); // a double click on 'sub/'
    t.wait_in(m, &base.join("sub"));
    t.wait_after(m, "deep.txt", 20);
    // up again with the keyboard, then click 'only.txt' and the "d:down" button
    let m = t.mark();
    t.send(b"\x7f");
    t.wait_in(m, &base);
    click(&mut t, 5, 12);
    let m = t.mark();
    click(&mut t, 24, 4); // inside "d:down"
    t.wait_after(m, "downloaded", 20);
    assert_eq!(std::fs::read(local.join("only.txt")).unwrap(), b"clicked!");
    // the wheel moves the selection; a click on the quit button leaves
    t.send(b"\x1b[<64;10;10M");
    click(&mut t, 24, 70);
    let (code, _) = t.finish();
    assert_eq!(code, Some(0));
}
