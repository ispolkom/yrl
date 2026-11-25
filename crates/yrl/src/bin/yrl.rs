//! yrl keygen <dir> | yrl ping <dir> <host:port> <server-public-hex> <login> | yrl exec <dir> <host:port> <server-public-hex> <login> -- <program> [args…]
use std::path::PathBuf;
use std::time::Duration;
use yrl::{client::Client, keys};

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let r = run(&a).await;
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(a: &[String]) -> anyhow::Result<()> {
    // `--relay host:port` anywhere: reach a server that is only connected to that relay
    let mut owned: Vec<String> = a.to_vec();
    if let Some(i) = owned.iter().position(|x| x == "--relay") {
        if let Some(r) = owned.get(i + 1).cloned() {
            std::env::set_var("YRL_RELAY", r);
            owned.drain(i..=i + 1);
        }
    }
    if let Some(i) = owned.iter().position(|x| x == "--knock") {
        if let Some(k) = owned.get(i + 1).cloned() {
            std::env::set_var("YRL_KNOCK", k);
            owned.drain(i..=i + 1);
        }
    }
    if let Some(i) = owned.iter().position(|x| x == "--udp") {
        if let Some(u) = owned.get(i + 1).cloned() {
            std::env::set_var("YRL_UDP", u);
            owned.drain(i..=i + 1);
        }
    }
    if let Some(i) = owned.iter().position(|x| x == "--executor") {
        if let Some(k) = owned.get(i + 1).cloned() {
            std::env::set_var("YRL_EXECUTOR_KEY", k);
            owned.drain(i..=i + 1);
        }
    }
    let a = &owned[..];
    match a.get(1).map(String::as_str) {
        Some("keygen") => {
            let k = keys::init(&PathBuf::from(&a[2]))?;
            println!("client public key (authorize it on the server): {}", hex::encode(&k.public));
        }
        Some("ping") => {
            let c = connect(a).await?;
            let t = std::time::Instant::now();
            c.ping(b"yrl", Duration::from_secs(5)).await?;
            println!("pong in {:?}", t.elapsed());
        }
        Some("put") | Some("get") => {
            let up = a[1] == "put";
            let (from, to) = (a.get(6).ok_or_else(|| anyhow::anyhow!("need two paths"))?, a.get(7).ok_or_else(|| anyhow::anyhow!("need two paths"))?);
            let c = connect(a).await?;
            let t = std::time::Instant::now();
            let r = if up {
                let mode = std::fs::metadata(from).map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) as u16 & 0o777)?;
                c.put_file(std::path::Path::new(from), to.as_bytes(), mode, Duration::from_secs(3600)).await?
            } else {
                c.get_file(from.as_bytes(), std::path::Path::new(to), Duration::from_secs(3600)).await?
            };
            let secs = t.elapsed().as_secs_f64().max(0.001);
            eprintln!("{} bytes in {secs:.1} s ({:.1} MiB/s){}", r.bytes, r.bytes as f64 / 1048576.0 / secs, if r.resumed_from > 0 { format!(", continued from byte {}", r.resumed_from) } else { String::new() });
        }
        Some("forward") | Some("socks") => {
            // yrl forward <dir> <addr> <srv> <login> <local-port> <host> <port>   |   yrl socks <dir> <addr> <srv> <login> <local-port>
            let local: u16 = a.get(6).ok_or_else(|| anyhow::anyhow!("need a local port"))?.parse()?;
            let c = std::sync::Arc::new(connect(a).await?);
            let l = tokio::net::TcpListener::bind(("127.0.0.1", local)).await?; // never beyond this machine: the proxy has no password
            eprintln!("listening on 127.0.0.1:{local} (Ctrl-C to stop)");
            if a[1] == "forward" {
                let host = a.get(7).ok_or_else(|| anyhow::anyhow!("need a host and a port"))?.clone();
                let port: u16 = a.get(8).ok_or_else(|| anyhow::anyhow!("need a host and a port"))?.parse()?;
                yrl::client_tun::forward_local(c, l, host, port).await;
            } else {
                yrl::client_tun::socks5(c, l).await;
            }
        }
        Some("visual") => {
            let c = std::sync::Arc::new(connect(a).await?);
            visual(c).await?;
        }
        Some("elevate") => {
            // yrl elevate <dir> <addr> <srv> <login> <sudo|root> <executor-key-hex> <op> [argument]
            use yrl::stepup::{Level, Op};
            let level = match a.get(6).map(String::as_str) {
                Some("sudo") => Level::Sudo,
                Some("root") => Level::Root,
                _ => anyhow::bail!("level: sudo or root"),
            };
            let exec_pub = hex::decode(a.get(7).ok_or_else(|| anyhow::anyhow!("need the executor key"))?)?;
            std::env::set_var("YRL_EXECUTOR_KEY", &a[7]);
            let arg = a.get(9).cloned().unwrap_or_default();
            let op = match a.get(8).map(String::as_str) {
                Some("test") => Op::TestPrivileged(arg),
                Some("restart") => Op::RestartService(arg),
                _ => anyhow::bail!("operation: test | restart <service>"),
            };
            let c = connect(a).await?;
            let phrase = zeroize::Zeroizing::new(yrl::prompt::read_password(&format!("{} phrase: ", level.right()))?);
            println!("{}", c.elevate(level, &op, &phrase, &exec_pub, Duration::from_secs(30)).await?);
        }
        Some("enroll") => {
            // yrl enroll <dir> <addr> <srv-key> <name>: add THIS device (its key is in <dir>) to a server whose owner has opened a window
            let me = keys::load(&PathBuf::from(&a[2]))?;
            let server = hex::decode(&a[4])?;
            let label = a.get(5).ok_or_else(|| anyhow::anyhow!("need a name for this device"))?;
            let relay = std::env::var("YRL_RELAY").ok();
            let opts = yrl::client::ClientOptions { relay, ..Default::default() };
            let c = Client::connect_opts(&a[3], &me, &server, opts).await?;
            eprintln!("The fingerprint of this device is {}. The owner must see the same one.", yrl::enroll::fingerprint(&me.public));
            let code = String::from_utf8_lossy(&yrl::prompt::read_password("enrolment code: ")?).trim().to_string();
            c.enroll(&code, label, Duration::from_secs(330)).await?;
            println!("this device was added; now log in as usual");
        }
        Some("shell") => {
            let c = connect(a).await?;
            let code = shell(&c).await?;
            std::process::exit(code);
        }
        Some("exec") => {
            let c = connect(a).await?;
            let sep = a.iter().position(|x| x == "--").ok_or_else(|| anyhow::anyhow!("put -- before the program"))?;
            let argv: Vec<&[u8]> = a[sep + 1..].iter().map(|s| s.as_bytes()).collect();
            let r = c.exec(&argv, 60_000, Duration::from_secs(70)).await?;
            use std::io::Write;
            std::io::stdout().write_all(&r.stdout)?;
            std::io::stderr().write_all(&r.stderr)?;
            if let Some((code, text)) = r.error {
                eprintln!("server error {code}: {text}");
            }
            std::process::exit(r.code);
        }
        _ => anyhow::bail!("usage: yrl keygen <dir> | enroll <dir> <addr> <srv-key> <name> | elevate <..> <sudo|root> <executor-key> <test|restart> [arg] | visual <..> | forward <..> <local-port> <host> <port> | socks <..> <local-port> | put|get <dir> <host:port> <server-public-hex> <login> <from> <to> | shell <dir> <host:port> <server-public-hex> <login> | ping <dir> <host:port> <server-public-hex> <login> | exec <dir> <host:port> <server-public-hex> <login> -- <program> [args…]; add --executor <executor-public-hex> to every login command"),
    }
    Ok(())
}

async fn connect(a: &[String]) -> anyhow::Result<Client> {
    // <dir> <host:port> <server-public-hex> <login> are at 2..=5 for every command that logs in
    if a.len() < 6 {
        anyhow::bail!("this command needs: <dir> <host:port> <server-public-hex> <login> (the login is the account name on the server)");
    }
    let me = keys::load(&PathBuf::from(&a[2]))?;
    let server = hex::decode(&a[4])?;
    let executor_public = hex::decode(std::env::var("YRL_EXECUTOR_KEY").map_err(|_| anyhow::anyhow!("missing pinned Executor key: pass --executor <executor-public-hex>"))?)?;
    let relay = std::env::var("YRL_RELAY").ok();
    let knock = std::env::var("YRL_KNOCK").ok().map(|udp| yrl::client::Knock { udp, settle: Duration::from_millis(300) });
    let opts = yrl::client::ClientOptions { executor_public: Some(executor_public), connect_timeout: Duration::from_secs(if relay.is_some() || knock.is_some() { 15 } else { 5 }), relay, knock, udp: std::env::var("YRL_UDP").ok(), ..Default::default() };
    let c = Client::connect_opts(&a[3], &me, &server, opts).await?;
    let pw = zeroize::Zeroizing::new(yrl::prompt::read_password(&format!("password for {}: ", a[5]))?);
    c.login(&a[5], &pw, Duration::from_secs(10)).await?;
    Ok(c)
}

/// puts the local terminal into raw mode and gives it back on every way out
struct Raw(Option<libc::termios>);
impl Raw {
    fn enter() -> Raw {
        unsafe {
            if libc::isatty(0) == 0 {
                return Raw(None);
            }
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return Raw(None);
            }
            let saved = t;
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(0, libc::TCSANOW, &t);
            Raw(Some(saved))
        }
    }
}
impl Drop for Raw {
    fn drop(&mut self) {
        if let Some(t) = &self.0 {
            unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
        }
    }
}

fn window_size() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        (ws.ws_row.min(1000), ws.ws_col.min(1000))
    } else {
        (24, 80)
    }
}

async fn shell(c: &Client) -> anyhow::Result<i32> {
    use tokio::io::AsyncWriteExt;
    use yrl::client::PtyEvent;
    let (rows, cols) = window_size();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".into());
    let mut pty = c.pty_open(rows, cols, &term).await?;
    let _raw = Raw::enter();
    let mut winch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    // std's stdin, not tokio's: whatever followed the password line is already in std's buffer (a pipe), and it belongs to the shell
    let (key_tx, mut keys) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut b = vec![0u8; 8192];
        while let Ok(n) = std::io::stdin().lock().read(&mut b) {
            if n == 0 || key_tx.blocking_send(b[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stdout = tokio::io::stdout();
    let mut stdin_open = true;
    loop {
        tokio::select! {
            k = keys.recv(), if stdin_open => match k {
                None => { stdin_open = false; pty.write(&[4]).await?; } // end of input = Ctrl-D, as at a terminal
                Some(b) => pty.write(&b).await?,
            },
            _ = winch.recv() => { let (r, c) = window_size(); pty.resize(r, c).await?; }
            ev = pty.next() => match ev {
                PtyEvent::Output(b) => { stdout.write_all(&b).await?; stdout.flush().await?; }
                PtyEvent::Exit(code) => return Ok(code),
                PtyEvent::Error(code, text) => { drop(_raw); anyhow::bail!("server error {code}: {text}") }
                PtyEvent::Closed => { drop(_raw); anyhow::bail!("the link closed") }
            },
        }
    }
}

enum Done {
    Listing(Vec<u8>, Vec<yrl::fsops::DirEntry>),
    Note(String),
    Fail(String),
    Reload,
}

fn paint(app: &yrl::visual::App, out: &mut impl std::io::Write) -> std::io::Result<()> {
    use yrl::visual::Style::*;
    let mut s = String::new();
    for (i, l) in app.render().iter().enumerate() {
        let sgr = match l.style {
            Header => "1;37;44",
            Titles => "1;4",
            Normal => "0",
            Dir => "1;34",
            Selected => "7",
            Status => "0;32",
            Error => "1;31",
            Bar => "30;47",
            Prompt => "1;33",
        };
        s.push_str(&format!("\x1b[{};1H\x1b[{sgr}m{}\x1b[0m", i + 1, l.text)); // the text holds no control characters: see visual::sanitize
    }
    out.write_all(s.as_bytes())?;
    out.flush()
}

async fn visual(c: std::sync::Arc<Client>) -> anyhow::Result<()> {
    use yrl::visual::{App, Cmd, Input, InputParser};
    let wait = Duration::from_secs(60);
    let (rows, cols) = window_size();
    let start = c.fs_real(b".", wait).await?;
    let local_dir = std::env::current_dir()?;
    let mut app = App::new(start.clone(), rows, cols, local_dir.clone());
    let first = c.fs_list(&start, wait).await?;
    app.set_listing(start, first);
    let (key_tx, mut keys) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut b = vec![0u8; 4096];
        while let Ok(n) = std::io::stdin().lock().read(&mut b) {
            if n == 0 || key_tx.blocking_send(b[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let _raw = Raw::enter();
    struct Screen;
    impl Drop for Screen {
        fn drop(&mut self) {
            print!("\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1006l\x1b[?1000l\x1b[?1049l");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }
    print!("\x1b[?1049h\x1b[?1000h\x1b[?1006h\x1b[?7l\x1b[?25l\x1b[2J");
    let _screen = Screen;
    let mut winch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let (done_tx, mut done) = tokio::sync::mpsc::channel::<Done>(64);
    let mut parser = InputParser::default();
    let mut out = std::io::stdout();
    paint(&app, &mut out)?;
    let mut quit = false;
    while !quit {
        let mut inputs: Vec<Input> = vec![];
        tokio::select! {
            b = tokio::time::timeout(Duration::from_millis(60), keys.recv()) => match b {
                Ok(Some(b)) => inputs = parser.feed(&b),
                Ok(None) => break,
                Err(_) => inputs.extend(parser.flush_pending()),
            },
            _ = winch.recv() => { let (r, c) = window_size(); inputs.push(Input::Resize(r, c)); }
            d = done.recv() => {
                match d {
                    Some(Done::Listing(p, e)) => app.set_listing(p, e),
                    Some(Done::Note(m)) => app.note(&m),
                    Some(Done::Fail(m)) => app.error(&m),
                    Some(Done::Reload) => inputs.push(Input::Key(yrl::visual::Key::Char('R'))),
                    None => break,
                }
            }
        }
        let mut cmds = vec![];
        for i in inputs {
            cmds.extend(app.handle(i, std::time::Instant::now()));
        }
        for cmd in cmds {
            let (c, tx, dir) = (c.clone(), done_tx.clone(), local_dir.clone());
            match &cmd {
                Cmd::Quit => {
                    quit = true;
                    continue;
                }
                _ => {}
            }
            tokio::spawn(async move {
                let r: anyhow::Result<Done> = async {
                    Ok(match cmd {
                        Cmd::List(p) => {
                            let real = c.fs_real(&p, wait).await?;
                            let entries = c.fs_list(&real, wait).await?;
                            Done::Listing(real, entries)
                        }
                        Cmd::Download { remote, local } => {
                            // only into the folder we started in, and never over a file that is there
                            if local.parent() != Some(dir.as_path()) || local.file_name().is_none() {
                                anyhow::bail!("refusing to write outside the current folder");
                            }
                            if local.symlink_metadata().is_ok() {
                                anyhow::bail!("{} already exists here; move it first", local.display());
                            }
                            let t = c.get_file(&remote, &local, Duration::from_secs(3600)).await?;
                            Done::Note(format!("downloaded {} ({} bytes)", local.display(), t.bytes + t.resumed_from))
                        }
                        Cmd::Upload { local, remote } => {
                            let mode = std::fs::metadata(&local).map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) as u16 & 0o777)?;
                            c.put_file(&local, &remote, mode, Duration::from_secs(3600)).await?;
                            let _ = tx.send(Done::Note("uploaded".into())).await;
                            Done::Reload
                        }
                        Cmd::Mkdir(p) => {
                            c.fs_mkdir(&p, 0o755, wait).await?;
                            Done::Reload
                        }
                        Cmd::Remove(p) => {
                            c.fs_remove(&p, wait).await?;
                            Done::Reload
                        }
                        Cmd::Rename { from, to } => {
                            c.fs_rename(&from, &to, wait).await?;
                            Done::Reload
                        }
                        Cmd::Quit => Done::Note(String::new()),
                    })
                }
                .await;
                let _ = tx.send(r.unwrap_or_else(|e| Done::Fail(e.to_string()))).await;
            });
        }
        paint(&app, &mut out)?;
    }
    c.close().await;
    Ok(())
}
