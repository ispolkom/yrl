//! yrld init <dir> | yrld authorize <dir> <client-public-hex> <label> <rights> | yrld serve <dir> <bind addr:port>
use std::path::PathBuf;
use yrl::{keys, server};

#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("sandbox-selftest") {
        std::process::exit(sandbox_selftest()); // used by the tests: what does the wall really stop?
    }
    if std::env::args().nth(1).as_deref() == Some("fs-helper") {
        std::process::exit(yrl::fshelper::main()); // the file side of a transfer, started by the server itself
    }
    let a: Vec<String> = std::env::args().collect();
    let r = match a.get(1).map(String::as_str) {
        Some("init") => keys::init(&PathBuf::from(&a[2])).and_then(|k| {
            yrl::ipc::init_keys(&PathBuf::from(&a[2]))?; // the keys of the local door between the gatekeeper and the executor
            println!("server public key (give it to the client): {}", hex::encode(k.public));
            let e = std::fs::read_to_string(PathBuf::from(&a[2]).join("ipc/executor.pub"))?;
            println!("executor public key (pin it on every client for the end-to-end channel): {}", e.trim());
            let b = std::fs::read_to_string(PathBuf::from(&a[2]).join("ipc/broker.pub"))?;
            println!("broker public key (give it to the client for ROOT step-up): {}", b.trim());
            Ok(())
        }),
        Some("authorize") => keys::authorize(&PathBuf::from(&a[2]).join("authorized_keys"), &a[3], &a[4], &a[5]).map(|_| println!("authorized")),
        Some("passwd") => {
            let pw = yrl::prompt::read_password("new password: ").map_err(anyhow::Error::from);
            pw.and_then(|pw| yrl::users::set_user_os(&PathBuf::from(&a[2]).join("users"), &a[3], &a[4], a.get(5).map(String::as_str), &pw)).map(|_| println!("account saved"))
        }
        Some("word") => word_set(&a).await,
        Some("unlock") => unlock(&a).await,
        Some("enroll") if a.get(2).map(String::as_str) == Some("enable") => enroll_enable(&a[3], &a).await,
        Some("audit") if a.get(2).map(String::as_str) == Some("verify") => audit_verify(&a[3]),
        Some("audit") if a.get(2).map(String::as_str) == Some("repair") => yrl::audit::repair(&PathBuf::from(&a[3])).map(|t| print!("{t}")),
        Some("audit") => audit(&a[2], &a).await,
        Some("firewall") => firewall(&a[2], &a).await,
        Some("install") => install_cmd(&a),
        Some("executor") => executor(&a[2], &a).await,
        Some("broker") => broker(&a[2], &a).await,
        Some("gatekeeper") => gatekeeper(&a[2], &a[3], a.iter().position(|x| x == "--relay").and_then(|i| a.get(i + 1)).cloned(), &a).await,
        Some("serve") => serve(&a[2], &a[3], a.iter().position(|x| x == "--relay").and_then(|i| a.get(i + 1)).cloned()).await,
        _ => Err(anyhow::anyhow!("usage: yrld firewall <dir> --ports 2222[,..] [--backend mock|nft] [--max-ttl N] [--allow-loopback] | install accounts|tmpfiles [run-dir]|layout <dir> [run-dir]|check <dir> [run-dir] | gatekeeper … [--spa udp-addr --work-port P] | audit <dir> | audit verify <dir> | audit repair <dir> | enroll enable <dir> [--ttl N] [--rights csv] | broker <dir> [--exec-uid N] [--exec-exe PATH] | executor <dir> [--gate-uid N] [--gate-exe PATH] | gatekeeper <dir> <addr:port|-> [--relay host:port] | init <dir> | authorize <dir> <client-public-hex> <label> <rights> | passwd <dir> <login> <rights|-> [system-user] (password from the terminal or stdin) | serve <dir> <addr:port|-> [--relay host:port]")),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn serve(dir: &str, bind: &str, relay: Option<String>) -> anyhow::Result<()> {
    let dir = PathBuf::from(dir);
    let me = keys::load(&dir)?;
    let cfg = server::ServerConfig::new(dir);
    match relay {
        // behind NAT: only dial out; the address `-` means no listening port at all
        Some(r) => {
            eprintln!("[yrld] dialing out to the relay {r}");
            if bind != "-" {
                let listener = tokio::net::TcpListener::bind(bind).await?;
                eprintln!("[yrld] listening on {bind}");
                tokio::spawn(server::serve(listener, me.clone(), cfg.clone()));
            }
            server::serve_via_relay(r, me, cfg, 2).await;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(bind).await?;
            eprintln!("[yrld] listening on {bind}");
            server::serve(listener, me, cfg).await;
        }
    }
    Ok(())
}

/// the part that does things on the machine; listens only on the local socket `<dir>/ipc.sock`


/// the installation on a machine with separate system users: `accounts` and `tmpfiles` only PRINT (the owner reads them, then runs them); `layout` gives owners and modes (as root); `check` finds every difference
fn install_cmd(a: &[String]) -> anyhow::Result<()> {
    use yrl::install::*;
    let run = |i: usize| a.get(i).cloned().unwrap_or_else(|| "/run/yrl".into());
    match a.get(2).map(String::as_str) {
        Some("accounts") => print!("{}", accounts_script()),
        Some("tmpfiles") => print!("{}", tmpfiles_conf(&run(3))),
        Some("layout") => {
            let dir = PathBuf::from(a.get(3).ok_or_else(|| anyhow::anyhow!("usage: yrld install layout <state-dir> [run-dir]"))?);
            let mut missing = apply(&dir, &state_layout(), &SystemNames)?;
            let run = PathBuf::from(run(4));
            std::fs::create_dir_all(&run)?;
            missing.extend(apply(&run, &run_layout(), &SystemNames)?);
            for m in &missing {
                println!("still to do: {}", describe(m));
            }
            println!("owners and modes set{}", if missing.is_empty() { "" } else { " (except what is listed above)" });
        }
        Some("check") => {
            let dir = PathBuf::from(a.get(3).ok_or_else(|| anyhow::anyhow!("usage: yrld install check <state-dir> [run-dir]"))?);
            let mut problems = check(&dir, &state_layout(), &SystemNames, true);
            problems.extend(check(&PathBuf::from(run(4)), &run_layout(), &SystemNames, false));
            for p in &problems {
                println!("PROBLEM: {}", describe(p));
            }
            if problems.is_empty() {
                println!("the installation matches the table");
            } else {
                std::process::exit(1);
            }
        }
        _ => anyhow::bail!("usage: yrld install accounts | tmpfiles [run-dir] | layout <state-dir> [run-dir] | check <state-dir> [run-dir]"),
    }
    Ok(())
}

/// The program on the other side of a door is expected to be this very program (checked through /proc/<pid>/exe); `-` turns that check off, which an
/// installation with separate system users needs: the kernel does not let one user read another's /proc/<pid>/exe, and there the user id, the group of the
/// socket and the pre-shared key do the identifying.
fn peer_exe(opt: &Option<String>) -> anyhow::Result<Option<PathBuf>> {
    Ok(match opt.as_deref() {
        Some("-") => None,
        Some(p) => Some(std::fs::canonicalize(p)?),
        None => std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok()),
    })
}

async fn executor(dir: &str, a: &[String]) -> anyhow::Result<()> {
    let dir = PathBuf::from(dir);
    let opt = |name: &str| a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned();
    let uid = opt("--gate-uid").map(|u| yrl::ipc::uid_arg(&u)).transpose()?;
    let exe = peer_exe(&opt("--gate-exe"))?;
    let ipc = yrl::ipc::load_executor(&dir, uid, exe)?;
    let listener = yrl::ipc::bind_socket(&ipc.socket)?;
    let mut cfg = server::ServerConfig::new(dir.clone());
    cfg.exec_identity = Some(ipc.key.clone());
    cfg.lockouts = std::sync::Arc::new(yrl::stepup::Lockouts::persistent(&yrl::ipc::state_dir(&dir, "exec"), "sudo"));
    cfg.broker = yrl::ipc::load_executor_to_broker(&dir).ok(); // without a broker every ROOT step-up is refused
    cfg.audit.exec = yrl::ipc::audit_client(&dir, "executor"); // reports to the audit process, if one has been set up
    if std::env::var_os("YRL_SESSION_CGROUPS").is_some() { yrl::cgroup::verify_delegation()?; }
    if std::env::var_os("YRL_NO_SANDBOX").is_none() { yrl::sandbox::apply_executor()?; }
    eprintln!("[yrld] executor ready on {}", ipc.socket.display());
    yrl::executor::serve_ipc(listener, cfg, ipc).await;
    Ok(())
}

/// the part that talks to the network; has no way to do anything on the machine except by asking the executor
async fn gatekeeper(dir: &str, bind: &str, relay: Option<String>, a: &[String]) -> anyhow::Result<()> {
    let opt = |name: &str| a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned();
    let dir = PathBuf::from(dir);
    let me = keys::load_shared(&dir)?; // the state directory is shared with the other parts: the file must be ours and private
    let mut cfg = server::ServerConfig::new(dir.clone());
    cfg.gate = Some(yrl::ipc::load_gatekeeper(&dir)?);
    cfg.audit.gate = yrl::ipc::audit_client(&dir, "gatekeeper");
    cfg.audit_enabled = false; // a separate gatekeeper never starts a journal of its own
    // the network gate: one datagram port that never answers, and a firewall program that is the only one to touch the firewall
    let spa_task = match (opt("--spa"), opt("--work-port")) {
        (Some(udp), Some(port)) => {
            let ipc = yrl::ipc::load_gatekeeper_to_firewall(&dir)?;
            let verifier = std::sync::Arc::new(yrl::spa::SpaVerifier::new(me.clone(), dir.clone(), yrl::spa::SpaConfig::default()));
            let sock = tokio::net::UdpSocket::bind(&udp).await?;
            eprintln!("[yrld] listening for knocks on {udp} (udp, never answers)");
            let ttl: u32 = opt("--knock-ttl").map(|t| t.parse()).transpose()?.unwrap_or(30);
            Some((sock, verifier, yrl::firewall::FirewallClient::new(ipc), port.parse::<u16>()?, ttl))
        }
        _ => None,
    };
    // everything the gatekeeper needs is open now (keys, config); from here on the system itself refuses it what it never needs
    if std::env::var_os("YRL_NO_SANDBOX").is_none() {
        yrl::sandbox::apply()?;
    }
    if let Some((sock, verifier, fw, port, ttl)) = spa_task {
        tokio::spawn(yrl::gatenet::spa_listen(sock, verifier, fw, port, ttl, cfg.clone()));
    }
    // the same server over UDP on the same port number (the firewall treats both alike): `--udp addr:port`
    if let Some(u) = opt("--udp") {
        let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind(&u).await?);
        eprintln!("[yrld] gatekeeper also listening on {u} (udp stream)");
        tokio::spawn(server::serve_udp(sock, me.clone(), cfg.clone()));
    }
    match relay {
        Some(r) => {
            eprintln!("[yrld] gatekeeper dialing out to the relay {r}");
            if bind != "-" {
                let listener = tokio::net::TcpListener::bind(bind).await?;
                tokio::spawn(server::serve(listener, me.clone(), cfg.clone()));
            }
            server::serve_via_relay(r, me, cfg, 2).await;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(bind).await?;
            eprintln!("[yrld] gatekeeper listening on {bind}");
            server::serve(listener, me, cfg).await;
        }
    }
    Ok(())
}

fn sandbox_selftest() -> i32 {
    let before = std::process::Command::new("/bin/true").status().is_ok();
    let (go, ready) = std::sync::mpsc::channel();
    let (report, checked) = std::sync::mpsc::channel();
    let existing = std::thread::spawn(move || {
        if ready.recv().is_ok() {
            let (_, mode) = yrl::sandbox::status();
            let _ = report.send(mode == 2 && std::process::Command::new("/bin/true").status().is_err());
        }
    });
    if let Err(e) = yrl::sandbox::apply() {
        println!("apply failed: {e}");
        return 2;
    }
    let (nnp, mode) = yrl::sandbox::status();
    let exec_after = std::process::Command::new("/bin/true").status();
    let read_ok = std::fs::read_to_string("/proc/self/status").is_ok();
    let sock_ok = std::os::unix::net::UnixListener::bind("/tmp/.yrl-selftest.sock").map(|_| { let _ = std::fs::remove_file("/tmp/.yrl-selftest.sock"); }).is_ok();
    let tcp_ok = std::net::TcpListener::bind("127.0.0.1:0").is_ok();
    let thread_ok = std::thread::spawn(|| {
        let (_, mode) = yrl::sandbox::status();
        mode == 2 && std::process::Command::new("/bin/true").status().is_err()
    }).join().unwrap_or(false);
    let _ = go.send(());
    let existing_thread_ok = checked.recv().unwrap_or(false);
    let _ = existing.join();
    let setuid_blocked = unsafe { libc::setuid(12345) } != 0;
    println!("before_exec={before} nnp={nnp} seccomp={mode} exec_after_ok={} read={read_ok} unix={sock_ok} tcp={tcp_ok} thread={thread_ok} existing_thread={existing_thread_ok} setuid_blocked={setuid_blocked}", exec_after.is_ok());
    0
}

/// the smallest part: answers the ROOT step-up and does the few typed things ROOT may ask for; listens only on its local socket
async fn broker(dir: &str, a: &[String]) -> anyhow::Result<()> {
    let dir = PathBuf::from(dir);
    let opt = |name: &str| a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned();
    let uid = opt("--exec-uid").map(|u| yrl::ipc::uid_arg(&u)).transpose()?;
    let exe = peer_exe(&opt("--exec-exe"))?;
    let ipc = yrl::ipc::load_broker(&dir, uid, exe)?;
    let listener = yrl::ipc::bind_socket(&ipc.socket)?;
    eprintln!("[yrld] broker ready on {}", ipc.socket.display());
    let mut cfg = server::ServerConfig::new(dir.clone());
    cfg.root_lockouts = std::sync::Arc::new(yrl::stepup::Lockouts::persistent(&yrl::ipc::state_dir(&dir, "broker"), "root"));
    cfg.audit.broker = yrl::ipc::audit_client(&dir, "broker");
    if std::env::var_os("YRL_NO_SANDBOX").is_none() { yrl::sandbox::apply()?; }
    yrl::broker::serve_ipc(listener, cfg, ipc).await;
    Ok(())
}

/// the owner, on the machine: opens a window, shows the code, waits for a device, shows its fingerprint, asks
async fn enroll_enable(dir: &str, a: &[String]) -> anyhow::Result<()> {
    use std::io::BufRead;
    let dir = PathBuf::from(dir);
    let opt = |name: &str| a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned();
    let ttl: u64 = opt("--ttl").map(|t| t.parse()).transpose()?.unwrap_or(120);
    let rights: Vec<String> = opt("--rights").unwrap_or_else(|| "exec".into()).split(',').filter(|s| !s.is_empty()).map(String::from).collect();
    let code = yrl::enroll::open_window(&dir, ttl, &rights)?;
    owner_note(&dir, yrl::auditlog::Event::new("enroll_open", yrl::auditlog::LEVEL_NONE, yrl::auditlog::RESULT_OK).target(&format!("ttl={ttl} rights={}", rights.join(","))), false).await?;
    println!("A window is open for {ttl} seconds. Tell the new device this code: {code}");
    println!("The new device will get these rights: {}", rights.join(","));
    let end = std::time::Instant::now() + std::time::Duration::from_secs(ttl);
    while std::time::Instant::now() < end {
        if let Some(req) = yrl::enroll::pending_request(&dir) {
            println!("A device asks to be added: name '{}', fingerprint {}", req.label, yrl::enroll::fingerprint(&req.public));
            println!("Does the NEW DEVICE show exactly the same fingerprint? Add it? [y/N]");
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            let yes = line.trim().eq_ignore_ascii_case("y");
            // adding a device is written down BEFORE it happens; if that is impossible, nothing is added
            let ev = yrl::auditlog::Event::new("enroll_decision", yrl::auditlog::LEVEL_NONE, if yes { yrl::auditlog::RESULT_OK } else { yrl::auditlog::RESULT_DENIED }).device(&req.public).target(&format!("{} {}", req.label, yrl::enroll::fingerprint(&req.public)));
            if let Err(e) = owner_note(&dir, ev, yes).await {
                yrl::enroll::decide(&dir, &req, false, &rights)?;
                yrl::enroll::close_window(&dir);
                return Err(e);
            }
            yrl::enroll::decide(&dir, &req, yes, &rights)?;
            yrl::enroll::close_window(&dir);
            println!("{}", if yes { "added" } else { "refused" });
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    yrl::enroll::close_window(&dir);
    println!("the window ended: nobody was added");
    Ok(())
}

/// the audit process: keeps the journals; listens only on its local socket
async fn audit(dir: &str, a: &[String]) -> anyhow::Result<()> {
    let dir = PathBuf::from(dir);
    let opt = |name: &str| a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned();
    let every: u64 = opt("--checkpoint-every").map(|n| n.parse()).transpose()?.unwrap_or(100);
    let uid = opt("--parts-uid").map(|u| yrl::ipc::uid_arg(&u)).transpose()?;
    let svc = yrl::audit::AuditService::open(&dir, every)?; // refuses to start on a journal that does not verify
    let ipc = yrl::ipc::load_audit(&dir, uid)?;
    let listener = yrl::ipc::bind_socket(&ipc.socket)?;
    if std::env::var_os("YRL_NO_SANDBOX").is_none() { yrl::sandbox::apply()?; }
    eprintln!("[yrld] audit ready on {}", ipc.socket.display());
    let s2 = svc.clone();
    tokio::spawn(async move {
        // seal what has been written now and then, so that a quiet period does not leave a long unsigned tail
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let _ = s2.seal();
        }
    });
    yrl::audit::serve_ipc(listener, svc, ipc, std::sync::Arc::new(|m| eprintln!("[yrld] {m}"))).await;
    Ok(())
}

fn audit_verify(dir: &str) -> anyhow::Result<()> {
    use yrl::auditlog::*;
    let dir = PathBuf::from(dir);
    let mut bad = false;
    for j in [Journal::Ordinary, Journal::Security] {
        let r = verify_dir(&dir, j)?;
        println!("{}: {} records, {} checkpoints, {} not yet sealed{}", j.file(), r.records, r.checkpoints, r.unsealed, r.sealed.map(|(s, h)| format!(", sealed up to #{s} ({})", &hex::encode(h)[..16])).unwrap_or_default());
        if let Some(f) = r.fault {
            println!("  PROBLEM: {f:?}");
            bad = true;
        }
    }
    if bad {
        anyhow::bail!("the journal does not verify");
    }
    println!("all journals verify");
    Ok(())
}

/// tells the audit process what the owner just did on the machine, if one has been set up here. `critical`: if it cannot be written down, do not do it.
async fn owner_note(dir: &std::path::Path, ev: yrl::auditlog::Event, critical: bool) -> anyhow::Result<()> {
    let Some(c) = yrl::ipc::audit_client(dir, "owner") else { return Ok(()) }; // no audit process set up in this directory
    match c.record_critical(ev).await {
        Ok(_) => Ok(()),
        Err(e) if critical => anyhow::bail!("this is not done because it cannot be written to the audit journal: {e}"),
        Err(e) => {
            eprintln!("warning: this could not be written to the audit journal ({e}); it is done all the same");
            Ok(())
        }
    }
}

async fn word_set(a: &[String]) -> anyhow::Result<()> {
    // yrld word set <dir> <sudo|root>   (the phrase from the terminal or standard input)
    let level = match a.get(4).map(String::as_str) {
        Some("sudo") => yrl::stepup::Level::Sudo,
        Some("root") => yrl::stepup::Level::Root,
        _ => anyhow::bail!("usage: yrld word set <dir> <sudo|root>"),
    };
    let dir = PathBuf::from(&a[3]);
    let phrase = yrl::prompt::read_password(&format!("phrase for {}: ", level.right()))?;
    // the fact is recorded first, the phrase never is
    owner_note(&dir, yrl::auditlog::Event::new("word_set", yrl::auditlog::LEVEL_NONE, yrl::auditlog::RESULT_OK).target(level.right()), true).await?;
    yrl::stepup::Verifier::set(&dir, level, &phrase)?;
    println!("saved (only a verifier of the {} phrase is stored)", level.right());
    Ok(())
}

async fn unlock(a: &[String]) -> anyhow::Result<()> {
    // yrld unlock <dir> <sudo|root|all>: the owner, on the machine (run as the user of the executor / of the broker). Nothing here can be done over the network.
    let dir = PathBuf::from(&a[2]);
    let names: Vec<&str> = match a.get(3).map(String::as_str) {
        Some("sudo") => vec!["sudo"],
        Some("root") => vec!["root"],
        Some("all") => vec!["sudo", "root"],
        _ => anyhow::bail!("usage: yrld unlock <dir> <sudo|root|all>"),
    };
    for n in names {
        owner_note(&dir, yrl::auditlog::Event::new("unlock", yrl::auditlog::LEVEL_NONE, yrl::auditlog::RESULT_OK).target(n), false).await?;
        yrl::stepup::Lockouts::reset_files(&yrl::ipc::state_dir(&dir, if n == "sudo" { "exec" } else { "broker" }), n)?;
        println!("lockouts for {n}: cleared");
    }
    Ok(())
}

/// the only part that changes the firewall
async fn firewall(dir: &str, a: &[String]) -> anyhow::Result<()> {
    let dir = PathBuf::from(dir);
    let opt = |name: &str| a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned();
    let ports: Vec<u16> = opt("--ports").ok_or_else(|| anyhow::anyhow!("--ports is needed: the work ports that stay closed until a knock"))?.split(',').map(|p| p.parse()).collect::<Result<_, _>>()?;
    let policy = yrl::firewall::Policy { work_ports: ports.clone(), max_ttl_secs: opt("--max-ttl").map(|t| t.parse()).transpose()?.unwrap_or(120), allow_loopback: a.iter().any(|x| x == "--allow-loopback"), ..Default::default() };
    let backend: Box<dyn yrl::firewall::Backend> = match opt("--backend").as_deref() {
        Some("mock") => Box::new(yrl::firewall::MockKernel::default()),
        _ => {
            let mut b = yrl::firewall::NftBackend { runner: yrl::firewall::RealRunner };
            b.install(&ports)?; // the permanent rules: the work ports are dropped unless the source is in the set
            Box::new(b)
        }
    };
    let audit = yrl::ipc::audit_client(&dir, "firewall");
    let svc = yrl::firewall::FirewallService::start(backend, policy, Box::new(yrl::gatenet::now_secs), audit)?;
    let ipc = yrl::ipc::load_firewall(&dir, opt("--gate-uid").map(|u| yrl::ipc::uid_arg(&u)).transpose()?, peer_exe(&opt("--gate-exe"))?)?;
    let listener = yrl::ipc::bind_socket(&ipc.socket)?;
    eprintln!("[yrld] firewall ready on {}", ipc.socket.display());
    if std::env::var_os("YRL_NO_SANDBOX").is_none() { yrl::sandbox::apply_firewall()?; }
    yrl::firewall::serve_ipc(listener, svc, ipc, std::sync::Arc::new(|m| eprintln!("[yrld] {m}"))).await;
    Ok(())
}
