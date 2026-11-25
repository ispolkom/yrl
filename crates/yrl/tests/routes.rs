//! Route failover keeps one authenticated, resumable server session alive.
mod common;

use common::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use yrl::client::{ClientOptions, Transport};
use yrl::relay::{self, RelayConfig};
use yrl::server::{serve_udp, serve_via_relay};

const W: Duration = Duration::from_secs(30);

fn failover_opts() -> ClientOptions {
    ClientOptions {
        ping_every: Duration::from_millis(50),
        dead_after: Duration::from_millis(400),
        retry_min: Duration::from_millis(20),
        retry_max: Duration::from_millis(100),
        connect_timeout: Duration::from_secs(5),
        route_timeout: Duration::from_millis(500),
        give_up_after: Duration::from_secs(15),
        ..Default::default()
    }
}

async fn switchable_udp_proxy(target: String) -> (String, Arc<AtomicBool>) {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = front.local_addr().unwrap().to_string();
    let disabled = Arc::new(AtomicBool::new(false));
    let off = disabled.clone();
    tokio::spawn(async move {
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        back.connect(target).await.unwrap();
        let mut client = None;
        let (mut a, mut b) = (vec![0u8; 2048], vec![0u8; 2048]);
        loop {
            tokio::select! {
                incoming = front.recv_from(&mut a) => {
                    let Ok((n, from)) = incoming else { return };
                    client = Some(from);
                    if !off.load(Ordering::SeqCst) { let _ = back.send(&a[..n]).await; }
                }
                incoming = back.recv(&mut b) => {
                    let Ok(n) = incoming else { return };
                    if !off.load(Ordering::SeqCst) {
                        if let Some(to) = client { let _ = front.send_to(&b[..n], to).await; }
                    }
                }
            }
        }
    });
    (addr, disabled)
}

async fn wait_for(path: &std::path::Path) {
    tokio::time::timeout(W, async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn udp_to_tcp_resumes_the_same_session_without_reexecuting_a_command() {
    let r = rig_with("exec,shell,files,tunnel", |mut c| {
        c.session_grace = Duration::from_secs(30);
        c
    }).await;
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_addr = udp.local_addr().unwrap().to_string();
    tokio::spawn(serve_udp(udp, r.server_key.clone(), r.cfg.clone()));
    let (proxy, disabled) = switchable_udp_proxy(udp_addr).await;
    let mut opts = failover_opts();
    opts.udp = Some(proxy);
    let c = open_via(&r, &r.addr, opts).await;
    assert_eq!(c.connection_diagnostics().current, Some(Transport::Udp));

    let mut pty = c.pty_open(24, 80, "xterm").await.unwrap();
    pty.write(b"export ROUTE_MARK=kept; printf '\\120\\111\\104=%s\\n' $$\n").await.unwrap();
    let first = pty.read_until("PID=", W).await.unwrap();
    let pid: String = first.split("PID=").nth(1).unwrap().chars().take_while(|c| c.is_ascii_digit()).collect();

    let marker = r.dir.path().join("exec-count");
    let script = format!("printf x >> '{}'; sleep 2; printf done", marker.display());
    let args: [&[u8]; 3] = [b"/bin/sh", b"-c", script.as_bytes()];
    let command = c.exec(&args, 10_000, W);
    let break_route = async {
        wait_for(&marker).await;
        disabled.store(true, Ordering::SeqCst);
    };
    let (result, ()) = tokio::join!(command, break_route);
    assert_eq!(result.unwrap().stdout, b"done");
    assert_eq!(std::fs::read(&marker).unwrap(), b"x", "the accepted request ran exactly once");

    pty.write(b"printf '\\120\\111\\104=%s \\115\\101\\122\\113=%s\\n' $$ \"$ROUTE_MARK\"\n").await.unwrap();
    let after = pty.read_until("MARK=kept", W).await.unwrap();
    assert!(after.contains(&format!("PID={pid} MARK=kept")), "the same remote shell survived: {after}");
    let d = c.connection_diagnostics();
    assert_eq!(d.current, Some(Transport::Tcp));
    assert!(d.disconnects >= 1 && d.resumes >= 1 && d.switches >= 1);
    assert_eq!(r.sessions.len(), 1);
}

async fn echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let (mut rd, mut wr) = socket.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    (port, task)
}

#[tokio::test]
async fn direct_tcp_to_relay_preserves_terminal_file_transfer_and_tunnel() {
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap().to_string();
    let _relay = relay::serve(relay_listener, RelayConfig::default()).await;
    let r = rig_with("exec,shell,files,tunnel", |mut c| {
        c.session_grace = Duration::from_secs(30);
        c
    }).await;
    tokio::spawn(serve_via_relay(relay_addr.clone(), r.server_key.clone(), r.cfg.clone(), 2));
    let direct = common::chaos::Chaos::start(&r.addr).await;
    let mut opts = failover_opts();
    opts.relay = Some(relay_addr);
    let c = Arc::new(open_via(&r, &direct.addr, opts).await);
    assert_eq!(c.connection_diagnostics().current, Some(Transport::Tcp));

    let mut pty = c.pty_open(24, 80, "xterm").await.unwrap();
    pty.write(b"export ROUTE_MARK=relay-kept; printf '\\120\\111\\104=%s\\n' $$\n").await.unwrap();
    let first = pty.read_until("PID=", W).await.unwrap();
    let pid: String = first.split("PID=").nth(1).unwrap().chars().take_while(|c| c.is_ascii_digit()).collect();

    let (port, _echo) = echo_server().await;
    let rules = r.server_dir().join("tunnels");
    std::fs::write(&rules, format!("anna 127.0.0.1 {port}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let tunnel = c.tunnel_open("127.0.0.1", port, W).await.unwrap();

    let source = r.dir.path().join("source");
    let target = r.dir.path().join("target");
    let bytes = vec![0x5au8; 6 << 20];
    std::fs::write(&source, &bytes).unwrap();
    direct.refuse(true);
    direct.cut();
    c.put_file(&source, target.to_str().unwrap().as_bytes(), 0o600, W).await.unwrap();
    assert_eq!(std::fs::read(target).unwrap(), bytes);

    pty.write(b"printf '\\120\\111\\104=%s \\115\\101\\122\\113=%s\\n' $$ \"$ROUTE_MARK\"\n").await.unwrap();
    let after = pty.read_until("MARK=relay-kept", W).await.unwrap();
    assert!(after.contains(&format!("PID={pid} MARK=relay-kept")), "the same remote shell survived: {after}");
    tunnel.send(b"same tunnel").await.unwrap();
    let echoed = tokio::time::timeout(W, tunnel.recv()).await.unwrap().unwrap();
    assert_eq!(echoed, b"same tunnel");

    let d = c.connection_diagnostics();
    assert_eq!(d.current, Some(Transport::Relay));
    assert!(d.last_rtt.is_some() && d.disconnects >= 1 && d.resumes >= 1 && d.switches >= 1);
    assert_eq!(r.sessions.len(), 1);
}
