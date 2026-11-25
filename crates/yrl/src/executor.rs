//! The EXECUTOR: the part of the server that does things on the machine (programs, terminals, files, directories, tunnels), as the account's system user.
//! It never listens on the network. It listens on a local Unix socket and talks only to the gatekeeper (src/server.rs), which does everything that touches the network.
//! Who may connect is decided by FOUR independent checks (docs/THREATS.md, section G): the socket's permissions, the operating system's word about the other
//! process (uid, pid), the other process's executable path, and a Noise handshake with a key that was set up in advance for exactly this pair.
//! What a session may do is decided HERE, from the account files, not from what the gatekeeper says: the gatekeeper can ask for a subset of what an account and a key
//! already have, nothing more, and cannot choose the system user the commands run as.
use crate::exec;
use crate::files::{self, FileIn};
use crate::filewire::{self as fw, GetReq, PutReq};
use crate::fsops::{self, FsReq};
use crate::identity::{self, Target};
use crate::keys::read_authorized;
use crate::pty::{self, PtyCmd};
use crate::resources::OperationKind;
use crate::server::ServerConfig;
use crate::stepup;
use crate::session::{read_msg, server_handshake, write_msg, REKEY_EVERY};
use crate::tunnel::{self, TunIn};
use crate::tunwire as tw;
use crate::users::read_users;
use crate::wire::{self, split_id, with_id, ExecReq, Frame};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Semaphore};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthSnapshot {
    key_rights: Vec<String>,
    account_rights: Vec<String>,
    password_hash: String,
    os_user: Option<String>,
}

pub(crate) fn auth_snapshot(dir: &std::path::Path, key: &[u8], account: &str) -> Option<AuthSnapshot> {
    let k = read_authorized(&dir.join("authorized_keys")).into_iter().find(|a| a.public == key)?;
    let u = read_users(&dir.join("users")).into_iter().find(|u| u.login == account)?;
    let mut key_rights = k.rights;
    let mut account_rights = u.rights;
    key_rights.sort();
    account_rights.sort();
    Some(AuthSnapshot { key_rights, account_rights, password_hash: u.phc, os_user: u.os_user })
}

fn denied(code: u16, text: &[u8], id: u64) -> Frame {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(text);
    Frame::new(wire::ERROR, 0, with_id(id, &p))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn session_main(cfg: ServerConfig, label: String, account: String, key: Vec<u8>, exec_key: crate::keys::KeyPair, session_rights: Vec<String>, target: Target, auth: AuthSnapshot, mut inbound: mpsc::Receiver<Frame>, tx: mpsc::Sender<Frame>) {
    let who = crate::keys::Authorized { public: key, label, rights: vec![] };
    static SESSION_NO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let session_no = SESSION_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut session_cgroup = if std::env::var_os("YRL_SESSION_CGROUPS").is_some() {
        match crate::cgroup::SessionCgroup::create(session_no) {
            Ok(cg) => Some(cg),
            Err(e) => { cfg.log(format!("session refused: cgroup isolation unavailable: {e}")); return; }
        }
    } else { None };
    use crate::auditlog::{Event, LEVEL_USER, RESULT_DENIED, RESULT_OK};
    let sess = session_no.to_be_bytes();
    let ev = |op: &str, result: u8| Event::new(op, LEVEL_USER, result).session(&sess).device(&who.public).user(&account);
    cfg.rec(1, ev("session_open", RESULT_OK));
    let mut step_server = stepup::StepServer::default();
    let mut root_ids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut broker_pipe: Option<mpsc::Sender<Frame>> = None;
    let target = Some(target);
    let slots = Arc::new(Semaphore::new(cfg.max_exec_per_connection));
    let fs_slots = Arc::new(Semaphore::new(8));
    let mut ptys: std::collections::HashMap<u64, mpsc::Sender<PtyCmd>> = std::collections::HashMap::new();
    let mut transfers: std::collections::HashMap<u64, mpsc::Sender<FileIn>> = std::collections::HashMap::new();
    let mut tunnels: std::collections::HashMap<u64, mpsc::Sender<TunIn>> = std::collections::HashMap::new();
    let mut jobs = tokio::task::JoinSet::new();
    while let Some(frame) = inbound.recv().await {
        while jobs.try_join_next().is_some() {}
        if auth_snapshot(&cfg.dir, &who.public, &account).as_ref() != Some(&auth) { break }
        match frame.kind {
            wire::PING => {
                let _ = tx.send(Frame::new(wire::PONG, frame.stream, frame.payload)).await;
            }
            wire::EXEC_REQ => {
                let Ok(req) = ExecReq::decode(&frame.payload) else {
                    cfg.log("session closed (bad request)".into());
                    break;
                };
                let id = req.request_id;
                if !session_rights.iter().any(|r| r == "exec") {
                    let _ = tx.send(denied(1, b"not permitted", id)).await;
                    cfg.log(format!("exec denied via '{}'", who.label));
                    cfg.rec(1, ev("denied", RESULT_DENIED).target("exec").request(id));
                    continue;
                }
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    let _ = tx.send(denied(5, b"too many running requests", id)).await;
                    continue;
                };
                let Some(resource) = cfg.resources.try_operation(session_no, &who.public, &account, OperationKind::Exec) else {
                    let _ = tx.send(denied(5, b"server operation budget exhausted", id)).await;
                    continue;
                };
                cfg.log(format!("exec started via '{}'", who.label));
                {
                    let name = req.argv.first().map(|a| String::from_utf8_lossy(a.rsplit(|c| *c == b'/').next().unwrap_or(a)).into_owned()).unwrap_or_default();
                    cfg.rec(1, ev("exec", RESULT_OK).named_hidden_target(&name, &req.argv.join(&b' ')).request(id));
                }
                let tx2 = tx.clone();
                let Some(t) = target.clone() else { break };
                let cgroup = session_cgroup.as_ref().map(|cg| cg.attachment());
                jobs.spawn(async move {
                    exec::run(req, t, tx2, cgroup).await;
                    drop(permit);
                    drop(resource);
                });
            }
            wire::PTY_OPEN => {
                let Ok((pid, rows, cols, term)) = wire::decode_pty_open(&frame.payload) else {
                    cfg.log("session closed (bad terminal request)".into());
                    break;
                };
                if !session_rights.iter().any(|r| r == "shell") {
                    let _ = tx.send(denied(1, b"not permitted", pid)).await;
                    cfg.log(format!("terminal denied via '{}'", who.label));
                    cfg.rec(1, ev("denied", RESULT_DENIED).target("pty").request(pid));
                    continue;
                }
                ptys.retain(|_, c| !c.is_closed());
                if ptys.len() >= cfg.max_pty_per_connection || ptys.contains_key(&pid) {
                    let _ = tx.send(denied(5, b"too many terminals or id in use", pid)).await;
                    continue;
                }
                let Some(resource) = cfg.resources.try_operation(session_no, &who.public, &account, OperationKind::Pty) else {
                    let _ = tx.send(denied(5, b"server operation budget exhausted", pid)).await;
                    continue;
                };
                let Some(t) = target.clone() else { break };
                let (ctx, crx) = mpsc::channel(64);
                ptys.insert(pid, ctx);
                cfg.log(format!("terminal started via '{}'", who.label));
                cfg.rec(1, ev("pty", RESULT_OK).target("shell").request(pid));
                let (term, tx2) = (pty::clean_term(term), tx.clone());
                let cgroup = session_cgroup.as_ref().map(|cg| cg.attachment());
                jobs.spawn(async move {
                    pty::run(pid, rows, cols, term, t, crx, tx2, cgroup).await;
                    drop(resource);
                });
            }
            wire::PTY_IN => {
                let Ok((pid, data)) = split_id(&frame.payload) else { break };
                if let Some(c) = ptys.get(&pid) {
                    let _ = c.send(PtyCmd::Input(data.to_vec())).await;
                }
            }
            wire::PTY_RESIZE => {
                let Ok((pid, r, c)) = wire::decode_resize(&frame.payload) else { break };
                if let Some(ch) = ptys.get(&pid) {
                    let _ = ch.send(PtyCmd::Resize(r, c)).await;
                }
            }
            wire::PTY_CLOSE => {
                let Ok((pid, _)) = split_id(&frame.payload) else { break };
                if let Some(c) = ptys.remove(&pid) {
                    let _ = c.send(PtyCmd::Hangup).await;
                }
            }
            fw::FILE_PUT | fw::FILE_GET => {
                let (fid, put) = match frame.kind {
                    fw::FILE_PUT => match PutReq::decode(&frame.payload) {
                        Ok(r) => (r.id, Some(r)),
                        Err(_) => break,
                    },
                    _ => match GetReq::decode(&frame.payload) {
                        Ok(r) => (r.id, None),
                        Err(_) => break,
                    },
                };
                if !session_rights.iter().any(|r| r == "files") {
                    let _ = tx.send(denied(1, b"not permitted", fid)).await;
                    cfg.log(format!("file transfer denied via '{}'", who.label));
                    cfg.rec(1, ev("denied", RESULT_DENIED).target("file").request(fid));
                    continue;
                }
                transfers.retain(|_, c| !c.is_closed());
                if transfers.len() >= cfg.max_transfers_per_connection || transfers.contains_key(&fid) {
                    let _ = tx.send(denied(5, b"too many transfers or id in use", fid)).await;
                    continue;
                }
                let Some(resource) = cfg.resources.try_operation(session_no, &who.public, &account, OperationKind::Transfer) else {
                    let _ = tx.send(denied(5, b"server operation budget exhausted", fid)).await;
                    continue;
                };
                let Some(t) = target.clone() else { break };
                let (ctx, crx) = mpsc::channel(16);
                transfers.insert(fid, ctx);
                cfg.log(format!("file transfer started via '{}'", who.label));
                match &put {
                    Some(r) => cfg.rec(1, ev("file", RESULT_OK).named_hidden_target("put", &r.path).request(fid)),
                    None => {
                        if let Ok(r) = GetReq::decode(&frame.payload) {
                            cfg.rec(1, ev("file", RESULT_OK).named_hidden_target("get", &r.path).request(fid));
                        }
                    }
                }
                let (tx2, helper) = (tx.clone(), cfg.helper.clone());
                let max_file_size = cfg.max_file_size;
                match put {
                    Some(r) => {
                        let cgroup = session_cgroup.as_ref().map(|cg| cg.attachment());
                        jobs.spawn(async move {
                            files::put(r, t, helper, max_file_size, crx, tx2, cgroup).await;
                            drop(resource);
                        });
                    }
                    None => {
                        let r = GetReq::decode(&frame.payload).expect("decoded above");
                        let cgroup = session_cgroup.as_ref().map(|cg| cg.attachment());
                        jobs.spawn(async move {
                            files::get(r, t, helper, crx, tx2, cgroup).await;
                            drop(resource);
                        });
                    }
                }
            }
            fw::FILE_DATA | fw::FILE_END | fw::FILE_ABORT => {
                let Ok((fid, data)) = split_id(&frame.payload) else { break };
                let msg = match frame.kind {
                    fw::FILE_DATA => FileIn::Data(data.to_vec()),
                    fw::FILE_END => FileIn::End,
                    _ => FileIn::Abort,
                };
                if let Some(c) = transfers.get(&fid) {
                    let _ = c.send(msg).await;
                }
            }
            tw::TUN_OPEN => {
                let Ok((tid, host, port)) = tw::decode_open(&frame.payload) else {
                    cfg.log("session closed (bad tunnel request)".into());
                    break;
                };
                if !session_rights.iter().any(|r| r == "tunnel") {
                    let _ = tx.send(denied(1, b"not permitted", tid)).await;
                    cfg.log(format!("tunnel denied via '{}'", who.label));
                    cfg.rec(1, ev("denied", RESULT_DENIED).target("tunnel").request(tid));
                    continue;
                }
                if !tunnel::permits(&tunnel::read_rules(&cfg.dir.join("tunnels")), &account, &host, port) {
                    let _ = tx.send(denied(tw::E_DENIED, b"this destination is not allowed", tid)).await;
                    cfg.log(format!("tunnel refused by the rules via '{}'", who.label)); // the destination is not logged
                    cfg.rec(1, ev("denied", RESULT_DENIED).named_hidden_target("tunnel-rule", format!("{host}:{port}").as_bytes()).request(tid));
                    continue;
                }
                tunnels.retain(|_, c| !c.is_closed());
                if tunnels.len() >= cfg.max_tunnels_per_connection || tunnels.contains_key(&tid) {
                    let _ = tx.send(denied(5, b"too many tunnels or id in use", tid)).await;
                    continue;
                }
                let Some(resource) = cfg.resources.try_operation(session_no, &who.public, &account, OperationKind::Tunnel) else {
                    let _ = tx.send(denied(5, b"server operation budget exhausted", tid)).await;
                    continue;
                };
                let (ctx, crx) = mpsc::channel(64);
                tunnels.insert(tid, ctx);
                cfg.log(format!("tunnel opened via '{}'", who.label));
                cfg.rec(1, ev("tunnel", RESULT_OK).named_hidden_target("open", format!("{host}:{port}").as_bytes()).request(tid));
                let timeout = cfg.tunnel_connect_timeout;
                let tx2 = tx.clone();
                jobs.spawn(async move {
                    tunnel::run(tid, host, port, timeout, crx, tx2).await;
                    drop(resource);
                });
            }
            tw::TUN_DATA | tw::TUN_EOF | tw::TUN_CLOSE => {
                let Ok((tid, data)) = split_id(&frame.payload) else { break };
                let msg = match frame.kind {
                    tw::TUN_DATA => TunIn::Data(data.to_vec()),
                    tw::TUN_EOF => TunIn::Eof,
                    _ => TunIn::Close,
                };
                if let Some(c) = tunnels.get(&tid) {
                    let _ = c.send(msg).await;
                }
            }
            fsops::FS_REQ => {
                let Ok(req) = FsReq::decode(&frame.payload) else {
                    cfg.log("session closed (bad directory request)".into());
                    break;
                };
                if !session_rights.iter().any(|r| r == "files") {
                    let _ = tx.send(denied(1, b"not permitted", req.id)).await;
                    cfg.rec(1, ev("denied", RESULT_DENIED).target("fs").request(req.id));
                    continue;
                }
                if req.op != fsops::OP_LS && req.op != fsops::OP_STAT && req.op != fsops::OP_REAL {
                    // listing is routine; changing things is recorded
                    let name = match req.op {
                        fsops::OP_MKDIR => "mkdir",
                        fsops::OP_RM => "remove",
                        _ => "rename",
                    };
                    cfg.rec(1, ev("fs", RESULT_OK).named_hidden_target(name, &req.a).request(req.id));
                }
                let Ok(permit) = fs_slots.clone().try_acquire_owned() else {
                    let _ = tx.send(denied(5, b"too many directory requests", req.id)).await;
                    continue;
                };
                let Some(resource) = cfg.resources.try_operation(session_no, &who.public, &account, OperationKind::Fs) else {
                    let _ = tx.send(denied(5, b"server operation budget exhausted", req.id)).await;
                    continue;
                };
                let Some(t) = target.clone() else { break };
                let (tx2, helper) = (tx.clone(), cfg.helper.clone());
                let cgroup = session_cgroup.as_ref().map(|cg| cg.attachment());
                jobs.spawn(async move {
                    fsops::run(req, t, helper, tx2, cgroup).await;
                    drop(permit);
                    drop(resource);
                });
            }
            stepup::STEPUP_BEGIN | stepup::STEPUP_PROOF => {
                // ROOT is the broker's business, end to end: the executor only carries those bytes. SUDO is answered here.
                let is_root = if frame.kind == stepup::STEPUP_BEGIN { stepup::decode_begin(&frame.payload).map(|b| b.1 == stepup::Level::Root).unwrap_or(false) } else { root_ids.contains(&stepup::decode_msg(&frame.payload).map(|m| m.0).unwrap_or(0)) };
                if is_root {
                    let rid = if frame.kind == stepup::STEPUP_BEGIN { stepup::decode_begin(&frame.payload).map(|b| b.0).unwrap_or(0) } else { stepup::decode_msg(&frame.payload).map(|m| m.0).unwrap_or(0) };
                    if frame.kind == stepup::STEPUP_BEGIN {
                        root_ids.insert(rid);
                    }
                    if broker_pipe.is_none() {
                        broker_pipe = match &cfg.broker {
                            Some(b) => open_broker(b, &who.public, &account, &session_rights, tx.clone()).await,
                            None => None,
                        };
                    }
                    match &broker_pipe {
                        Some(to_broker) => {
                            let _ = to_broker.send(frame).await;
                        }
                        None => {
                            let _ = tx.send(Frame::new(stepup::STEPUP_RESULT, 0, stepup::encode_result(rid, stepup::R_DENIED, ""))).await;
                        }
                    }
                    continue;
                }
                let ctx = stepup::Ctx { dir: &cfg.dir, lockouts: &cfg.lockouts, my_key: &exec_key, session_rights: &session_rights, device_key: &who.public, session_no, label: &who.label, serves: &[stepup::Level::Sudo], log: &|l| cfg.log(l), audit: cfg.audit.exec.as_ref(), account: &account };
                let out = if frame.kind == stepup::STEPUP_BEGIN { step_server.begin(&frame.payload, &ctx) } else { step_server.proof(&frame.payload, &ctx).await };
                match out {
                    Ok(frames) => {
                        for f in frames {
                            let _ = tx.send(f).await;
                        }
                    }
                    Err(()) => {
                        cfg.log("session closed (bad step-up frame)".into());
                        break;
                    }
                }
            }
            wire::CLOSE => break,
            wire::LOGIN => break, // a second login inside a session is not a thing
            _ => {} // unknown kinds are ignored (reserved space)
        }
    }
    drop(ptys); // every terminal gets its hangup
    drop(tunnels); // every tunnel is closed
    drop(transfers); // every transfer is stopped; partial files stay for a resume
    if let Some(cg) = &mut session_cgroup {
        if let Err(e) = cg.kill() { cfg.log(format!("session cgroup kill failed: {e}")); }
    }
    // PTYs get a chance to deliver SIGHUP to the entire process group. Other jobs are then
    // cancelled; their child processes use kill_on_drop.
    if tokio::time::timeout(Duration::from_secs(3), async { while jobs.join_next().await.is_some() {} }).await.is_err() {
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
    }
    if let Some(cg) = &mut session_cgroup {
        if let Err(e) = cg.finish().await { cfg.log(format!("session cgroup cleanup failed: {e}")); }
    }
    cfg.rec(1, ev("session_close", RESULT_OK));
    drop(tx);
    cfg.log(format!("session closed via '{}'", who.label));
}


// ---------------------------------------------------------------- the local door

pub async fn serve_ipc(listener: UnixListener, cfg: ServerConfig, ipc: crate::ipc::ExecutorIpc) {
    let preauth = Arc::new(Semaphore::new(64));
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let Ok(slot) = preauth.clone().try_acquire_owned() else { continue };
        let (cfg, ipc) = (cfg.clone(), ipc.clone());
        tokio::spawn(async move { handle_ipc(stream, cfg, ipc).await; drop(slot); });
    }
}

/// what an account and a key really allow, read from the files (not from the gatekeeper)
pub fn rights_for(dir: &std::path::Path, key: &[u8], account: &str, wanted: &[String]) -> Option<(Vec<String>, Option<String>)> {
    let k = read_authorized(&dir.join("authorized_keys")).into_iter().find(|a| a.public == key)?;
    let u = read_users(&dir.join("users")).into_iter().find(|u| u.login == account)?;
    if wanted.iter().any(|r| !(u.rights.contains(r) && k.rights.contains(r))) {
        return None; // asked for more than the account and the key both have
    }
    Some((wanted.to_vec(), u.os_user))
}

async fn handle_ipc(mut stream: UnixStream, cfg: ServerConfig, ipc: crate::ipc::ExecutorIpc) {
    use crate::ipc::*;
    // 1. what the operating system says about the other process
    let Ok(cred) = stream.peer_cred() else { return };
    let peer = Peer { uid: cred.uid(), pid: cred.pid() };
    let verdict = judge_peer(&ipc, &peer, exe_of_pid);
    if verdict != PeerVerdict::Ok {
        cfg.log(format!("local connection refused: {verdict:?}"));
        cfg.rec(1, crate::auditlog::Event::new("peer_refused", crate::auditlog::LEVEL_NONE, crate::auditlog::RESULT_DENIED).target(&format!("{verdict:?}")));
        return;
    }
    // 2. the key set up in advance for this pair (an unknown key gets silence)
    let authorized = [crate::keys::Authorized { public: ipc.gatekeeper_public.clone(), label: "gatekeeper".into(), rights: vec![] }];
    let hs = tokio::time::timeout(Duration::from_secs(5), server_handshake(&mut stream, &ipc.key, &authorized, REKEY_EVERY)).await;
    let Ok(Ok((sec, _))) = hs else {
        cfg.log("local connection refused: handshake".into());
        cfg.rec(1, crate::auditlog::Event::new("peer_refused", crate::auditlog::LEVEL_NONE, crate::auditlog::RESULT_DENIED).target("handshake"));
        return;
    };
    let (mut rd, mut wr) = stream.into_split();
    // 3. only an opaque tunnel may be opened. Client identity and authorization are established by
    // a second Noise IK handshake that terminates here, never by assertions from the gatekeeper.
    let Ok(Ok(msg)) = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut rd)).await else { return };
    let Ok(open) = sec.open(&msg) else { return };
    if open.kind != IPC_TUNNEL || open.payload.len() > 64 {
        cfg.log("local connection refused: no tunnel request".into());
        return;
    }
    let peer = if open.payload.is_empty() {
        None
    } else {
        std::str::from_utf8(&open.payload).ok().and_then(|s| s.parse().ok())
    };
    if !open.payload.is_empty() && peer.is_none() { return }
    let sec = Arc::new(sec);
    let Ok(m) = sec.seal(&Frame::new(IPC_TUNNEL_OK, 0, vec![])) else { return };
    if write_msg(&mut wr, &m).await.is_err() {
        return;
    }
    let tunnel = crate::ipc::secure_tunnel(rd, wr, sec);
    crate::server::handle_inner(tunnel, peer, ipc.key.clone(), cfg).await;
}

// ---------------------------------------------------------------- the gatekeeper's side of the same door

/// asks the executor for a session; on success returns the two ends of the frame pipe
pub async fn open_session(g: &crate::ipc::GatekeeperIpc, key: &[u8], account: &str, rights: &[String]) -> Option<(mpsc::Sender<Frame>, mpsc::Receiver<Frame>)> {
    use crate::ipc::*;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&g.socket)).await.ok()?.ok()?;
    let sec = tokio::time::timeout(Duration::from_secs(5), crate::session::client_handshake(&mut stream, &g.key, &g.executor_public, REKEY_EVERY)).await.ok()?.ok()?;
    let (mut rd, mut wr) = stream.into_split();
    write_msg(&mut wr, &sec.seal(&open_frame(key, account, rights).ok()?).ok()?).await.ok()?;
    let msg = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut rd)).await.ok()?.ok()?;
    if sec.open(&msg).ok()?.kind != IPC_OK {
        return None;
    }
    let sec = Arc::new(sec);
    let (to_exec, mut from_gate) = mpsc::channel::<Frame>(64);
    let (to_gate, from_exec) = mpsc::channel::<Frame>(64);
    let sec_r = sec.clone();
    tokio::spawn(async move {
        while let Ok(m) = read_msg(&mut rd).await {
            let Ok(f) = sec_r.open(&m) else { break };
            if to_gate.send(f).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(f) = from_gate.recv().await {
            let Ok(m) = sec.seal(&f) else { break };
            if write_msg(&mut wr, &m).await.is_err() {
                break;
            }
        }
    });
    Some((to_exec, from_exec))
}

/// Gatekeeper side of the executor door. It receives only an opaque stream; there are deliberately
/// no key/account/rights arguments for a compromised gatekeeper to forge.
pub async fn open_tunnel(g: &crate::ipc::GatekeeperIpc, peer: Option<std::net::SocketAddr>) -> Option<tokio::io::DuplexStream> {
    use crate::ipc::*;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&g.socket)).await.ok()?.ok()?;
    let sec = tokio::time::timeout(Duration::from_secs(5), crate::session::client_handshake(&mut stream, &g.key, &g.executor_public, REKEY_EVERY)).await.ok()?.ok()?;
    let sec = Arc::new(sec);
    let (mut rd, mut wr) = stream.into_split();
    // The peer address is an availability/rate-limit hint only. It is never used for identity,
    // authorization, or access rights, because a compromised Gatekeeper can forge it.
    let payload = peer.map(|p| p.to_string().into_bytes()).unwrap_or_default();
    let open = sec.seal(&Frame::new(IPC_TUNNEL, 0, payload)).ok()?;
    write_msg(&mut wr, &open).await.ok()?;
    let msg = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut rd)).await.ok()?.ok()?;
    let reply = sec.open(&msg).ok()?;
    if reply.kind != IPC_TUNNEL_OK || !reply.payload.is_empty() { return None }
    Some(crate::ipc::secure_tunnel(rd, wr, sec))
}

/// Starts the already authenticated user's operational session inside Executor. The inputs come
/// from the Client <-> Executor Noise endpoint, not from Gatekeeper, and are checked against disk again.
pub(crate) async fn direct_session(cfg: &ServerConfig, key: &[u8], account: &str, wanted: &[String]) -> Option<(mpsc::Sender<Frame>, mpsc::Receiver<Frame>)> {
    let Some((rights, os_user)) = rights_for(&cfg.dir, key, account, wanted) else {
        cfg.log("executor authorization refused: account/key rights do not permit the request".into());
        return None;
    };
    let target = match identity::resolve(os_user.as_deref(), identity::euid(), &rights, identity::lookup_name, identity::lookup_uid) {
        Ok(target) => target,
        Err(why) => {
            cfg.log(format!("executor identity refused: {}", why.why()));
            return None;
        }
    };
    let exec_key = cfg.exec_identity.clone()?;
    let auth = auth_snapshot(&cfg.dir, key, account)?;
    let (to_exec, in_rx) = mpsc::channel::<Frame>(64);
    let (out_tx, from_exec) = mpsc::channel::<Frame>(64);
    let cfg = cfg.clone();
    let key = key.to_vec();
    let account = account.to_string();
    tokio::spawn(session_main(cfg, "end-to-end client".into(), account, key, exec_key, rights, target, auth, in_rx, out_tx));
    Some((to_exec, from_exec))
}


/// the executor's pipe to the broker for one session: whatever the broker answers goes straight to the client
async fn open_broker(b: &crate::ipc::GatekeeperIpc, key: &[u8], account: &str, rights: &[String], to_client: mpsc::Sender<Frame>) -> Option<mpsc::Sender<Frame>> {
    let (to_broker, mut from_broker) = open_session(b, key, account, rights).await?;
    tokio::spawn(async move {
        while let Some(f) = from_broker.recv().await {
            if to_client.send(f).await.is_err() {
                break;
            }
        }
    });
    Some(to_broker)
}
