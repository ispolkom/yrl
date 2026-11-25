//! The BROKER: the smallest part, the only one that may ever hold privileges. It listens on a local socket and nowhere else, talks only to the executor, and does
//! two things: answers the ROOT step-up (the phrase is encrypted to the BROKER's key, so even the executor cannot read it) and carries out the few typed operations
//! that ROOT may ask for. It does not run commands and has no way to be told to. Its checks of who may connect are the same four as the executor's.
use crate::executor::rights_for;
use crate::ipc::*;
use crate::server::ServerConfig;
use crate::session::{read_msg, server_handshake, write_msg, REKEY_EVERY};
use crate::stepup::{self, StepServer};
use crate::wire::Frame;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};

pub async fn serve_ipc(listener: UnixListener, cfg: ServerConfig, ipc: ExecutorIpc) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let (cfg, ipc) = (cfg.clone(), ipc.clone());
        tokio::spawn(async move { handle(stream, cfg, ipc).await });
    }
}

async fn handle(mut stream: UnixStream, cfg: ServerConfig, ipc: ExecutorIpc) {
    let Ok(cred) = stream.peer_cred() else { return };
    let verdict = judge_peer(&ipc, &Peer { uid: cred.uid(), pid: cred.pid() }, exe_of_pid);
    if verdict != PeerVerdict::Ok {
        cfg.log(format!("broker: connection refused: {verdict:?}"));
        cfg.rec(2, crate::auditlog::Event::new("peer_refused", crate::auditlog::LEVEL_NONE, crate::auditlog::RESULT_DENIED).target(&format!("{verdict:?}")));
        return;
    }
    let authorized = [crate::keys::Authorized { public: ipc.gatekeeper_public.clone(), label: "executor".into(), rights: vec![] }];
    let Ok(Ok((sec, _))) = tokio::time::timeout(Duration::from_secs(5), server_handshake(&mut stream, &ipc.key, &authorized, REKEY_EVERY)).await else {
        cfg.log("broker: connection refused: handshake".into());
        cfg.rec(2, crate::auditlog::Event::new("peer_refused", crate::auditlog::LEVEL_NONE, crate::auditlog::RESULT_DENIED).target("handshake"));
        return;
    };
    let (mut rd, mut wr) = stream.into_split();
    let Ok(Ok(msg)) = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut rd)).await else { return };
    let Ok(open) = sec.open(&msg) else { return };
    if open.kind != IPC_OPEN {
        return;
    }
    // the broker checks the account files for itself: the executor's word alone is not enough
    let verified = decode_open(&open.payload).ok().and_then(|(key, account, wanted)| rights_for(&cfg.dir, &key, &account, &wanted).map(|(rights, _)| (key, account, rights)));
    let Some((key, account, rights)) = verified else {
        cfg.log("broker: request refused: more than the account and the key allow".into());
        if let Ok(m) = sec.seal(&Frame::new(IPC_REFUSED, 0, vec![])) {
            let _ = write_msg(&mut wr, &m).await;
        }
        return;
    };
    let Ok(m) = sec.seal(&Frame::new(IPC_OK, 0, vec![])) else { return };
    if write_msg(&mut wr, &m).await.is_err() {
        return;
    }
    static SESSION_NO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1_000_000);
    let session_no = SESSION_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let sec = Arc::new(sec);
    let mut server = StepServer::default();
    while let Ok(msg) = read_msg(&mut rd).await {
        let Ok(f) = sec.open(&msg) else { break };
        let ctx = stepup::Ctx { dir: &cfg.dir, lockouts: &cfg.root_lockouts, my_key: &ipc.key, session_rights: &rights, device_key: &key, session_no, label: "broker", serves: &[stepup::Level::Root], log: &|l| cfg.log(l), audit: cfg.audit.broker.as_ref(), account: &account };
        let out = match f.kind {
            stepup::STEPUP_BEGIN => server.begin(&f.payload, &ctx),
            stepup::STEPUP_PROOF => server.proof(&f.payload, &ctx).await,
            _ => break, // the broker speaks of nothing else
        };
        let Ok(frames) = out else { break };
        for fr in frames {
            let Ok(m) = sec.seal(&fr) else { return };
            if write_msg(&mut wr, &m).await.is_err() {
                return;
            }
        }
    }
}
