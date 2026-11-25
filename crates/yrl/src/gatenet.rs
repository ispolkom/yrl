//! The network gate of the gatekeeper: listens for SPA datagrams and, for a valid one, asks the firewall program to let that source address try the work port for a while.
//! It never answers a datagram. Why a datagram was dropped goes to the local security journal, in words the sender never sees.
use crate::auditlog::{Event, LEVEL_NONE, RESULT_DENIED, RESULT_ERROR, RESULT_OK};
use crate::firewall::{FirewallClient, Request};
use crate::server::ServerConfig;
use crate::spa::{Reject, SpaVerifier};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// runs until the task is dropped; `ttl_secs` is how long a valid knock lets its address in
pub async fn spa_listen(sock: UdpSocket, verifier: Arc<SpaVerifier>, fw: FirewallClient, work_port: u16, ttl_secs: u32, cfg: ServerConfig) {
    let mut buf = vec![0u8; 2048];
    // a rejection is written down once per reason and source in a while, not once per packet of a flood
    let mut told: HashMap<(Reject, IpAddr), u64> = HashMap::new();
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
        let src = from.ip().to_canonical();
        let now = now_secs();
        let packet = buf[..n.min(buf.len())].to_vec();
        match verifier.verify(&packet, src, now) {
            Err(why) => {
                if told.len() > 10_000 {
                    told.clear();
                }
                let due = told.get(&(why, src)).is_none_or(|t| now >= t + 10);
                if due {
                    told.insert((why, src), now);
                    cfg.log(format!("spa: dropped ({})", why.name()));
                    cfg.rec(0, Event::new("spa_rejected", LEVEL_NONE, RESULT_DENIED).target(why.name()));
                }
            }
            Ok(acc) => {
                // the address that is let in is the one the datagram came from; the one written inside the packet is not looked at
                let mut session = [0u8; 16];
                session.copy_from_slice(&blake3::hash(&acc.vip).as_bytes()[..16]);
                match fw.call(Request::Open { addr: src, port: work_port, ttl_secs, session }).await {
                    Ok(_) => {
                        cfg.log("spa: accepted".into());
                        cfg.rec(0, Event::new("spa_ok", LEVEL_NONE, RESULT_OK).device(&acc.client_public).code(ttl_secs.min(65535) as u16));
                    }
                    Err(e) => {
                        // the firewall did not open: nothing is open, and that is all the sender will ever learn (nothing)
                        cfg.log(format!("spa: valid, but the firewall did not open: {e}"));
                        cfg.rec(0, Event::new("spa_error", LEVEL_NONE, RESULT_ERROR).device(&acc.client_public).target("firewall"));
                    }
                }
            }
        }
    }
}
