//! Single Packet Authorization: one small datagram that asks the machine to let the sender's address try to reach the real YRL port for a short while.
//! It carries no trust. It opens no session, shows no banner, gets NO answer of any kind (so it cannot be used to reflect or amplify anything), and its only effect is a
//! temporary entry in the firewall's allow-set, made by the separate firewall program. After it, the real port still demands the full key + login handshake.
//!
//! Packet (94 bytes, fixed): `YSPA` ver(1) client_id(8) server_id(8) service(1) timestamp(8) nonce(16) virtual_ipv6(16) mac(32).
//! The mac is a keyed BLAKE3 over everything before it, keyed with a secret that only the device's private key and the server's public key (or the other way round) can make:
//! X25519(device private, server public) = X25519(server private, device public). No new key to manage: the keys that are already registered are the ones that count.
//! The server id is in the mac, so a packet for one server is useless at another. The address that is let through is the one the datagram really CAME FROM, never one written inside.
use crate::keys::{read_authorized, KeyPair};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::Mutex;

pub const LEN: usize = 94;
pub const MAGIC: &[u8; 4] = b"YSPA";
pub const VERSION: u8 = 1;
/// the only service so far: the YRL work port
pub const SERVICE_WORK: u8 = 1;

pub fn client_id(public: &[u8]) -> [u8; 8] {
    let mut h = blake3::Hasher::new();
    h.update(b"yrl-spa-client");
    h.update(public);
    h.finalize().as_bytes()[..8].try_into().unwrap()
}

pub fn server_id(public: &[u8]) -> [u8; 8] {
    let mut h = blake3::Hasher::new();
    h.update(b"yrl-spa-server");
    h.update(public);
    h.finalize().as_bytes()[..8].try_into().unwrap()
}

/// the device's address inside the overlay: derived from its key, so key and address cannot be told apart from each other
pub fn virtual_ipv6(public: &[u8]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(b"yrl-vip-v1");
    h.update(public);
    let mut a = [0u8; 16];
    a[0] = 0xfd;
    a[1..].copy_from_slice(&h.finalize().as_bytes()[..15]);
    a
}

fn mac_key(private: &[u8], public: &[u8]) -> Option<[u8; 32]> {
    let sk: [u8; 32] = private.try_into().ok()?;
    let pk: [u8; 32] = public.try_into().ok()?;
    let shared = x25519_dalek::StaticSecret::from(sk).diffie_hellman(&x25519_dalek::PublicKey::from(pk));
    let mut h = blake3::Hasher::new();
    h.update(b"yrl-spa-mac-key-v1");
    h.update(shared.as_bytes());
    Some(*h.finalize().as_bytes())
}

/// the client's side: one packet
pub fn build(client: &KeyPair, server_public: &[u8], service: u8, now: u64) -> Vec<u8> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    build_with(client, server_public, service, now, nonce)
}

pub fn build_with(client: &KeyPair, server_public: &[u8], service: u8, now: u64, nonce: [u8; 16]) -> Vec<u8> {
    build_raw(client, server_public, service, now, nonce, virtual_ipv6(&client.public))
}

/// with any virtual address (for tests of what a careless or hostile sender could do; a proper client never calls this)
pub fn build_raw(client: &KeyPair, server_public: &[u8], service: u8, now: u64, nonce: [u8; 16], vip: [u8; 16]) -> Vec<u8> {
    let mut p = Vec::with_capacity(LEN);
    p.extend_from_slice(MAGIC);
    p.push(VERSION);
    p.extend_from_slice(&client_id(&client.public));
    p.extend_from_slice(&server_id(server_public));
    p.push(service);
    p.extend_from_slice(&now.to_be_bytes());
    p.extend_from_slice(&nonce);
    p.extend_from_slice(&vip);
    let key = mac_key(&client.private, server_public).expect("keys are 32 bytes");
    let mac = blake3::keyed_hash(&key, &p);
    p.extend_from_slice(mac.as_bytes());
    p
}

/// why a packet was not accepted - for the LOCAL journal only; nothing of it ever goes back to the sender
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reject {
    Size,
    Format,
    WrongServer,
    RateLimited,
    UnknownClient,
    ClockSkew,
    Replay,
    BadMac,
    VipMismatch,
    ServiceDisabled,
    CacheFull,
}

impl Reject {
    pub fn name(self) -> &'static str {
        match self {
            Reject::Size => "size",
            Reject::Format => "format",
            Reject::WrongServer => "wrong-server",
            Reject::RateLimited => "rate-limited",
            Reject::UnknownClient => "unknown-client",
            Reject::ClockSkew => "clock-skew",
            Reject::Replay => "replay",
            Reject::BadMac => "bad-signature",
            Reject::VipMismatch => "virtual-address-mismatch",
            Reject::ServiceDisabled => "service-disabled",
            Reject::CacheFull => "replay-cache-full",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Accepted {
    pub client_public: Vec<u8>,
    pub vip: [u8; 16],
    pub service: u8,
}

pub struct SpaConfig {
    /// accepted if the packet's time differs from ours by at most this many seconds
    pub window: u64,
    /// most packets from one source address per second before the rest are dropped without looking at them
    pub per_source_per_sec: u32,
    /// most packets of all per second
    pub global_per_sec: u32,
    pub max_replay_entries: usize,
    pub enabled_services: Vec<u8>,
}

impl Default for SpaConfig {
    fn default() -> Self {
        SpaConfig { window: 30, per_source_per_sec: 5, global_per_sec: 500, max_replay_entries: 100_000, enabled_services: vec![SERVICE_WORK] }
    }
}

struct Clients {
    map: HashMap<[u8; 8], Vec<u8>>,
    loaded: u64,
}

pub struct SpaVerifier {
    server: KeyPair,
    dir: PathBuf,
    cfg: SpaConfig,
    clients: Mutex<Clients>,
    /// (client id, nonce) -> when it may be forgotten
    replay: Mutex<HashMap<([u8; 8], [u8; 16]), u64>>,
    rate: Mutex<(u64, HashMap<IpAddr, u32>, u32)>,
    /// how many times the expensive check was done (tests: a packet that is dropped early must not cost one)
    pub mac_checks: AtomicU64,
}

impl SpaVerifier {
    pub fn new(server: KeyPair, dir: PathBuf, cfg: SpaConfig) -> SpaVerifier {
        SpaVerifier { server, dir, cfg, clients: Mutex::new(Clients { map: HashMap::new(), loaded: 0 }), replay: Mutex::new(HashMap::new()), rate: Mutex::new((0, HashMap::new(), 0)), mac_checks: AtomicU64::new(0) }
    }

    fn lookup(&self, id: &[u8; 8], now: u64) -> Option<Vec<u8>> {
        let mut c = self.clients.lock().unwrap();
        if c.loaded == 0 || now > c.loaded {
            // the list of devices is re-read at most once a second: a removed device stops being let in within a second
            c.map = read_authorized(&self.dir.join("authorized_keys")).into_iter().map(|a| (client_id(&a.public), a.public)).collect();
            c.loaded = now;
        }
        c.map.get(id).cloned()
    }

    /// `now` is the server's own clock in seconds
    pub fn verify(&self, bytes: &[u8], src: IpAddr, now: u64) -> Result<Accepted, Reject> {
        // 1. only things that cost nothing
        if bytes.len() != LEN {
            return Err(Reject::Size);
        }
        if &bytes[..4] != MAGIC || bytes[4] != VERSION {
            return Err(Reject::Format);
        }
        if bytes[13..21] != server_id(&self.server.public) {
            return Err(Reject::WrongServer);
        }
        {
            // everything together is limited before anything else is looked at
            let mut r = self.rate.lock().unwrap();
            if r.0 != now {
                *r = (now, HashMap::new(), 0);
            }
            r.2 += 1;
            if r.2 > self.cfg.global_per_sec {
                return Err(Reject::RateLimited);
            }
        }
        let cid: [u8; 8] = bytes[5..13].try_into().unwrap();
        let Some(client_pub) = self.lookup(&cid, now) else { return Err(Reject::UnknownClient) };
        {
            // a source is limited only for packets that name a device we know: whoever does not know a device id cannot use up that device's turns by faking its address
            let mut r = self.rate.lock().unwrap();
            if r.1.len() > 10_000 {
                return Err(Reject::RateLimited);
            }
            let n = r.1.entry(src).or_insert(0);
            *n += 1;
            if *n > self.cfg.per_source_per_sec {
                return Err(Reject::RateLimited);
            }
        }
        let ts = u64::from_be_bytes(bytes[22..30].try_into().unwrap());
        if ts.abs_diff(now) > self.cfg.window {
            return Err(Reject::ClockSkew);
        }
        let nonce: [u8; 16] = bytes[30..46].try_into().unwrap();
        let ttl_end = now + 2 * self.cfg.window + 10;
        {
            let mut rp = self.replay.lock().unwrap();
            if rp.get(&(cid, nonce)).is_some_and(|until| *until > now) {
                return Err(Reject::Replay);
            }
            if rp.len() >= self.cfg.max_replay_entries {
                rp.retain(|_, until| *until > now);
                if rp.len() >= self.cfg.max_replay_entries {
                    return Err(Reject::CacheFull); // full of live entries: refuse rather than forget
                }
            }
        }
        // 2. the one expensive thing
        self.mac_checks.fetch_add(1, SeqCst);
        let key = mac_key(&self.server.private, &client_pub).ok_or(Reject::BadMac)?;
        let want = blake3::keyed_hash(&key, &bytes[..LEN - 32]);
        if want != blake3::Hash::from_bytes(bytes[LEN - 32..].try_into().unwrap()) {
            return Err(Reject::BadMac);
        }
        let vip: [u8; 16] = bytes[46..62].try_into().unwrap();
        if vip != virtual_ipv6(&client_pub) {
            return Err(Reject::VipMismatch);
        }
        let service = bytes[21];
        if !self.cfg.enabled_services.contains(&service) {
            return Err(Reject::ServiceDisabled);
        }
        // only a packet that passed everything is remembered, so that garbage cannot fill the cache
        self.replay.lock().unwrap().insert((cid, nonce), ttl_end);
        Ok(Accepted { client_public: client_pub, vip, service })
    }
}
