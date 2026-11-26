//! The encrypted channel: Noise IK over any byte stream, one Noise message per YRL frame. The server answers NOTHING to a handshake that fails for any reason.
use crate::keys::{Authorized, KeyPair, PARAMS};
use crate::wire::{Frame, MAX_FRAME};
use anyhow::{bail, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

pub const HELLO: &[u8] = b"YRL1\x01";
pub const REPLY: &[u8] = b"YRL1ok";
pub const REKEY_EVERY: u64 = 1 << 20;

/// `[u16 length][bytes]`; a zero length is not allowed.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l).await?;
    let n = u16::from_be_bytes(l) as usize;
    if n == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "empty message"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    if data.is_empty() || data.len() > u16::MAX as usize {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad message length"));
    }
    let mut out = (data.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    w.write_all(&out).await?;
    w.flush().await
}

/// The transport state with keys rotated by message count (both sides count the same messages, so they rekey at the same moment).
pub struct Secure {
    state: Mutex<snow::TransportState>,
    sent: AtomicU64,
    received: AtomicU64,
    rekey_every: u64,
    /// bookkeeping for connections driven by hand in tests (the real client keeps its numbers in `Link`)
    pub raw_mode: std::sync::atomic::AtomicBool,
    pub raw_out: AtomicU64,
    pub raw_in: AtomicU64,
    profile: crate::crypto_profile::ProfileId,
}

impl Secure {
    pub fn new(state: snow::TransportState, rekey_every: u64) -> Secure {
        Secure::new_profile(state, rekey_every, crate::crypto_profile::CLASSICAL_V1)
    }
    pub fn new_profile(state: snow::TransportState, rekey_every: u64, profile: crate::crypto_profile::ProfileId) -> Secure {
        Secure { state: Mutex::new(state), sent: AtomicU64::new(0), received: AtomicU64::new(0), rekey_every, raw_mode: Default::default(), raw_out: AtomicU64::new(0), raw_in: AtomicU64::new(0), profile }
    }
    pub fn profile(&self) -> crate::crypto_profile::ProfileId { self.profile }
    pub fn seal(&self, f: &Frame) -> Result<Vec<u8>> {
        let mut plain = f.encode().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mut out = vec![0u8; plain.len() + 16];
        let mut st = self.state.lock().unwrap();
        let sealed = st.write_message(&plain, &mut out);
        // LOGIN is the protocol frame carrying a reusable credential in its plaintext
        // payload. Bulk frames remain retained by Link until ACK, so wiping this extra
        // encoded copy did not shorten their lifetime and made debug transfers an order slower.
        if f.kind == crate::wire::LOGIN {
            plain.zeroize();
        }
        let n = sealed?;
        out.truncate(n);
        if self.sent.fetch_add(1, Ordering::SeqCst) + 1 == self.rekey_every {
            st.rekey_outgoing();
            self.sent.store(0, Ordering::SeqCst);
        }
        Ok(out)
    }
    pub fn open(&self, msg: &[u8]) -> Result<Frame> {
        if msg.len() > MAX_FRAME + 16 {
            bail!("message too large");
        }
        let mut plain = vec![0u8; msg.len()];
        let mut st = self.state.lock().unwrap();
        let n = match st.read_message(msg, &mut plain) {
            Ok(n) => n,
            Err(e) => {
                // Authentication failures may leave unspecified bytes in the output
                // buffer, so clear it before returning even though its kind is unknown.
                plain.zeroize();
                return Err(e.into());
            }
        };
        plain.truncate(n);
        if self.received.fetch_add(1, Ordering::SeqCst) + 1 == self.rekey_every {
            st.rekey_incoming();
            self.received.store(0, Ordering::SeqCst);
        }
        let frame = Frame::decode(&plain).map_err(|e| anyhow::anyhow!("{e:?}"));
        if plain.first() == Some(&crate::wire::LOGIN) {
            plain.zeroize();
        }
        frame
    }
}

pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, me: &KeyPair, server_public: &[u8], rekey_every: u64) -> Result<Secure> {
    client_handshake_context(s, me, server_public, rekey_every, crate::crypto_profile::Context::LocalIpc, crate::crypto_profile::Policy::from_env()?).await
}

pub async fn client_handshake_context<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, me: &KeyPair, server_public: &[u8], rekey_every: u64, context: crate::crypto_profile::Context, policy: crate::crypto_profile::Policy) -> Result<Secure> {
    #[cfg(not(feature = "crypto-profiles"))]
    let _ = (context, policy);
    #[cfg(feature = "crypto-profiles")]
    let prologue = crate::crypto_profile::prologue(context);
    #[cfg(not(feature = "crypto-profiles"))]
    let mut hs = snow::Builder::new(PARAMS.parse()?).local_private_key(&me.private).remote_public_key(server_public).build_initiator()?;
    #[cfg(feature = "crypto-profiles")]
    let mut hs = snow::Builder::new(PARAMS.parse()?).local_private_key(&me.private).remote_public_key(server_public).prologue(&prologue).build_initiator()?;
    let mut buf = vec![0u8; 512];
    #[cfg(not(feature = "crypto-profiles"))]
    let n = hs.write_message(HELLO, &mut buf)?;
    #[cfg(feature = "crypto-profiles")]
    let (offer, n) = {
        policy.validate()?;
        let offer = crate::crypto_profile::Offer { context, minimum: policy.minimum, supported: policy.supported.clone() };
        let n = hs.write_message(&offer.encode()?, &mut buf)?;
        (offer, n)
    };
    write_msg(s, &buf[..n]).await?;
    let reply = read_msg(s).await?;
    let mut out = vec![0u8; 512];
    let m = hs.read_message(&reply, &mut out)?;
    #[cfg(not(feature = "crypto-profiles"))]
    if &out[..m] != REPLY {
        bail!("unexpected server reply");
    }
    #[cfg(feature = "crypto-profiles")]
    let selected = crate::crypto_profile::parse_response(&out[..m], &offer)?;
    #[cfg(not(feature = "crypto-profiles"))]
    let selected = crate::crypto_profile::CLASSICAL_V1;
    Ok(Secure::new_profile(hs.into_transport_mode()?, rekey_every, selected))
}

/// Failure of any kind: the caller drops the connection WITHOUT writing a byte.
#[derive(Debug)]
pub struct Silent;

pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, me: &KeyPair, authorized: &[Authorized], rekey_every: u64) -> Result<(Secure, Authorized), Silent> {
    server_handshake_open(s, me, authorized, rekey_every, false).await
}

/// with `open` a key that is not in the list also completes the handshake (as a nameless guest with no rights): used only while the owner has a window open
pub async fn server_handshake_open<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, me: &KeyPair, authorized: &[Authorized], rekey_every: u64, open: bool) -> Result<(Secure, Authorized), Silent> {
    server_handshake_open_context(s, me, authorized, rekey_every, open, crate::crypto_profile::Context::LocalIpc, crate::crypto_profile::Policy::from_env().map_err(|_| Silent)?).await
}

pub async fn server_handshake_open_context<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, me: &KeyPair, authorized: &[Authorized], rekey_every: u64, open: bool, context: crate::crypto_profile::Context, policy: crate::crypto_profile::Policy) -> Result<(Secure, Authorized), Silent> {
    #[cfg(not(feature = "crypto-profiles"))]
    let _ = (context, policy);
    let m1 = read_msg(s).await.map_err(|_| Silent)?;
    if m1.len() > 512 {
        return Err(Silent);
    }
    #[cfg(not(feature = "crypto-profiles"))]
    let mut hs = snow::Builder::new(PARAMS.parse().map_err(|_| Silent)?).local_private_key(&me.private).build_responder().map_err(|_| Silent)?;
    #[cfg(feature = "crypto-profiles")]
    let prologue = crate::crypto_profile::prologue(context);
    #[cfg(feature = "crypto-profiles")]
    let mut hs = snow::Builder::new(PARAMS.parse().map_err(|_| Silent)?).local_private_key(&me.private).prologue(&prologue).build_responder().map_err(|_| Silent)?;
    let mut payload = vec![0u8; 512];
    let n = hs.read_message(&m1, &mut payload).map_err(|_| Silent)?;
    #[cfg(not(feature = "crypto-profiles"))]
    if &payload[..n] != HELLO {
        return Err(Silent);
    }
    #[cfg(feature = "crypto-profiles")]
    let (offer, selected) = {
        let offer = crate::crypto_profile::Offer::decode(&payload[..n]).map_err(|_| Silent)?;
        if offer.context != context { return Err(Silent) }
        let selected = policy.select(&offer).map_err(|_| Silent)?;
        (offer, selected)
    };
    let remote = hs.get_remote_static().ok_or(Silent)?.to_vec();
    let who = match authorized.iter().find(|a| a.public == remote).cloned() {
        Some(w) => w,
        None if open => Authorized { public: remote.clone(), label: "guest".into(), rights: vec![] },
        None => return Err(Silent),
    };
    let mut out = vec![0u8; 512];
    #[cfg(not(feature = "crypto-profiles"))]
    let k = hs.write_message(REPLY, &mut out).map_err(|_| Silent)?;
    #[cfg(feature = "crypto-profiles")]
    let k = hs.write_message(&crate::crypto_profile::response(context, selected, offer.digest().map_err(|_| Silent)?).map_err(|_| Silent)?, &mut out).map_err(|_| Silent)?;
    write_msg(s, &out[..k]).await.map_err(|_| Silent)?;
    #[cfg(not(feature = "crypto-profiles"))]
    let selected = crate::crypto_profile::CLASSICAL_V1;
    Ok((Secure::new_profile(hs.into_transport_mode().map_err(|_| Silent)?, rekey_every, selected), who))
}
