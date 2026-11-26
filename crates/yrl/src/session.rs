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

#[cfg(feature = "pq-hybrid")]
type PqTransport = clatter::transportstate::TransportState<clatter::crypto::cipher::ChaChaPoly, clatter::crypto::hash::Blake2s>;
#[cfg(feature = "pq-hybrid")]
type PqHandshake = clatter::PqHandshake<clatter::crypto::kem::rust_crypto_ml_kem::MlKem768, clatter::crypto::kem::rust_crypto_ml_kem::MlKem768, clatter::crypto::cipher::ChaChaPoly, clatter::crypto::hash::Blake2s>;

enum TransportState {
    Classical(snow::TransportState),
    #[cfg(feature = "pq-hybrid")]
    Hybrid(PqTransport),
}

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
    state: Mutex<TransportState>,
    sent: AtomicU64,
    received: AtomicU64,
    rekey_every: u64,
    /// bookkeeping for connections driven by hand in tests (the real client keeps its numbers in `Link`)
    pub raw_mode: std::sync::atomic::AtomicBool,
    pub raw_out: AtomicU64,
    pub raw_in: AtomicU64,
    profile: crate::crypto_profile::ProfileId,
    channel_binding: [u8; 32],
}

impl Secure {
    pub fn new(state: snow::TransportState, rekey_every: u64) -> Secure {
        Secure::new_profile(state, rekey_every, crate::crypto_profile::CLASSICAL_V1)
    }
    pub fn new_profile(state: snow::TransportState, rekey_every: u64, profile: crate::crypto_profile::ProfileId) -> Secure {
        Secure::new_profile_bound(state, rekey_every, profile, &[0; 32])
    }
    fn new_profile_bound(state: snow::TransportState, rekey_every: u64, profile: crate::crypto_profile::ProfileId, binding: &[u8]) -> Secure {
        Secure { state: Mutex::new(TransportState::Classical(state)), sent: AtomicU64::new(0), received: AtomicU64::new(0), rekey_every, raw_mode: Default::default(), raw_out: AtomicU64::new(0), raw_in: AtomicU64::new(0), profile, channel_binding: *blake3::hash(binding).as_bytes() }
    }
    #[cfg(feature = "pq-hybrid")]
    fn new_hybrid(state: PqTransport, rekey_every: u64, binding: &[u8]) -> Secure {
        Secure { state: Mutex::new(TransportState::Hybrid(state)), sent: AtomicU64::new(0), received: AtomicU64::new(0), rekey_every, raw_mode: Default::default(), raw_out: AtomicU64::new(0), raw_in: AtomicU64::new(0), profile: crate::crypto_profile::HYBRID_X25519_MLKEM768, channel_binding: *blake3::hash(binding).as_bytes() }
    }
    pub fn profile(&self) -> crate::crypto_profile::ProfileId { self.profile }
    pub fn channel_binding(&self) -> &[u8; 32] { &self.channel_binding }
    pub fn seal(&self, f: &Frame) -> Result<Vec<u8>> {
        let mut plain = f.encode().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mut out = vec![0u8; plain.len() + 16];
        let mut st = self.state.lock().unwrap();
        let sealed = match &mut *st {
            TransportState::Classical(st) => st.write_message(&plain, &mut out).map_err(anyhow::Error::from),
            #[cfg(feature = "pq-hybrid")]
            TransportState::Hybrid(st) => st.send(&plain, &mut out).map_err(|e| anyhow::anyhow!("hybrid transport: {e:?}")),
        };
        // LOGIN is the protocol frame carrying a reusable credential in its plaintext
        // payload. Bulk frames remain retained by Link until ACK, so wiping this extra
        // encoded copy did not shorten their lifetime and made debug transfers an order slower.
        if sensitive_frame(f.kind) {
            plain.zeroize();
        }
        let n = sealed?;
        out.truncate(n);
        if self.sent.fetch_add(1, Ordering::SeqCst) + 1 == self.rekey_every {
            match &mut *st {
                TransportState::Classical(st) => st.rekey_outgoing(),
                #[cfg(feature = "pq-hybrid")]
                TransportState::Hybrid(st) => st.rekey_sender().map_err(|e| anyhow::anyhow!("hybrid rekey: {e:?}"))?,
            }
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
        let opened = match &mut *st {
            TransportState::Classical(st) => st.read_message(msg, &mut plain).map_err(anyhow::Error::from),
            #[cfg(feature = "pq-hybrid")]
            TransportState::Hybrid(st) => st.receive(msg, &mut plain).map_err(|e| anyhow::anyhow!("hybrid transport: {e:?}")),
        };
        let n = match opened {
            Ok(n) => n,
            Err(e) => {
                // Authentication failures may leave unspecified bytes in the output
                // buffer, so clear it before returning even though its kind is unknown.
                plain.zeroize();
                return Err(e);
            }
        };
        plain.truncate(n);
        if self.received.fetch_add(1, Ordering::SeqCst) + 1 == self.rekey_every {
            match &mut *st {
                TransportState::Classical(st) => st.rekey_incoming(),
                #[cfg(feature = "pq-hybrid")]
                TransportState::Hybrid(st) => st.rekey_receiver().map_err(|e| anyhow::anyhow!("hybrid rekey: {e:?}"))?,
            }
            self.received.store(0, Ordering::SeqCst);
        }
        let frame = Frame::decode(&plain).map_err(|e| anyhow::anyhow!("{e:?}"));
        if plain.first().is_some_and(|kind| sensitive_frame(*kind)) {
            plain.zeroize();
        }
        frame
    }
}

fn sensitive_frame(kind: u8) -> bool {
    matches!(kind, crate::wire::LOGIN | crate::wire::OPAQUE_LOGIN_START | crate::wire::OPAQUE_LOGIN_FINISH | crate::wire::OPAQUE_REG_START | crate::wire::OPAQUE_REG_FINISH | crate::stepup::STEPUP_PROOF)
}

#[cfg(feature = "hybrid-signatures")]
fn hybrid_proof_body(context: crate::crypto_profile::Context, sec: &Secure, initiator_x25519: &[u8], responder_x25519: &[u8], role: u8) -> Result<Vec<u8>> {
    if initiator_x25519.len() != 32 || responder_x25519.len() != 32 || !matches!(role, b'I' | b'R') { bail!("invalid hybrid identity proof context") }
    let mut body = b"YRL hybrid handshake authentication v1\0".to_vec();
    body.push(context as u8); body.extend_from_slice(&sec.profile().to_be_bytes()); body.extend_from_slice(sec.channel_binding());
    body.extend_from_slice(initiator_x25519); body.extend_from_slice(responder_x25519); body.push(role); Ok(body)
}

/// Additional mutually authenticated proof used by the mandatory-hybrid
/// profile. Hybrid public keys are caller-supplied pins; accepting a key sent
/// by the peer would reduce this to unauthenticated key exchange.
#[cfg(feature = "hybrid-signatures")]
pub async fn hybrid_auth_client<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, sec: &Secure, context: crate::crypto_profile::Context, initiator_x25519: &[u8], responder_x25519: &[u8], own: &crate::hybrid_signature::SigningKey, pinned_server: &crate::hybrid_signature::PublicKey) -> Result<()> {
    if own.public().purpose != crate::hybrid_signature::Purpose::Handshake || pinned_server.purpose != crate::hybrid_signature::Purpose::Handshake { bail!("wrong hybrid handshake key purpose") }
    let request = own.sign(&hybrid_proof_body(context, sec, initiator_x25519, responder_x25519, b'I')?)?.encode();
    write_msg(s, &sec.seal(&Frame::new(crate::wire::HYBRID_CLIENT_PROOF, 0, request))?).await?;
    let reply = sec.open(&read_msg(s).await?)?;
    if reply.kind != crate::wire::HYBRID_SERVER_PROOF { bail!("missing hybrid server proof") }
    let signature = crate::hybrid_signature::SignatureEnvelope::decode(&reply.payload)?;
    pinned_server.verify(&hybrid_proof_body(context, sec, initiator_x25519, responder_x25519, b'R')?, &signature)
}

#[cfg(feature = "hybrid-signatures")]
pub async fn hybrid_auth_server<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, sec: &Secure, context: crate::crypto_profile::Context, initiator_x25519: &[u8], responder_x25519: &[u8], own: &crate::hybrid_signature::SigningKey, pinned_client: &crate::hybrid_signature::PublicKey) -> Result<()> {
    if own.public().purpose != crate::hybrid_signature::Purpose::Handshake || pinned_client.purpose != crate::hybrid_signature::Purpose::Handshake { bail!("wrong hybrid handshake key purpose") }
    let request = sec.open(&read_msg(s).await?)?;
    if request.kind != crate::wire::HYBRID_CLIENT_PROOF { bail!("missing hybrid client proof") }
    let signature = crate::hybrid_signature::SignatureEnvelope::decode(&request.payload)?;
    pinned_client.verify(&hybrid_proof_body(context, sec, initiator_x25519, responder_x25519, b'I')?, &signature)?;
    let response = own.sign(&hybrid_proof_body(context, sec, initiator_x25519, responder_x25519, b'R')?)?.encode();
    write_msg(s, &sec.seal(&Frame::new(crate::wire::HYBRID_SERVER_PROOF, 0, response))?).await?;
    Ok(())
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
    #[cfg(feature = "pq-hybrid")]
    if selected == crate::crypto_profile::HYBRID_X25519_MLKEM768 {
        let binding = hs.get_handshake_hash().to_vec();
        return pq_upgrade_client(s, hs.into_transport_mode()?, &binding, rekey_every).await;
    }
    let binding = hs.get_handshake_hash().to_vec();
    Ok(Secure::new_profile_bound(hs.into_transport_mode()?, rekey_every, selected, &binding))
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
    #[cfg(feature = "pq-hybrid")]
    if selected == crate::crypto_profile::HYBRID_X25519_MLKEM768 {
        let binding = hs.get_handshake_hash().to_vec();
        let secure = pq_upgrade_server(s, hs.into_transport_mode().map_err(|_| Silent)?, &binding, rekey_every).await?;
        return Ok((secure, who));
    }
    let binding = hs.get_handshake_hash().to_vec();
    Ok((Secure::new_profile_bound(hs.into_transport_mode().map_err(|_| Silent)?, rekey_every, selected, &binding), who))
}

#[cfg(feature = "pq-hybrid")]
fn pq_handshake(initiator: bool, binding: &[u8]) -> Result<PqHandshake> {
    use clatter::traits::Handshaker;
    let mut hs = PqHandshake::new(
        clatter::handshakepattern::noise_pqnn(),
        b"YRL hybrid profile 0x00020001",
        initiator,
        None,
        None,
        None,
        None,
    ).map_err(|e| anyhow::anyhow!("PQ Noise init: {e:?}"))?;
    hs.get_state_mut().mix_hash(b"clatter.hybrid_dual_layer.outer");
    hs.get_state_mut().mix_key_and_hash(binding);
    Ok(hs)
}

#[cfg(feature = "pq-hybrid")]
async fn pq_upgrade_client<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, mut outer: snow::TransportState, binding: &[u8], rekey_every: u64) -> Result<Secure> {
    use clatter::traits::Handshaker;
    let mut pq = pq_handshake(true, binding)?;
    let mut pq_msg = vec![0u8; 4096];
    let n = pq.write_message(&[], &mut pq_msg).map_err(|e| anyhow::anyhow!("PQ Noise request: {e:?}"))?;
    let mut wrapped = vec![0u8; n + 16];
    let w = outer.write_message(&pq_msg[..n], &mut wrapped)?;
    write_msg(s, &wrapped[..w]).await?;
    let reply = read_msg(s).await?;
    if reply.len() > 4096 { bail!("oversized PQ Noise reply") }
    let n = outer.read_message(&reply, &mut pq_msg)?;
    let mut payload = [0u8; 1];
    let p = pq.read_message(&pq_msg[..n], &mut payload).map_err(|e| anyhow::anyhow!("PQ Noise reply: {e:?}"))?;
    if p != 0 || !pq.is_finished() { bail!("invalid PQ Noise completion") }
    Ok(Secure::new_hybrid(pq.finalize().map_err(|e| anyhow::anyhow!("PQ Noise finalize: {e:?}"))?, rekey_every, binding))
}

#[cfg(feature = "pq-hybrid")]
async fn pq_upgrade_server<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, mut outer: snow::TransportState, binding: &[u8], rekey_every: u64) -> Result<Secure, Silent> {
    use clatter::traits::Handshaker;
    let request = read_msg(s).await.map_err(|_| Silent)?;
    if request.len() > 4096 { return Err(Silent) }
    let mut pq_msg = vec![0u8; 4096];
    let n = outer.read_message(&request, &mut pq_msg).map_err(|_| Silent)?;
    let mut pq = pq_handshake(false, binding).map_err(|_| Silent)?;
    let mut payload = [0u8; 1];
    let p = pq.read_message(&pq_msg[..n], &mut payload).map_err(|_| Silent)?;
    if p != 0 { return Err(Silent) }
    let n = pq.write_message(&[], &mut pq_msg).map_err(|_| Silent)?;
    if !pq.is_finished() { return Err(Silent) }
    let mut wrapped = vec![0u8; n + 16];
    let w = outer.write_message(&pq_msg[..n], &mut wrapped).map_err(|_| Silent)?;
    write_msg(s, &wrapped[..w]).await.map_err(|_| Silent)?;
    Ok(Secure::new_hybrid(pq.finalize().map_err(|_| Silent)?, rekey_every, binding))
}
