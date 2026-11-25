//! The first YRL check: a link between two endpoints on this machine, built ONLY from the pieces copied from the YANDI node: a TLS identity with a pinned fingerprint,
//! a WebSocket-over-TLS connection, an X25519 key exchange over it and AES-256-GCM session encryption. No command, no interface: just "a secure link exists".
use yrl_link::netlayer::encryption::EncryptionManager;
use yrl_link::netlayer::peer::PeerInfo;
use yrl_link::netlayer::tls_cert::TlsIdentity;
use yrl_link::netlayer::ws_transport::{connect_to_anchor, WsConnection, WsServer};
use yrl_link::util::HashId;

/// The node's session encryption appends 0-32 zero bytes of random padding and the receiver does NOT remove them (found by this very test): a YRL frame therefore carries an explicit length.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes().to_vec();
    f.extend_from_slice(payload);
    f
}

fn unframe(plain: &[u8]) -> Vec<u8> {
    let n = u32::from_be_bytes(plain[..4].try_into().unwrap()) as usize;
    plain[4..4 + n].to_vec()
}

fn id(b: u8) -> HashId {
    HashId([b; 32])
}

async fn up() -> (WsServer, TlsIdentity, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let tls = TlsIdentity::load_or_generate_in(dir.path(), &hex::encode([7u8; 32])).unwrap();
    let srv = WsServer::bind("127.0.0.1:0".parse().unwrap(), &tls).await.unwrap();
    (srv, tls, dir)
}

/// Both sides exchange their X25519 public keys over the (already TLS-protected) socket and derive the session key.
async fn handshake(server: &mut WsConnection, client: &mut WsConnection, s_enc: &mut EncryptionManager, c_enc: &mut EncryptionManager) {
    client.outgoing.send(c_enc.local_keys.get_public().to_vec()).await.unwrap();
    server.outgoing.send(s_enc.local_keys.get_public().to_vec()).await.unwrap();
    let from_client: [u8; 32] = server.incoming.recv().await.unwrap().try_into().unwrap();
    let from_server: [u8; 32] = client.incoming.recv().await.unwrap().try_into().unwrap();
    s_enc.handle_key_exchange(&PeerInfo::new(id(2), "client"), &from_client).unwrap();
    c_enc.handle_key_exchange(&PeerInfo::new(id(1), "server"), &from_server).unwrap();
}

#[tokio::test]
async fn a_secure_link_is_established_and_carries_encrypted_messages_both_ways() {
    let (mut srv, tls, _d) = up().await;
    let url = format!("wss://127.0.0.1:{}/", srv.local_addr.port());
    let mut client = connect_to_anchor(&url, &tls.fingerprint_hex).await.expect("pinned connect");
    let mut server_side = srv.accept_rx.recv().await.expect("accepted");
    let (mut s_enc, mut c_enc) = (EncryptionManager::new(id(1)), EncryptionManager::new(id(2)));
    handshake(&mut server_side, &mut client, &mut s_enc, &mut c_enc).await;

    let (server_peer, client_peer) = (PeerInfo::new(id(1), "server"), PeerInfo::new(id(2), "client"));
    // client -> server
    let ct = c_enc.encrypt(&server_peer, &frame(b"hello host")).unwrap();
    assert!(!ct.windows(10).any(|w| w == b"hello host"), "the plaintext must not appear on the wire");
    client.outgoing.send(ct).await.unwrap();
    let got = server_side.incoming.recv().await.unwrap();
    assert_eq!(unframe(&s_enc.decrypt(&client_peer, &got).unwrap()), b"hello host");
    // server -> client
    let ct = s_enc.encrypt(&client_peer, &frame(b"hello client")).unwrap();
    server_side.outgoing.send(ct).await.unwrap();
    let got = client.incoming.recv().await.unwrap();
    assert_eq!(unframe(&c_enc.decrypt(&server_peer, &got).unwrap()), b"hello client");
}

#[tokio::test]
async fn a_server_with_another_certificate_is_refused_by_the_pin() {
    let (srv, _tls, _d) = up().await;
    let url = format!("wss://127.0.0.1:{}/", srv.local_addr.port());
    let wrong = "00".repeat(32);
    assert!(connect_to_anchor(&url, &wrong).await.is_err(), "an impostor (or a man in the middle) with a different certificate must not be accepted");
}

#[tokio::test]
async fn a_tampered_or_replayed_message_is_rejected() {
    let (mut srv, tls, _d) = up().await;
    let url = format!("wss://127.0.0.1:{}/", srv.local_addr.port());
    let mut client = connect_to_anchor(&url, &tls.fingerprint_hex).await.unwrap();
    let mut server_side = srv.accept_rx.recv().await.unwrap();
    let (mut s_enc, mut c_enc) = (EncryptionManager::new(id(1)), EncryptionManager::new(id(2)));
    handshake(&mut server_side, &mut client, &mut s_enc, &mut c_enc).await;
    let (server_peer, client_peer) = (PeerInfo::new(id(1), "server"), PeerInfo::new(id(2), "client"));

    let ct = c_enc.encrypt(&server_peer, &frame(b"transfer 1")).unwrap();
    assert_eq!(unframe(&s_enc.decrypt(&client_peer, &ct).unwrap()), b"transfer 1");
    assert!(s_enc.decrypt(&client_peer, &ct).is_err(), "the same ciphertext a second time is a replay");
    let mut bad = c_enc.encrypt(&server_peer, &frame(b"transfer 2")).unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(s_enc.decrypt(&client_peer, &bad).is_err(), "a flipped bit must break the authentication tag");
    let other = PeerInfo::new(id(9), "stranger");
    let ct = c_enc.encrypt(&server_peer, &frame(b"transfer 3")).unwrap();
    assert!(s_enc.decrypt(&other, &ct).is_err(), "a message that claims another sender is refused");
}

/// KNOWN LIMITATION of the copied code, recorded as a test so that it cannot be forgotten: the session key is derived from the long-lived (per process) X25519 keys of both sides,
/// so two key exchanges between the same pair give the SAME key — there is no per-session ephemeral secret and therefore no forward secrecy. YRL's own handshake (Noise with ephemeral
/// keys, hybrid with ML-KEM, signed by the device identity) replaces this; when it does, this test is flipped.
#[test]
fn known_limitation_the_copied_session_key_is_static_per_process_no_forward_secrecy() {
    let (mut a, mut b) = (EncryptionManager::new(id(1)), EncryptionManager::new(id(2)));
    let (pa, pb) = (PeerInfo::new(id(1), "a"), PeerInfo::new(id(2), "b"));
    a.handle_key_exchange(&pb, &b.local_keys.get_public()).unwrap();
    let k1 = a.session_key_bytes(id(2)).unwrap();
    a.remove_session(&pb);
    a.handle_key_exchange(&pb, &b.local_keys.get_public()).unwrap();
    let k2 = a.session_key_bytes(id(2)).unwrap();
    assert_eq!(k1, k2, "same keys, same session key: a later leak of the process keys opens every recorded session");
    let _ = pa;
}
