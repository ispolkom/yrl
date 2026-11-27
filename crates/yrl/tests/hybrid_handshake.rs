#![cfg(feature = "hybrid-signatures")]

mod common;

use std::{fs, path::Path, time::Duration};
use yrl::{
    client::Client,
    crypto_profile::{Context, Policy, HYBRID_MUTUAL_SIGNATURES},
    hybrid_signature::{Purpose, SigningKey},
    session::{client_handshake_context, REKEY_EVERY},
};

fn install_pair(root: &Path, left: &[u8], right: &[u8]) {
    let local = root.join("local");
    let peers = root.join("peers");
    fs::create_dir_all(&peers).unwrap();
    for identity in [left, right] {
        let local = local.join(hex::encode(identity));
        SigningKey::generate_files(
            &local.with_extension("key"),
            &local.with_extension("pub"),
            Purpose::Handshake,
            1,
        ).unwrap();
        fs::copy(
            local.with_extension("pub"),
            peers.join(hex::encode(identity)).with_extension("pub"),
        ).unwrap();
    }
}

#[tokio::test]
async fn client_and_executor_enforce_hybrid_proofs_on_the_running_stack() {
    let rig = common::rig("exec").await;
    let gate = rig.dir.path().join("hybrid-gate");
    let executor = rig.dir.path().join("hybrid-executor");
    install_pair(&gate, &rig.client.public, &rig.server_pub);
    install_pair(&executor, &rig.client.public, &rig.exec_pub);
    // This integration binary has one test. Set both opt-ins before connecting.
    std::env::set_var("YRL_HYBRID_GATE_KEYS", &gate);
    std::env::set_var("YRL_HYBRID_EXECUTOR_KEYS", &executor);

    let mut stream = tokio::net::TcpStream::connect(&rig.addr).await.unwrap();
    let refusal = client_handshake_context(
        &mut stream, &rig.client, &rig.server_pub, REKEY_EVERY, Context::Gatekeeper, Policy::default(),
    ).await;
    assert!(refusal.is_err(), "a classical offer must be rejected");

    let policy = Policy::for_handshake(Context::Gatekeeper).unwrap();
    let mut stream = tokio::net::TcpStream::connect(&rig.addr).await.unwrap();
    let secure = client_handshake_context(
        &mut stream, &rig.client, &rig.server_pub, REKEY_EVERY, Context::Gatekeeper, policy,
    ).await.unwrap();
    assert_eq!(secure.profile(), HYBRID_MUTUAL_SIGNATURES);

    let client = Client::connect_pinned(&rig.addr, &rig.client, &rig.server_pub, &rig.exec_pub, common::T)
        .await.unwrap();
    client.login("anna", common::PW, common::T).await.unwrap();
    assert_eq!(client.ping(b"hybrid", common::T).await.unwrap(), b"hybrid");

    // Swap the Executor pin for the Gatekeeper's authentic hybrid public key.
    fs::copy(
        gate.join("peers").join(hex::encode(&rig.server_pub)).with_extension("pub"),
        executor.join("peers").join(hex::encode(&rig.exec_pub)).with_extension("pub"),
    ).unwrap();
    assert!(Client::connect_pinned(
        &rig.addr, &rig.client, &rig.server_pub, &rig.exec_pub, Duration::from_millis(350),
    ).await.is_err(), "a substituted Executor pin must fail without falling back");
}
