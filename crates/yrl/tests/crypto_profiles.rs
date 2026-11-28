use std::os::unix::fs::PermissionsExt;
use yrl::crypto_profile::{
    parse_response, response, Context, Offer, Policy, ProfileStore, CLASSICAL_V1,
    HYBRID_X25519_MLKEM768,
};

#[test]
fn negotiation_rejects_unknown_repeated_and_stripped_profiles() {
    let offer = Offer {
        context: Context::Executor,
        minimum: CLASSICAL_V1,
        supported: vec![CLASSICAL_V1],
    };
    let encoded = offer.encode().unwrap();
    assert_eq!(Offer::decode(&encoded).unwrap(), offer);

    let mut unknown = encoded.clone();
    let n = unknown.len();
    unknown[n - 4..].copy_from_slice(&0xfeed_beefu32.to_be_bytes());
    assert!(Offer::decode(&unknown).is_err());

    let mut repeated = encoded.clone();
    repeated[b"YRL-CRYPTO-OFFER".len() + 6] = 2;
    repeated.extend_from_slice(&CLASSICAL_V1.to_be_bytes());
    assert!(Offer::decode(&repeated).is_err());

    let valid = response(Context::Executor, CLASSICAL_V1, offer.digest().unwrap()).unwrap();
    assert_eq!(parse_response(&valid, &offer).unwrap(), CLASSICAL_V1);
    let mut stripped = valid;
    stripped.pop();
    assert!(parse_response(&stripped, &offer).is_err());
}

#[test]
fn selection_is_bound_to_context_and_exact_offer() {
    let offer = Offer {
        context: Context::Gatekeeper,
        minimum: CLASSICAL_V1,
        supported: vec![CLASSICAL_V1],
    };
    let valid = response(Context::Gatekeeper, CLASSICAL_V1, offer.digest().unwrap()).unwrap();
    let changed = Offer {
        context: Context::Executor,
        ..offer.clone()
    };
    assert!(parse_response(&valid, &changed).is_err());

    let mut substituted = valid;
    let at = b"YRL-CRYPTO-SELECT".len() + 2;
    substituted[at..at + 4].copy_from_slice(&0u32.to_be_bytes());
    assert!(parse_response(&substituted, &offer).is_err());
    assert!(Policy {
        minimum: CLASSICAL_V1 + 1,
        supported: vec![CLASSICAL_V1]
    }
    .validate()
    .is_err());
}

#[test]
fn pq_profile_availability_matches_the_build() {
    #[cfg(not(feature = "pq-hybrid"))]
    assert!(yrl::crypto_profile::suite(HYBRID_X25519_MLKEM768).is_none());
    #[cfg(feature = "pq-hybrid")]
    assert!(yrl::crypto_profile::suite(HYBRID_X25519_MLKEM768).is_some());
    let policy = Policy {
        minimum: CLASSICAL_V1,
        supported: vec![CLASSICAL_V1, HYBRID_X25519_MLKEM768],
    };
    #[cfg(not(feature = "pq-hybrid"))]
    assert!(policy.validate().is_err());
    #[cfg(feature = "pq-hybrid")]
    assert!(policy.validate().is_ok());
    #[cfg(not(feature = "pq-hybrid"))]
    assert!(Policy {
        minimum: CLASSICAL_V1,
        supported: vec![CLASSICAL_V1, HYBRID_X25519_MLKEM768],
    }
    .validate()
    .is_err());
    #[cfg(not(feature = "pq-hybrid"))]
    assert!(response(
        Context::Executor,
        HYBRID_X25519_MLKEM768,
        [0u8; 32],
    )
    .is_err());
}

#[test]
fn opaque_backend_availability_matches_feature() {
    assert_eq!(
        yrl::crypto_support::require(yrl::crypto_support::Mechanism::OpaqueRfc9807).is_ok(),
        cfg!(feature = "opaque-rfc9807")
    );
}

#[test]
fn hybrid_signature_backend_availability_matches_feature() {
    assert_eq!(yrl::crypto_support::require(yrl::crypto_support::Mechanism::HybridEd25519MlDsa65).is_ok(), cfg!(feature = "hybrid-signatures"));
}

#[test]
fn fido2_backend_availability_matches_feature() {
    assert_eq!(yrl::crypto_support::require(yrl::crypto_support::Mechanism::Fido2).is_ok(), cfg!(feature = "fido2"));
}

#[test]
fn tpm_backend_availability_matches_feature() {
    assert_eq!(yrl::crypto_support::require(yrl::crypto_support::Mechanism::Tpm2).is_ok(), cfg!(feature = "tpm2"));
}

#[test]
fn peer_high_water_mark_is_private_persistent_and_monotonic() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state").join("profiles");
    let peer = [7u8; 32];
    let mut store = ProfileStore::open(&path).unwrap();
    store
        .remember(Context::Executor, &peer, CLASSICAL_V1)
        .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let reopened = ProfileStore::open(&path).unwrap();
    assert_eq!(reopened.minimum(Context::Executor, &peer, 0), CLASSICAL_V1);
    assert_eq!(reopened.minimum(Context::Gatekeeper, &peer, 0), 0);
}

#[cfg(feature = "crypto-profiles")]
#[tokio::test]
async fn transcript_bound_profile_handshake_uses_independent_contexts() {
    let client = yrl::keys::generate();
    let server = yrl::keys::generate();
    let auth = vec![yrl::keys::Authorized {
        public: client.public.clone(),
        label: "client".into(),
        rights: vec![],
    }];
    let (mut a, mut b) = tokio::io::duplex(4096);
    let c = yrl::session::client_handshake_context(
        &mut a,
        &client,
        &server.public,
        yrl::session::REKEY_EVERY,
        Context::Executor,
        Policy::default(),
    );
    let s = yrl::session::server_handshake_open_context(
        &mut b,
        &server,
        &auth,
        yrl::session::REKEY_EVERY,
        false,
        Context::Executor,
        Policy::default(),
    );
    let (client_result, server_result) = tokio::join!(c, s);
    assert_eq!(client_result.unwrap().profile(), CLASSICAL_V1);
    assert_eq!(server_result.unwrap().0.profile(), CLASSICAL_V1);
}

#[cfg(feature = "pq-hybrid")]
#[tokio::test]
async fn hybrid_profile_completes_bound_mlkem768_upgrade() {
    let client = yrl::keys::generate();
    let server = yrl::keys::generate();
    let auth = vec![yrl::keys::Authorized { public: client.public.clone(), label: "client".into(), rights: vec![] }];
    let policy = Policy { minimum: HYBRID_X25519_MLKEM768, supported: vec![CLASSICAL_V1, HYBRID_X25519_MLKEM768] };
    let (mut a, mut b) = tokio::io::duplex(8192);
    let c = yrl::session::client_handshake_context(&mut a, &client, &server.public, yrl::session::REKEY_EVERY, Context::Executor, policy.clone());
    let s = yrl::session::server_handshake_open_context(&mut b, &server, &auth, yrl::session::REKEY_EVERY, false, Context::Executor, policy);
    let (client_result, server_result) = tokio::join!(c, s);
    assert_eq!(client_result.unwrap().profile(), HYBRID_X25519_MLKEM768);
    assert_eq!(server_result.unwrap().0.profile(), HYBRID_X25519_MLKEM768);
}

// REV-001: independently opened stores must not lose each other's entries.
#[test]
fn independent_profile_writers_preserve_all_entries() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state").join("profiles");

    let peer_a = [11u8; 32];
    let peer_b = [22u8; 32];

    let mut a = ProfileStore::open(&path).unwrap();
    let mut b = ProfileStore::open(&path).unwrap();

    a.remember(Context::Executor, &peer_a, CLASSICAL_V1)
        .unwrap();

    b.remember(Context::Executor, &peer_b, CLASSICAL_V1)
        .unwrap();

    let saved = ProfileStore::open(&path).unwrap();

    assert_eq!(
        saved.minimum(Context::Executor, &peer_a, 0),
        CLASSICAL_V1,
        "writer B erased writer A's profile"
    );

    assert_eq!(
        saved.minimum(Context::Executor, &peer_b, 0),
        CLASSICAL_V1
    );
}

// REV-001: a stale writer must never overwrite a stronger profile.
#[cfg(feature = "pq-hybrid")]
#[test]
fn stale_profile_writer_cannot_downgrade_peer() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state").join("profiles");
    let peer = [33u8; 32];

    let mut strong = ProfileStore::open(&path).unwrap();
    let mut stale = ProfileStore::open(&path).unwrap();

    strong
        .remember(Context::Executor, &peer, HYBRID_X25519_MLKEM768)
        .unwrap();

    assert!(
        stale.remember(Context::Executor, &peer, CLASSICAL_V1)
            .is_err(),
        "stale writer accepted a cryptographic downgrade"
    );

    let saved = ProfileStore::open(&path).unwrap();

    assert_eq!(
        saved.minimum(Context::Executor, &peer, 0),
        HYBRID_X25519_MLKEM768
    );
}

// REV-001: concurrent writers must preserve every peer's policy.
#[test]
fn parallel_profile_writers_preserve_every_peer() {
    use std::sync::{Arc, Barrier};

    const N: usize = 32;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state").join("profiles");
    let barrier = Arc::new(Barrier::new(N));
    let mut workers = Vec::new();

    for i in 0..N {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);

        workers.push(std::thread::spawn(move || {
            let mut store = ProfileStore::open(&path).unwrap();
            let peer = [i as u8; 32];

            barrier.wait();

            store.remember(
                Context::Executor,
                &peer,
                CLASSICAL_V1,
            ).unwrap();
        }));
    }

    for worker in workers {
        worker.join().unwrap();
    }

    let saved = ProfileStore::open(&path).unwrap();

    for i in 0..N {
        assert_eq!(
            saved.minimum(
                Context::Executor,
                &[i as u8; 32],
                0,
            ),
            CLASSICAL_V1,
            "missing profile for peer {i}"
        );
    }
}

// REV-001: the lock must never follow a symbolic link.
#[test]
fn profile_store_refuses_symlink_lock() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("state");
    std::fs::create_dir(&dir).unwrap();

    let path = dir.join("profiles");
    let victim = temp.path().join("victim");

    std::fs::write(&victim, b"unchanged").unwrap();
    symlink(&victim, dir.join("profiles.lock")).unwrap();

    let mut store = ProfileStore::open(&path).unwrap();

    assert!(
        store.remember(
            Context::Executor,
            &[44u8; 32],
            CLASSICAL_V1,
        ).is_err()
    );

    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"unchanged"
    );

    assert!(!path.exists());
}

// REV-001: an insecure lock file must be refused.
#[test]
fn profile_store_refuses_public_lock() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("state");
    std::fs::create_dir(&dir).unwrap();

    let path = dir.join("profiles");
    let lock = dir.join("profiles.lock");

    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(
        &lock,
        std::fs::Permissions::from_mode(0o666),
    ).unwrap();

    let mut store = ProfileStore::open(&path).unwrap();

    assert!(
        store.remember(
            Context::Executor,
            &[55u8; 32],
            CLASSICAL_V1,
        ).is_err()
    );

    assert!(!path.exists());
}

// REV-001: all publications must use the same lock inode.
#[test]
fn profile_store_preserves_lock_inode() {
    use std::os::unix::fs::MetadataExt;

    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("state");
    let path = dir.join("profiles");
    let lock = dir.join("profiles.lock");

    let mut store = ProfileStore::open(&path).unwrap();

    store.remember(
        Context::Executor,
        &[66u8; 32],
        CLASSICAL_V1,
    ).unwrap();

    let before = std::fs::metadata(&lock).unwrap();

    store.remember(
        Context::Executor,
        &[77u8; 32],
        CLASSICAL_V1,
    ).unwrap();

    let after = std::fs::metadata(&lock).unwrap();

    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.dev(), after.dev());
    assert_eq!(after.permissions().mode() & 0o777, 0o600);
}

// REV-007: a local policy must not permit an unavailable
// mandatory cryptographic profile.
#[cfg(not(feature = "pq-hybrid"))]
#[test]
fn rev007_unavailable_mandatory_profile_is_refused() {
    let policy = Policy {
        minimum: HYBRID_X25519_MLKEM768,
        supported: vec![CLASSICAL_V1],
    };

    assert!(policy.validate().is_err());
}

// REV-007: selecting a mutually permitted profile must
// never violate the local or remote minimum.
#[test]
fn rev007_incompatible_minimum_is_refused() {
    let policy = Policy {
        minimum: CLASSICAL_V1,
        supported: vec![CLASSICAL_V1],
    };

    let offer = Offer {
        context: Context::Executor,
        minimum: HYBRID_X25519_MLKEM768,
        supported: vec![HYBRID_X25519_MLKEM768],
    };

    assert!(policy.select(&offer).is_err());
}

// REV-007: invalid local policies must fail before any
// handshake traffic is required.
#[tokio::test]
async fn rev007_invalid_client_policy_fails_immediately() {
    use std::time::Duration;

    let client = yrl::keys::generate();
    let server = yrl::keys::generate();
    let (mut stream, _peer) = tokio::io::duplex(4096);

    let policy = Policy {
        minimum: CLASSICAL_V1,
        supported: vec![],
    };

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        yrl::session::client_handshake_context(
            &mut stream,
            &client,
            &server.public,
            yrl::session::REKEY_EVERY,
            Context::Executor,
            policy,
        ),
    )
    .await
    .expect("invalid local policy must not wait for peer");

    assert!(result.is_err());
}

#[tokio::test]
async fn rev007_invalid_server_policy_fails_immediately() {
    use std::time::Duration;

    let server = yrl::keys::generate();
    let (mut stream, _peer) = tokio::io::duplex(4096);

    let policy = Policy {
        minimum: CLASSICAL_V1,
        supported: vec![],
    };

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        yrl::session::server_handshake_open_context(
            &mut stream,
            &server,
            &[],
            yrl::session::REKEY_EVERY,
            false,
            Context::Executor,
            policy,
        ),
    )
    .await
    .expect("invalid local policy must not wait for peer");

    assert!(result.is_err());
}

#[test]
fn rev007_known_optional_profile_can_be_decoded() {
    let offer = Offer {
        context: Context::Executor,
        minimum: CLASSICAL_V1,
        supported: vec![
            CLASSICAL_V1,
            HYBRID_X25519_MLKEM768,
        ],
    };

    let encoded = offer.encode().unwrap();

    assert_eq!(
        Offer::decode(&encoded).unwrap(),
        offer
    );
}

#[test]
fn rev007_unknown_profile_remains_refused() {
    let offer = Offer {
        context: Context::Executor,
        minimum: CLASSICAL_V1,
        supported: vec![CLASSICAL_V1, 0xfeed_beef],
    };

    assert!(
        offer.encode()
            .and_then(|bytes| Offer::decode(&bytes))
            .is_err()
    );
}

#[test]
fn rev007_required_profile_cannot_be_replaced() {
    let policy = Policy::default();

    let offer = Offer {
        context: Context::Executor,
        minimum: HYBRID_X25519_MLKEM768,
        supported: vec![
            CLASSICAL_V1,
            HYBRID_X25519_MLKEM768,
        ],
    };

    assert!(policy.select(&offer).is_err());
}

#[test]
fn rev007_known_signed_profile_can_be_decoded() {
    use yrl::crypto_profile::HYBRID_MUTUAL_SIGNATURES;

    let offer = Offer {
        context: Context::Executor,
        minimum: CLASSICAL_V1,
        supported: vec![
            CLASSICAL_V1,
            HYBRID_MUTUAL_SIGNATURES,
        ],
    };

    assert_eq!(
        Offer::decode(&offer.encode().unwrap()).unwrap(),
        offer
    );
}

#[test]
fn rev007_recognition_does_not_change_local_capabilities() {
    use yrl::crypto_profile::{
        known_profile,
        suite,
        HYBRID_MUTUAL_SIGNATURES,
    };

    assert!(known_profile(CLASSICAL_V1));
    assert!(known_profile(HYBRID_X25519_MLKEM768));
    assert!(known_profile(HYBRID_MUTUAL_SIGNATURES));
    assert!(!known_profile(0xfeed_beef));

    assert!(suite(CLASSICAL_V1).is_some());

    assert_eq!(
        suite(HYBRID_X25519_MLKEM768).is_some(),
        cfg!(feature = "pq-hybrid")
    );

    assert_eq!(
        suite(HYBRID_MUTUAL_SIGNATURES).is_some(),
        cfg!(feature = "hybrid-signatures")
    );
}

#[test]
fn rev007_classical_policy_remains_classical() {
    let policy = Policy::default();

    assert_eq!(policy.minimum, CLASSICAL_V1);
    assert_eq!(policy.supported, vec![CLASSICAL_V1]);

    assert!(policy.validate().is_ok());
}

#[test]
fn rev007_required_minimum_remains_mandatory() {
    use yrl::crypto_profile::HYBRID_MUTUAL_SIGNATURES;

    for minimum in [
        HYBRID_X25519_MLKEM768,
        HYBRID_MUTUAL_SIGNATURES,
    ] {
        let policy = Policy {
            minimum,
            supported: vec![CLASSICAL_V1],
        };

        assert!(policy.validate().is_err());
    }
}
