use std::os::unix::fs::PermissionsExt;
use yrl::crypto_profile::{
    parse_response, response, Context, Offer, Policy, ProfileStore, CLASSICAL_V1,
    HYBRID_X25519_MLKEM768_RESERVED,
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
fn reserved_pq_profile_is_never_advertised_or_accepted() {
    assert!(yrl::crypto_profile::suite(HYBRID_X25519_MLKEM768_RESERVED).is_none());
    assert!(Policy {
        minimum: CLASSICAL_V1,
        supported: vec![CLASSICAL_V1, HYBRID_X25519_MLKEM768_RESERVED],
    }
    .validate()
    .is_err());
    assert!(response(
        Context::Executor,
        HYBRID_X25519_MLKEM768_RESERVED,
        [0u8; 32],
    )
    .is_err());
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
