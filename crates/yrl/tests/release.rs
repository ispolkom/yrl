use std::io::Write;

#[test]
fn r65_signed_release_binds_the_complete_component_set_and_delegation() {
    let d = tempfile::tempdir().unwrap();
    let root_secret = d.path().join("root.key");
    let root_public = d.path().join("root.pub");
    yrl::release::generate_key(&root_secret, &root_public).unwrap();
    let trust = d.path().join("trust");
    yrl::release::init_trust(&root_public, &trust).unwrap();
    let delegate_secret = d.path().join("delegate.key");
    let delegate_public = d.path().join("delegate.pub");
    yrl::release::generate_key(&delegate_secret, &delegate_public).unwrap();
    let delegation = d.path().join("delegation");
    yrl::release::delegate(
        &trust,
        &root_secret,
        &delegate_public,
        7,
        100,
        1000,
        40,
        50,
        &delegation,
    )
    .unwrap();
    let artifacts = d.path().join("artifacts");
    std::fs::create_dir(&artifacts).unwrap();
    std::fs::File::create(artifacts.join("yrld"))
        .unwrap()
        .write_all(b"daemon")
        .unwrap();
    std::fs::File::create(artifacts.join("yrl"))
        .unwrap()
        .write_all(b"client")
        .unwrap();
    let manifest = d.path().join("manifest");
    yrl::release::create_manifest(
        &artifacts, 42, "1.2.3", "linux", "x86_64", 1, 1, 1, 200, 900, 7, &manifest,
    )
    .unwrap();
    let signature = d.path().join("manifest.sig");
    yrl::release::sign_manifest(&manifest, &delegation, &delegate_secret, &signature, &trust)
        .unwrap();
    let verified =
        yrl::release::verify_release(&artifacts, &manifest, &signature, &delegation, &trust, 500)
            .unwrap();
    assert_eq!(verified.number, 42);
    std::fs::write(artifacts.join("yrld"), b"other release").unwrap();
    assert!(yrl::release::verify_release(
        &artifacts,
        &manifest,
        &signature,
        &delegation,
        &trust,
        500
    )
    .is_err());
}

#[test]
fn r65_expired_or_revoked_delegation_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let rs = d.path().join("r.key");
    let rp = d.path().join("r.pub");
    yrl::release::generate_key(&rs, &rp).unwrap();
    let trust = d.path().join("trust");
    yrl::release::init_trust(&rp, &trust).unwrap();
    let ds = d.path().join("d.key");
    let dp = d.path().join("d.pub");
    yrl::release::generate_key(&ds, &dp).unwrap();
    let cert = d.path().join("cert");
    yrl::release::delegate(&trust, &rs, &dp, 1, 10, 20, 1, 10, &cert).unwrap();
    let store = yrl::release::load_trust(&trust).unwrap();
    assert!(yrl::release::parse_delegation(&cert, &store).is_ok());
    yrl::release::revoke_delegate(&trust, &rs, 1, &dp, 15).unwrap();
    let store = yrl::release::load_trust(&trust).unwrap();
    assert!(yrl::release::parse_delegation(&cert, &store).is_err());
}

#[cfg(feature = "hybrid-signatures")]
#[test]
fn hybrid_release_requires_both_signatures_at_every_trust_boundary() {
    use yrl::hybrid_signature::{Purpose, SigningKey};
    use yrl::release::*;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let (root, root_pub) = (dir.join("root.key"), dir.join("root.pub"));
    let (delegate_key, delegate_pub) = (dir.join("delegate.key"), dir.join("delegate.pub"));
    let trust = dir.join("trust");
    SigningKey::generate_files(&root, &root_pub, Purpose::ReleaseRoot, 0).unwrap();
    SigningKey::generate_files(&delegate_key, &delegate_pub, Purpose::ReleaseDelegated, 7).unwrap();
    init_trust(&root_pub, &trust).unwrap();
    let cert = dir.join("cert");
    delegate(&trust, &root, &delegate_pub, 7, 100, 900, 40, 50, &cert).unwrap();
    assert!(delegate(&trust, &root, &delegate_pub, 8, 100, 900, 40, 50, &dir.join("bad")).is_err());

    let artifacts = dir.join("artifacts");
    std::fs::create_dir(&artifacts).unwrap();
    std::fs::write(artifacts.join("yrld"), b"daemon").unwrap();
    let manifest = dir.join("manifest");
    create_manifest(&artifacts, 42, "1.2.3", "linux", "x86_64", 1, 1, 1, 200, 800, 7, &manifest).unwrap();
    let sig = dir.join("sig");
    sign_manifest(&manifest, &cert, &delegate_key, &sig, &trust).unwrap();
    let verify = |sig: &std::path::Path, cert: &std::path::Path| {
        verify_release(&artifacts, &manifest, sig, cert, &trust, 500)
    };
    assert_eq!(verify(&sig, &cert).unwrap().number, 42);

    let original = hex::decode(std::fs::read_to_string(&sig).unwrap().trim()).unwrap();
    let bad_sig = dir.join("bad-sig");
    let bad_cert = dir.join("bad-cert");
    let cert_text = std::fs::read_to_string(&cert).unwrap();
    let (body, cert_sig) = cert_text.trim().rsplit_once(' ').unwrap();
    let cert_sig = hex::decode(cert_sig).unwrap();
    for mutation in [
        |b: &mut Vec<u8>| b[45] ^= 1,
        |b: &mut Vec<u8>| b[109] ^= 1,
        |b: &mut Vec<u8>| { b.drain(45..109); },
        |b: &mut Vec<u8>| b.truncate(109),
        |b: &mut Vec<u8>| b[12] ^= 1,
        |b: &mut Vec<u8>| b[13] ^= 1,
    ] {
        let mut altered = original.clone();
        mutation(&mut altered);
        std::fs::write(&bad_sig, hex::encode(altered)).unwrap();
        assert!(verify(&bad_sig, &cert).is_err());
        let mut altered = cert_sig.clone();
        mutation(&mut altered);
        std::fs::write(&bad_cert, format!("{body} {}\n", hex::encode(altered))).unwrap();
        assert!(verify(&sig, &bad_cert).is_err());
    }

    let new_root = dir.join("new.key");
    rotate_root(&trust, &root, &new_root, &dir.join("new.pub")).unwrap();
    assert_eq!(load_trust(&trust).unwrap().generation, 1);
    assert!(verify(&sig, &cert).is_ok());
    revoke_delegate(&trust, &new_root, 7, &delegate_pub, 520).unwrap();
    assert!(verify(&sig, &cert).is_err());

    let (recovery, recovery_pub) = (dir.join("recover.key"), dir.join("recover.pub"));
    SigningKey::generate_files(&recovery, &recovery_pub, Purpose::Recovery, 0).unwrap();
    register_root_recovery(&trust, &recovery_pub).unwrap();
    let historical = dir.join("historical-cert");
    let other_pub = dir.join("other.pub");
    SigningKey::generate_files(&dir.join("other.key"), &other_pub, Purpose::ReleaseDelegated, 8).unwrap();
    delegate(&trust, &new_root, &other_pub, 8, 100, 900, 40, 50, &historical).unwrap();
    assert!(parse_delegation(&historical, &load_trust(&trust).unwrap()).is_ok());
    std::fs::remove_file(&new_root).unwrap();
    recover_root(&trust, &recovery, &dir.join("new2.key"), &dir.join("new2.pub")).unwrap();
    let store = load_trust(&trust).unwrap();
    assert_eq!(store.minimum_root, 2);
    assert!(parse_delegation(&historical, &store).is_err());
}
