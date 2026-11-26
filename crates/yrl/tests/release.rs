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
        &artifacts, 42, "1.2.3", "linux", "x86_64", 1, 1, 200, 900, 7, &manifest,
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
