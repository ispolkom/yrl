use ed25519_dalek::SigningKey;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use yrl::audit::AuditService;
use yrl::auditlog::Journal;

fn current(dir: &std::path::Path) -> SigningKey {
    let seed = yrl::keys::read_secret_hex(&dir.join("audit/sign.key"), 32).unwrap();
    SigningKey::from_bytes(seed.as_slice().try_into().unwrap())
}

#[test]
fn r64_planned_rotation_cross_signs_and_preserves_historical_verification() {
    let d = tempfile::tempdir().unwrap();
    let svc = AuditService::open(d.path(), 10).unwrap();
    let old = current(d.path());
    svc.rotate_all().unwrap();
    drop(svc);
    let base = d.path().join("audit");
    let states: Vec<_> = [Journal::Ordinary, Journal::Security]
        .into_iter()
        .map(|j| {
            (
                j,
                yrl::auditsegments::read_active(&base, j, &old.verifying_key(), 0).unwrap(),
            )
        })
        .collect();
    yrl::auditkeys::planned_transition(d.path(), &old).unwrap();
    let new = current(d.path());
    for (j, state) in states {
        yrl::auditsegments::write_active(&base, j, &state, &new).unwrap();
    }
    let history = yrl::auditkeys::load(d.path()).unwrap();
    assert_eq!(history.current_generation, 1);
    yrl::auditsegments::verify_chain(d.path(), None).unwrap();
}

#[test]
fn r64_emergency_transition_requires_pretrusted_recovery_possession() {
    let d = tempfile::tempdir().unwrap();
    AuditService::open(d.path(), 10).unwrap();
    let recovery = SigningKey::generate(&mut argon2::password_hash::rand_core::OsRng);
    yrl::auditkeys::register_recovery(d.path(), &hex::encode(recovery.verifying_key().to_bytes()))
        .unwrap();
    let seed = d.path().join("recovery.seed");
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&seed)
        .unwrap();
    writeln!(f, "{}", hex::encode(recovery.to_bytes())).unwrap();
    yrl::auditkeys::emergency_transition(d.path(), &seed).unwrap();
    let now = current(d.path());
    yrl::auditkeys::revoke(d.path(), 0, "compromised", &now).unwrap();
    let history = yrl::auditkeys::load(d.path()).unwrap();
    assert_eq!(history.current_generation, 1);
    assert!(history.revoked.contains(&0));
}
