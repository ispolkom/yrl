use yrl::auditsign::Verify;
use yrl::audit::AuditService;
use yrl::auditexport::{verify, Outcome};
use yrl::auditlog::{Event, Source, LEVEL_USER, RESULT_OK};
use yrl::auditsegments::TrustAnchor;

#[test]
fn r63_offline_verifier_needs_only_public_material() {
    let d = tempfile::tempdir().unwrap();
    let svc = AuditService::open(d.path(), 10).unwrap();
    svc.append(
        Source::Executor,
        Event::new("exec", LEVEL_USER, RESULT_OK).hidden_target(b"secret command"),
    )
    .unwrap();
    std::fs::remove_file(d.path().join("audit/sign.key")).unwrap();
    let (outcome, _) = verify(d.path(), None);
    assert_eq!(outcome, Outcome::Full);
}

#[test]
fn r63_export_manifest_signature_is_domain_separated_and_bound_to_anchor() {
    let d = tempfile::tempdir().unwrap();
    let svc = AuditService::open(d.path(), 10).unwrap();
    let digest = *blake3::hash(b"manifest").as_bytes();
    let auth = svc.sign_export(&digest).unwrap();
    let n = u32::from_be_bytes(auth[..4].try_into().unwrap()) as usize;
    let anchor = TrustAnchor::decode(&auth[4..4 + n], Some(&svc.verifying_key())).unwrap();
    let mut message = b"yrl-audit-export-v1".to_vec();
    message.extend_from_slice(&digest);
    message.extend_from_slice(blake3::hash(&auth[4..4 + n]).as_bytes());
    svc.verifying_key()
        .verify_bytes(&message, &auth[4 + n..])
        .unwrap();
    assert_eq!(anchor.key, svc.verifying_key().to_bytes());
}
