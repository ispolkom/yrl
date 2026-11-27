#![cfg(feature = "hybrid-signatures")]

use std::fs;
use yrl::{
    audit::AuditService,
    auditkeys,
    auditlog::{Event, Journal, Source, LEVEL_NONE, RESULT_OK},
    auditsegments::{verify_chain, TrustAnchor},
    auditsign::{Purpose as AuditPurpose, Secret, Verify},
    hybrid_signature::{Purpose, SigningKey},
};

#[test]
fn hybrid_journal_checkpoints_anchors_rotation_and_revocation() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let base = dir.join("audit");
    let (secret, public) = (base.join("sign.key"), base.join("sign.pub"));
    SigningKey::generate_files(&secret, &public, Purpose::Audit, 0).unwrap();
    let service = AuditService::open(dir, 1).unwrap();
    service.append(Source::Audit, Event::new("start", LEVEL_NONE, RESULT_OK)).unwrap();
    service.seal().unwrap();
    let anchor = service.trust_anchor().unwrap();
    let proof = TrustAnchor::decode(&anchor, Some(&service.verifying_key())).unwrap();
    verify_chain(dir, Some(&proof)).unwrap();

    let text = std::str::from_utf8(&anchor).unwrap();
    let fields: Vec<_> = text.split_whitespace().collect();
    let bytes = hex::decode(fields[11]).unwrap();
    for mutate in [
        |b: &mut Vec<u8>| b[45] ^= 1,
        |b: &mut Vec<u8>| b[109] ^= 1,
        |b: &mut Vec<u8>| { b.drain(45..109); },
        |b: &mut Vec<u8>| b.truncate(109),
        |b: &mut Vec<u8>| b[12] ^= 1,
        |b: &mut Vec<u8>| b[13] ^= 1,
    ] {
        let mut altered = bytes.clone();
        mutate(&mut altered);
        let token = hex::encode(altered);
        let mut fields = fields.clone();
        fields[11] = &token;
        assert!(TrustAnchor::decode(fields.join(" ").as_bytes(), Some(&service.verifying_key())).is_err());
    }

    let digest = *blake3::hash(b"export manifest").as_bytes();
    let auth = service.sign_export(&digest).unwrap();
    let size = u32::from_be_bytes(auth[..4].try_into().unwrap()) as usize;
    let mut message = b"yrl-audit-export-v1".to_vec();
    message.extend_from_slice(&digest);
    message.extend_from_slice(blake3::hash(&auth[4..4 + size]).as_bytes());
    service.verifying_key().verify_bytes(&message, &auth[4 + size..]).unwrap();
    assert!(service.verifying_key().verify_bytes(b"different context", &auth[4 + size..]).is_err());

    service.rotate_all().unwrap();
    drop(service);
    let old = Secret::load(&secret, &auditkeys::load(dir).unwrap().current, AuditPurpose::Journal).unwrap();
    let old_states: Vec<_> = [Journal::Ordinary, Journal::Security].iter().map(|&journal| {
        (journal, yrl::auditsegments::read_active(&base, journal, &old.verifying_key(), 0).unwrap())
    }).collect();
    let next = auditkeys::planned_transition(dir, &old).unwrap();
    let current = Secret::load(&secret, &next, AuditPurpose::Journal).unwrap();
    for (journal, active) in old_states {
        yrl::auditsegments::write_active(&base, journal, &active, &current).unwrap();
    }
    auditkeys::revoke(dir, 0, "retired in test", &current).unwrap();
    let service = AuditService::open(dir, 1).unwrap();
    let report = verify_chain(dir, Some(&proof)).unwrap();
    assert!(report.revoked_key_segments > 0);
    drop(service);

    let (recovery, recovery_public) = (dir.join("recovery.key"), dir.join("recovery.pub"));
    let generated = SigningKey::generate_files(&recovery, &recovery_public, Purpose::Recovery, 0).unwrap();
    auditkeys::register_recovery(dir, &hex::encode(generated.encode())).unwrap();
    fs::remove_file(&secret).unwrap();
    auditkeys::emergency_transition(dir, &recovery).unwrap();
    assert_eq!(auditkeys::load(dir).unwrap().current_generation, 2);
}
