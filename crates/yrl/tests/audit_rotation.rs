use std::os::unix::fs::PermissionsExt;
use yrl::audit::AuditService;
use yrl::auditlog::{Event, Journal, Source, LEVEL_USER, RESULT_OK};
use yrl::auditsegments::{RotationPolicy, SegmentSeal};

fn policy() -> RotationPolicy {
    RotationPolicy {
        max_bytes: 1,
        max_age_secs: u64::MAX,
        max_total_bytes: 1 << 30,
        retain_segments: 3,
        min_free_bytes: 0,
    }
}

#[test]
fn r61_rotation_has_signed_boundaries_and_a_fresh_active_segment() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let svc = AuditService::open_with_policy(d.path(), 100, policy()).unwrap();
    svc.append(Source::Executor, Event::new("exec", LEVEL_USER, RESULT_OK))
        .unwrap();
    svc.append(Source::Executor, Event::new("exec", LEVEL_USER, RESULT_OK))
        .unwrap();
    let base = d.path().join("audit");
    let seal = std::fs::read(base.join("ordinary.00000000000000000000.seal")).unwrap();
    let decoded = SegmentSeal::decode(&seal, &svc.verifying_key()).unwrap();
    assert_eq!(decoded.journal, Journal::Ordinary);
    assert!(base.join("ordinary.log").exists());
}

#[test]
fn r61_retention_writes_evidence_before_removing_old_archives() {
    let d = tempfile::tempdir().unwrap();
    let svc = AuditService::open_with_policy(d.path(), 100, policy()).unwrap();
    for _ in 0..8 {
        svc.append(Source::Executor, Event::new("exec", LEVEL_USER, RESULT_OK))
            .unwrap();
    }
    let evidence = std::fs::read_to_string(d.path().join("audit/deletions.log")).unwrap();
    assert!(evidence.contains("YRL-AUDIT-DELETE-1 ordinary"));
}
