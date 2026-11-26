use yrl::audit::AuditService;
use yrl::auditlog::{Event, Source, LEVEL_USER, RESULT_OK};
use yrl::auditsegments::{verify_chain, RotationPolicy, TrustAnchor};

fn tiny() -> RotationPolicy {
    RotationPolicy {
        max_bytes: 1,
        max_age_secs: u64::MAX,
        max_total_bytes: 1 << 30,
        retain_segments: 64,
        min_free_bytes: 0,
    }
}

#[test]
fn r62_missing_or_substituted_segment_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let svc = AuditService::open_with_policy(d.path(), 100, tiny()).unwrap();
    for _ in 0..3 {
        svc.append(Source::Executor, Event::new("exec", LEVEL_USER, RESULT_OK))
            .unwrap();
    }
    verify_chain(d.path(), None).unwrap();
    std::fs::remove_file(d.path().join("audit/ordinary.00000000000000000000.seal")).unwrap();
    assert!(verify_chain(d.path(), None).is_err());
}

#[test]
fn r62_external_checkpoint_detects_rollback_of_an_active_segment() {
    let d = tempfile::tempdir().unwrap();
    let svc = AuditService::open_with_policy(
        d.path(),
        100,
        RotationPolicy {
            max_bytes: u64::MAX,
            ..tiny()
        },
    )
    .unwrap();
    let log = d.path().join("audit/ordinary.log");
    let old = std::fs::read(&log).unwrap_or_default();
    svc.append(Source::Executor, Event::new("exec", LEVEL_USER, RESULT_OK))
        .unwrap();
    let key = svc.verifying_key();
    let anchor = TrustAnchor::decode(&svc.trust_anchor().unwrap(), Some(&key)).unwrap();
    verify_chain(d.path(), Some(&anchor)).unwrap();
    std::fs::write(&log, old).unwrap();
    let _ = std::fs::remove_file(d.path().join("audit/ordinary.head"));
    assert!(verify_chain(d.path(), Some(&anchor)).is_err());
}
