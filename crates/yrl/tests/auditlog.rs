//! The audit journal: what it records, and that nobody can change history without it showing.
use std::os::unix::fs::PermissionsExt;
use yrl::audit::*;
use yrl::auditlog::*;

fn ev(op: &str, level: u8) -> Event {
    Event::new(op, level, RESULT_OK).session(b"sess-0123456789ab").device(&[7u8; 32]).user("anna").request(1).target("t")
}

fn svc(every: u64) -> (tempfile::TempDir, std::sync::Arc<AuditService>) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let s = AuditService::open(d.path(), every).unwrap();
    (d, s)
}

fn report(d: &std::path::Path, j: Journal) -> Report {
    verify_dir(d, j).unwrap()
}

/// splits a journal into its framed records (raw bytes each)
fn records(bytes: &[u8]) -> Vec<Vec<u8>> {
    let (mut v, mut at) = (vec![], 0);
    while at < bytes.len() {
        let n = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        v.push(bytes[at..at + 4 + n].to_vec());
        at += 4 + n;
    }
    v
}

fn fill(s: &AuditService, n: u64) {
    for i in 0..n {
        s.append(Source::Executor, ev("exec", LEVEL_USER).request(100 + i)).unwrap();
    }
}

fn path(d: &std::path::Path, j: Journal) -> std::path::PathBuf {
    d.join("audit").join(format!("{}.log", j.file()))
}

#[test]
fn a1_a_record_has_one_binary_form() {
    let r = Record { kind: KIND_EVENT, journal: Journal::Ordinary, source: Source::Executor, seq: 5, time: 1_760_000_000, flags: 0, ev: ev("exec", LEVEL_SUDO).cap(&[9; 16]).code(7), extra: vec![] };
    let c = r.canonical().unwrap();
    assert_eq!(Record::parse(&c).unwrap(), r);
    assert_eq!(c, r.canonical().unwrap(), "the same record, the same bytes");
    assert!(c.starts_with(b"YAR1\x01\x00\x02"));
    // a golden value: if this changes, every old journal would stop verifying
    let (_, h) = frame(&r, &[0u8; 32]).unwrap();
    assert_eq!(hex::encode(h), hex::encode(chain_hash(&[0u8; 32], &c)));
    assert_eq!(hex::encode(h), "b0c226515679f53f9eeee1dbc4115cff2963fc74ec7aa0a9c613050bbf5e24ee", "the hash of this record, from the first version of the format");
    // every field matters
    let mut other = r.clone();
    other.ev.target = b"u".to_vec();
    assert_ne!(other.canonical().unwrap(), c);
    other = r.clone();
    other.seq = 6;
    assert_ne!(other.canonical().unwrap(), c);
    // exact: trailing bytes, cut, bad magic, absurd lengths
    let mut longer = c.clone();
    longer.push(0);
    assert!(Record::parse(&longer).is_err() && Record::parse(&c[..c.len() - 1]).is_err() && Record::parse(b"XXXX").is_err() && Record::parse(&[]).is_err());
    let mut bad_kind = c.clone();
    bad_kind[4] = 9;
    assert!(Record::parse(&bad_kind).is_err());
    assert!(Record { ev: Event { target: vec![0; MAX_FIELD + 1], ..r.ev.clone() }, ..r.clone() }.canonical().is_err());
    let mut x = 17u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..30_000 {
        let b: Vec<u8> = (0..(rnd() % 120) as usize).map(|_| rnd() as u8).collect();
        let _ = Record::parse(&b);
    }
}

#[test]
fn a2_the_chain_is_intact_when_nobody_touched_it() {
    let (d, s) = svc(10);
    fill(&s, 25);
    let rep = report(d.path(), Journal::Ordinary);
    assert_eq!(rep.fault, None);
    assert_eq!(rep.records, 25 + 2, "25 events and 2 checkpoints");
    assert_eq!(rep.checkpoints, 2);
    assert_eq!(rep.unsealed, 5);
    let sec = report(d.path(), Journal::Security);
    assert_eq!(sec.records, 1, "only the start of the audit process went to the security journal");
}

#[test]
fn a3_changing_one_old_record_is_found() {
    let (d, s) = svc(100);
    fill(&s, 12);
    drop(s);
    let p = path(d.path(), Journal::Ordinary);
    let mut b = std::fs::read(&p).unwrap();
    let recs = records(&b);
    let at: usize = recs[..5].iter().map(|r| r.len()).sum();
    // flip one bit in the 6th record's body (the "result" byte area)
    b[at + 4 + 20] ^= 0x01;
    std::fs::write(&p, &b).unwrap();
    let rep = report(d.path(), Journal::Ordinary);
    assert!(matches!(rep.fault, Some(Fault::BrokenChain(5))), "{:?}", rep.fault);
}

#[test]
fn a4_deleting_inserting_and_reordering_are_found() {
    let (d, s) = svc(100);
    fill(&s, 12);
    drop(s);
    let p = path(d.path(), Journal::Ordinary);
    let orig = std::fs::read(&p).unwrap();
    let recs = records(&orig);
    let join = |v: &[Vec<u8>]| v.concat();
    // deleted from the middle
    let mut v = recs.clone();
    v.remove(4);
    std::fs::write(&p, join(&v)).unwrap();
    assert!(report(d.path(), Journal::Ordinary).fault.is_some(), "a missing record");
    // two swapped
    let mut v = recs.clone();
    v.swap(3, 4);
    std::fs::write(&p, join(&v)).unwrap();
    assert!(report(d.path(), Journal::Ordinary).fault.is_some(), "swapped records");
    // a copy of an old record inserted
    let mut v = recs.clone();
    v.insert(6, recs[2].clone());
    std::fs::write(&p, join(&v)).unwrap();
    assert!(report(d.path(), Journal::Ordinary).fault.is_some(), "an inserted copy");
    // a forged, perfectly well-formed record inserted by somebody who knows the format (they can compute hashes, they cannot sign)
    let forged = Record { kind: KIND_EVENT, journal: Journal::Ordinary, source: Source::Broker, seq: 6, time: 1, flags: 0, ev: ev("broker_op", LEVEL_ROOT), extra: vec![] };
    let prev: [u8; 32] = recs[5][recs[5].len() - 32..].try_into().unwrap();
    let (fb, _) = frame(&forged, &prev).unwrap();
    let mut v = recs.clone();
    v.insert(6, fb);
    std::fs::write(&p, join(&v)).unwrap();
    assert!(report(d.path(), Journal::Ordinary).fault.is_some(), "a forged record: everything after it no longer follows");
    std::fs::write(&p, &orig).unwrap();
    assert_eq!(report(d.path(), Journal::Ordinary).fault, None, "and the original is fine again (so the checks above were about the edits)");
}

#[test]
fn a5_a_cut_tail_is_found_by_the_signed_head() {
    let (d, s) = svc(5);
    fill(&s, 20);
    drop(s);
    let p = path(d.path(), Journal::Ordinary);
    let b = std::fs::read(&p).unwrap();
    let recs = records(&b);
    assert_eq!(report(d.path(), Journal::Ordinary).fault, None);
    // cut at a record boundary, leaving an internally perfect chain
    std::fs::write(&p, recs[..recs.len() - 7].concat()).unwrap();
    assert!(matches!(report(d.path(), Journal::Ordinary).fault, Some(Fault::Truncated { .. })), "{:?}", report(d.path(), Journal::Ordinary).fault);
    // cut off even the checkpoints that follow the head's: still found
    std::fs::write(&p, recs[..3].concat()).unwrap();
    assert!(matches!(report(d.path(), Journal::Ordinary).fault, Some(Fault::Truncated { .. })));
    // a head that was edited is not trusted
    std::fs::write(&p, &b).unwrap();
    let hp = d.path().join("audit/ordinary.head");
    let head = std::fs::read_to_string(&hp).unwrap();
    std::fs::write(&hp, head.replacen(' ', " 9", 1)).unwrap();
    assert_eq!(report(d.path(), Journal::Ordinary).fault, Some(Fault::BadHead));
}

#[test]
fn a6_rewriting_the_whole_history_with_a_key_of_ones_own_is_found() {
    let (d, s) = svc(5);
    fill(&s, 20);
    drop(s);
    // an attacker with the files builds a fresh, well-chained history with checkpoints signed by their own key
    let evil_dir = tempfile::tempdir().unwrap();
    let evil = AuditService::open(evil_dir.path(), 5).unwrap();
    fill(&evil, 20);
    drop(evil);
    std::fs::copy(evil_dir.path().join("audit/ordinary.log"), path(d.path(), Journal::Ordinary)).unwrap();
    std::fs::copy(evil_dir.path().join("audit/ordinary.head"), d.path().join("audit/ordinary.head")).unwrap();
    let rep = report(d.path(), Journal::Ordinary);
    assert!(matches!(rep.fault, Some(Fault::BadSignature(_)) | Some(Fault::BadHead)), "judged by the real public key: {:?}", rep.fault);
    // and without any checkpoints at all, with the old head: the head says there should be more
    let nocp = AuditService::open(tempfile::tempdir().unwrap().path(), 1_000_000);
    let _ = nocp;
}

#[test]
fn a7_a_damaged_last_record_is_never_silently_continued() {
    let (d, s) = svc(100);
    fill(&s, 8);
    drop(s);
    let p = path(d.path(), Journal::Ordinary);
    let b = std::fs::read(&p).unwrap();
    std::fs::write(&p, &b[..b.len() - 10]).unwrap(); // a partial write at the very end
    assert_eq!(report(d.path(), Journal::Ordinary).fault, Some(Fault::DamagedTail));
    let err = AuditService::open(d.path(), 100).err().expect("must refuse").to_string();
    assert!(err.contains("does not verify"), "{err}");
    assert_eq!(std::fs::read(&p).unwrap().len(), b.len() - 10, "and it did not touch the file");
    // the owner repairs: only the broken end goes, and the rest verifies
    let said = repair(d.path()).unwrap();
    assert!(said.contains("cut"), "{said}");
    assert_eq!(report(d.path(), Journal::Ordinary).fault, None);
    let s2 = AuditService::open(d.path(), 100).unwrap();
    assert!(s2.append(Source::Executor, ev("exec", LEVEL_USER)).is_ok());
    // something that is not a damaged tail is not repaired by this
    drop(s2);
    let mut b = std::fs::read(&p).unwrap();
    b[30] ^= 1;
    std::fs::write(&p, &b).unwrap();
    assert!(repair(d.path()).unwrap().contains("NOT repaired"));
}

#[test]
fn a8_a_source_may_report_only_what_it_could_have_seen() {
    let (d, s) = svc(100);
    assert!(s.append(Source::Gatekeeper, ev("enroll_guest", LEVEL_NONE)).is_ok());
    assert!(s.append(Source::Gatekeeper, ev("login", LEVEL_NONE)).is_err());
    for op in ["stepup_root", "broker_op", "exec", "stepup_sudo", "unlock", "checkpoint", "global_root_off"] {
        assert!(s.append(Source::Gatekeeper, ev(op, LEVEL_ROOT)).is_err(), "the gatekeeper must not report '{op}'");
    }
    assert!(s.append(Source::Broker, ev("exec", LEVEL_USER)).is_err() && s.append(Source::Broker, ev("stepup_root", LEVEL_ROOT)).is_ok());
    assert!(s.append(Source::Executor, ev("stepup_root", LEVEL_ROOT)).is_err() && s.append(Source::Executor, ev("exec", LEVEL_USER)).is_ok() && s.append(Source::Executor, ev("login", LEVEL_USER)).is_ok());
    assert!(s.append(Source::Executor, ev("checkpoint", LEVEL_NONE)).is_err(), "nobody but the audit process makes checkpoints");
    assert!(s.append(Source::Owner, ev("unlock", LEVEL_NONE)).is_ok() && s.append(Source::Owner, ev("exec", LEVEL_USER)).is_err());
    assert!(s.append(Source::Gatekeeper, ev("made-up", LEVEL_NONE)).is_err());
    let _ = d;
}

#[test]
fn a9_ordinary_and_security_events_go_to_their_own_journals() {
    let (d, s) = svc(100);
    s.append(Source::Executor, ev("exec", LEVEL_USER)).unwrap();
    s.append(Source::Broker, ev("stepup_root", LEVEL_ROOT)).unwrap();
    s.append(Source::Owner, ev("unlock", LEVEL_NONE)).unwrap();
    s.append(Source::Executor, ev("peer_refused", LEVEL_NONE)).unwrap();
    s.append(Source::Broker, ev("global_root_off", LEVEL_ROOT)).unwrap();
    s.append(Source::Gatekeeper, ev("enroll_guest", LEVEL_NONE)).unwrap();
    let ord: Vec<String> = records(&std::fs::read(path(d.path(), Journal::Ordinary)).unwrap()).iter().map(|r| Record::parse(&r[4..r.len() - 64]).unwrap().ev.op).collect();
    let sec: Vec<String> = records(&std::fs::read(path(d.path(), Journal::Security)).unwrap()).iter().map(|r| Record::parse(&r[4..r.len() - 64]).unwrap().ev.op).collect();
    assert_eq!(ord, vec!["exec", "stepup_root"]);
    assert_eq!(sec, vec!["start", "unlock", "peer_refused", "global_root_off", "enroll_guest"]);
    assert_eq!(Journal::of("stepup_sudo"), Journal::Ordinary);
    assert_eq!(Journal::of("lockout_tamper"), Journal::Security);
}

#[test]
fn a10_a_repeated_request_is_marked_as_a_repeat() {
    let (d, s) = svc(100);
    s.append(Source::Executor, ev("exec", LEVEL_USER).request(42)).unwrap();
    s.append(Source::Executor, ev("exec", LEVEL_USER).request(43)).unwrap();
    s.append(Source::Executor, ev("exec", LEVEL_USER).request(42)).unwrap(); // the same request id in the same session
    s.append(Source::Executor, ev("exec", LEVEL_USER).session(b"another-session!").request(42)).unwrap();
    s.append(Source::Executor, ev("pty", LEVEL_USER).request(42)).unwrap(); // another operation
    let flags: Vec<u8> = records(&std::fs::read(path(d.path(), Journal::Ordinary)).unwrap()).iter().map(|r| Record::parse(&r[4..r.len() - 64]).unwrap().flags).collect();
    assert_eq!(flags, vec![0, 0, FLAG_REPEAT, 0, 0]);
    // the flag is part of the sealed record: it cannot be removed afterwards
    let p = path(d.path(), Journal::Ordinary);
    let mut b = std::fs::read(&p).unwrap();
    let at: usize = records(&b)[..2].iter().map(|r| r.len()).sum();
    let flag_at = at + 4 + 4 + 3 + 8 + 8 + 1; // magic, kind, journal, source, seq, time, level
    assert_eq!(b[flag_at], FLAG_REPEAT);
    b[flag_at] = 0;
    std::fs::write(&p, b).unwrap();
    assert!(report(d.path(), Journal::Ordinary).fault.is_some());
}

#[test]
fn a11_no_secret_can_get_into_a_record() {
    let (d, s) = svc(100);
    let secret_path = b"/home/anna/secret-plans/phrase-correct-horse.txt";
    s.append(Source::Executor, Event::new("file", LEVEL_USER, RESULT_OK).hidden_target(secret_path).user("anna")).unwrap();
    s.append(Source::Executor, Event::new("tunnel", LEVEL_USER, RESULT_OK).hidden_target(b"internal.example:5432")).unwrap();
    let all = std::fs::read(path(d.path(), Journal::Ordinary)).unwrap();
    for needle in [&b"secret-plans"[..], b"correct-horse", b"internal.example", b"5432"] {
        assert!(!all.windows(needle.len()).any(|w| w == needle), "{:?} is in the journal", String::from_utf8_lossy(needle));
    }
    assert!(all.windows(2).any(|w| w == b"h:"), "a hashed target is marked as such");
    // the same target gives the same mark (so a person can find 'all that touched this path'), another one a different mark
    let a = Event::new("file", 1, 0).hidden_target(b"x").target;
    assert_eq!(a, Event::new("file", 1, 0).hidden_target(b"x").target);
    assert_ne!(a, Event::new("file", 1, 0).hidden_target(b"y").target);
    // control characters in a user name do not get into the journal
    let ev = Event::new("exec", 1, 0).user("an\x1b[2Jna\n");
    assert_eq!(ev.user, "an[2Jna");
}

#[test]
fn a12_checkpoints_come_every_n_events_and_a_clean_stop_seals() {
    let (d, s) = svc(4);
    fill(&s, 9);
    let rep = report(d.path(), Journal::Ordinary);
    assert_eq!((rep.checkpoints, rep.unsealed), (2, 1));
    s.seal().unwrap();
    let rep = report(d.path(), Journal::Ordinary);
    assert_eq!((rep.checkpoints, rep.unsealed), (3, 0));
    assert!(rep.sealed.is_some());
    s.seal().unwrap();
    assert_eq!(report(d.path(), Journal::Ordinary).checkpoints, 3, "nothing new to seal: no empty checkpoint");
    // a restart continues the same chain
    let n = rep.records;
    drop(s);
    let s2 = AuditService::open(d.path(), 4).unwrap();
    s2.append(Source::Executor, ev("exec", LEVEL_USER)).unwrap();
    let rep2 = report(d.path(), Journal::Ordinary);
    assert_eq!((rep2.fault, rep2.records), (None, n + 1));
}

#[test]
fn a13_a_journal_that_cannot_be_written_is_closed_not_skipped() {
    let (d, s) = svc(100);
    s.append(Source::Executor, ev("exec", LEVEL_USER)).unwrap();
    let p = path(d.path(), Journal::Ordinary);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
    if std::fs::OpenOptions::new().append(true).open(&p).is_ok() {
        return; // running as root: permissions do not stop it
    }
    assert!(s.append(Source::Executor, ev("exec", LEVEL_USER)).is_err(), "the failure is reported to the caller");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(s.append(Source::Executor, ev("exec", LEVEL_USER)).is_err(), "and the journal stays closed: no chain goes on from an unknown place");
    assert!(s.append(Source::Owner, ev("unlock", LEVEL_NONE)).is_err(), "all of it");
}

#[test]
fn a14_one_audit_process_per_directory_and_a_key_only_the_audit_holds() {
    let (d, _s) = svc(100);
    assert!(AuditService::open(d.path(), 100).err().unwrap().to_string().contains("another audit process"));
    assert_eq!(std::fs::metadata(d.path().join("audit/sign.key")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(d.path().join("audit/sign.pub")).unwrap().permissions().mode() & 0o777, 0o644);
    let d2 = tempfile::tempdir().unwrap();
    drop(AuditService::open(d2.path(), 100).unwrap());
    std::fs::set_permissions(d2.path().join("audit/sign.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(AuditService::open(d2.path(), 100).err().unwrap().to_string().contains("read by others"));
}

#[test]
fn a15_what_comes_over_the_wire_has_no_number_no_time_no_source() {
    let e = ev("exec", LEVEL_USER);
    let w = encode_event(&e).unwrap();
    assert_eq!(decode_event(&w).unwrap(), e);
    // a client that sneaks in its own number, time, flags or signature is not understood
    for (at, byte) in [(7usize, 9u8), (15, 1), (24, 1)] {
        let mut x = w.clone();
        x[at] = byte;
        assert!(decode_event(&x).is_err(), "byte {at} set");
    }
    let mut with_sig = Record::parse(&w).unwrap();
    with_sig.extra = vec![1; 64];
    assert!(decode_event(&with_sig.canonical().unwrap()).is_err());
}


/// rebuilds the framed bytes of a record list with the hashes recomputed (what somebody who knows the format but not the key can do)
fn rechain(recs: &[Record]) -> Vec<u8> {
    let mut prev = [0u8; 32];
    let mut out = vec![];
    for r in recs {
        let (b, h) = frame(r, &prev).unwrap();
        out.extend(b);
        prev = h;
    }
    out
}

fn parsed(bytes: &[u8]) -> Vec<Record> {
    records(bytes).iter().map(|r| Record::parse(&r[4..r.len() - 64]).unwrap()).collect()
}

#[test]
fn a16_a_tail_rewritten_with_good_hashes_but_wrong_numbers_is_found() {
    let (d, s) = svc(100);
    fill(&s, 8); // no checkpoint yet: the whole journal is an unsealed tail
    drop(s);
    let p = path(d.path(), Journal::Ordinary);
    let mut recs = parsed(&std::fs::read(&p).unwrap());
    recs[5].seq = 9; // a gap
    std::fs::write(&p, rechain(&recs)).unwrap();
    assert!(matches!(report(d.path(), Journal::Ordinary).fault, Some(Fault::BadNumber(9))), "{:?}", report(d.path(), Journal::Ordinary).fault);
}

#[test]
fn a17_the_stored_previous_hash_of_every_record_must_be_the_one_before() {
    let (d, s) = svc(100);
    fill(&s, 6);
    drop(s);
    let p = path(d.path(), Journal::Ordinary);
    let mut b = std::fs::read(&p).unwrap();
    let recs = records(&b);
    let at: usize = recs[..3].iter().map(|r| r.len()).sum();
    let prev_field = at + recs[3].len() - 64; // inside record 3: the stored 'previous hash'
    b[prev_field] ^= 1;
    std::fs::write(&p, &b).unwrap();
    assert!(matches!(report(d.path(), Journal::Ordinary).fault, Some(Fault::BrokenChain(3))), "{:?}", report(d.path(), Journal::Ordinary).fault);
}

#[test]
fn a18_a_forged_checkpoint_is_refused_even_without_the_head_file() {
    let (d, s) = svc(5);
    fill(&s, 12);
    drop(s);
    let evil_dir = tempfile::tempdir().unwrap();
    let evil = AuditService::open(evil_dir.path(), 5).unwrap();
    fill(&evil, 12);
    drop(evil);
    std::fs::copy(evil_dir.path().join("audit/ordinary.log"), path(d.path(), Journal::Ordinary)).unwrap();
    std::fs::remove_file(d.path().join("audit/ordinary.head")).unwrap();
    let rep = report(d.path(), Journal::Ordinary);
    assert!(matches!(rep.fault, Some(Fault::BadSignature(_))), "a chain with checkpoints signed by another key: {:?}", rep.fault);
}

#[test]
fn a19_a_log_cut_by_exactly_one_record_and_a_changed_sealed_record_are_both_found_by_the_head() {
    let (d, s) = svc(4);
    fill(&s, 8);
    s.seal().unwrap();
    drop(s);
    let p = path(d.path(), Journal::Ordinary);
    let orig = std::fs::read(&p).unwrap();
    let recs = records(&orig);
    // the head vouches for the last record (a checkpoint); take away exactly that one
    std::fs::write(&p, recs[..recs.len() - 1].concat()).unwrap();
    assert!(matches!(report(d.path(), Journal::Ordinary).fault, Some(Fault::Truncated { .. })), "{:?}", report(d.path(), Journal::Ordinary).fault);
    // a checkpoint's own time is not covered by its signature; changing it (and re-chaining) is caught because the head holds the hash of the whole record
    let mut all = parsed(&orig);
    let last = all.len() - 1;
    assert_eq!(all[last].kind, KIND_CHECKPOINT);
    all[last].time += 1;
    std::fs::write(&p, rechain(&all)).unwrap();
    let rep = report(d.path(), Journal::Ordinary);
    assert!(matches!(rep.fault, Some(Fault::BrokenChain(_))), "{:?}", rep.fault);
    std::fs::remove_file(d.path().join("audit/ordinary.head")).unwrap();
    assert_eq!(report(d.path(), Journal::Ordinary).fault, None, "(without the head this particular change is not visible: that is what the head is for)");
}

#[test]
fn a20_the_audit_process_itself_reports_only_its_own_things() {
    let (_d, s) = svc(100);
    for op in ["exec", "login", "stepup_root", "unlock", "session_open"] {
        assert!(s.append(Source::Audit, ev(op, LEVEL_NONE)).is_err(), "{op}");
    }
    assert!(s.append(Source::Audit, ev("audit_degraded", LEVEL_NONE)).is_ok() && s.append(Source::Audit, ev("repair", LEVEL_NONE)).is_ok());
}
