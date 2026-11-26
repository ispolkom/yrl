//! The layout for separate system users: the table, the check, the commands, the unit files, and the small pieces the code needed for it
//! (door directories, socket groups, the server key in a shared directory, the owner staying the same after an unlock).
use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use yrl::install::*;

/// a world where the system users and groups are exactly these numbers
struct Fake(HashMap<&'static str, u32>);
impl Names for Fake {
    fn uid(&self, n: &str) -> Option<u32> {
        self.0.get(n).copied()
    }
    fn gid(&self, n: &str) -> Option<u32> {
        self.0.get(n).copied()
    }
}

fn world() -> Fake {
    let mut m = HashMap::new();
    for (i, n) in ["root", GATE, FW, AUDIT, BROKER, G_CONF, G_TO_AUDIT, G_TO_EXEC, G_TO_BROKER, G_TO_FW].iter().enumerate() {
        m.insert(*n, if *n == "root" { 0 } else { 900 + i as u32 });
    }
    Fake(m)
}

fn find(l: &[Item], p: &str) -> Item {
    l.iter().find(|i| i.path == p).unwrap_or_else(|| panic!("{p} is not in the table")).clone()
}

#[test]
fn i1_the_table_says_what_it_should_about_secrets() {
    let l = state_layout();
    // only these files may be read by any group, and only by the group named
    let group_readable: BTreeSet<(String, &str)> = l.iter().filter(|i| i.kind == Kind::File && i.mode & 0o040 != 0 && !i.path.ends_with(".pub")).map(|i| (i.path.clone(), i.group)).collect();
    let want: BTreeSet<(String, &str)> = [("authorized_keys", G_CONF), ("words.root", "yrl-broker")].iter().map(|(p, g)| (p.to_string(), *g)).collect();
    assert_eq!(group_readable, want, "which files a group may read");
    // nothing is open to everybody except the public keys
    let everyone: BTreeSet<String> = l.iter().filter(|i| i.kind == Kind::File && i.mode & 0o004 != 0).map(|i| i.path.clone()).collect();
    assert!(everyone.iter().all(|p| p.ends_with(".pub")), "world-readable files: {everyone:?}");
    // every private key is 0600 and its directory 0700, both its own user's
    for (side, user) in SIDES {
        let k = find(&l, &format!("ipc/{side}/static.key"));
        let d = find(&l, &format!("ipc/{side}"));
        assert_eq!((k.mode, d.mode, k.owner, d.owner), (0o600, 0o700, *user, *user), "{side}");
    }
    let s = find(&l, "static.key");
    assert_eq!((s.mode, s.owner), (0o600, GATE), "the server key is the gatekeeper's alone");
    // the SUDO verifiers belong to the executor, the ROOT verifiers to the broker, and neither to the gatekeeper
    assert_eq!(find(&l, "words").owner, EXEC);
    assert_eq!(find(&l, "words.root").group, "yrl-broker");
    assert!(!MEMBERS.iter().find(|(u, _)| *u == GATE).unwrap().1.contains(&G_TO_BROKER), "the gatekeeper has no way to the broker");
    // the audit process's directory is its own
    assert_eq!((find(&l, "audit").owner, find(&l, "audit").mode), (AUDIT, 0o700));
    // nothing is writable by others anywhere
    assert!(l.iter().chain(run_layout().iter()).all(|i| i.mode & 0o002 == 0), "no world-writable item");
    assert_eq!(run_layout().iter().filter(|i| i.mode & 0o020 != 0).count(), 0, "no door directory is writable by a group");
    assert_eq!(find(&l, "enroll").mode, 0o770, "the one directory a group writes into");
}

#[test]
fn i2_judge_names_every_kind_of_difference() {
    let w = world();
    let item = find(&state_layout(), "authorized_keys");
    let good = Stat { is_dir: false, uid: 0, gid: w.gid(G_CONF).unwrap(), mode: 0o100640 };
    assert!(judge(&item, Some(good), &w).is_empty());
    assert_eq!(judge(&item, None, &w), vec![Problem::Missing("authorized_keys".into())], "a required file");
    assert!(judge(&find(&state_layout(), "tunnels"), None, &w).is_empty(), "an optional one may be absent");
    assert_eq!(judge(&item, Some(Stat { is_dir: true, ..good }), &w), vec![Problem::WrongKind("authorized_keys".into())]);
    assert_eq!(judge(&item, Some(Stat { uid: 1000, ..good }), &w), vec![Problem::WrongOwner { path: "authorized_keys".into(), want: 0, got: 1000 }]);
    assert_eq!(judge(&item, Some(Stat { gid: 7, ..good }), &w), vec![Problem::WrongGroup { path: "authorized_keys".into(), want: w.gid(G_CONF).unwrap(), got: 7 }]);
    assert_eq!(judge(&item, Some(Stat { mode: 0o100644, ..good }), &w), vec![Problem::WrongMode { path: "authorized_keys".into(), want: 0o640, got: 0o644 }], "readable by everybody");
    assert_eq!(judge(&item, Some(Stat { mode: 0o100660, ..good }), &w).len(), 1, "writable by the group");
    assert_eq!(judge(&item, Some(good), &Fake(HashMap::new())).len(), 2, "unknown owner and group");
}

fn me() -> (u32, u32) {
    let m = std::fs::metadata("/proc/self").unwrap();
    (m.uid(), m.gid())
}

/// everybody is the current user: chown to oneself is allowed without root, so the whole apply/check can run for real
fn all_me() -> Fake {
    let (u, g) = me();
    let mut m = HashMap::new();
    for n in ["root", GATE, FW, AUDIT, BROKER] {
        m.insert(n, u);
    }
    for n in [G_CONF, G_TO_AUDIT, G_TO_EXEC, G_TO_BROKER, G_TO_FW, "root", GATE, FW, AUDIT, BROKER, "yrl-broker"] {
        m.insert(n, g);
    }
    Fake(m)
}

fn initialised() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let sd = d.path().join("srv");
    std::fs::create_dir(&sd).unwrap();
    std::fs::set_permissions(&sd, std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_yrld")).args(["init", sd.to_str().unwrap()]).output().unwrap();
    assert!(out.status.success());
    std::fs::write(sd.join("authorized_keys"), "").unwrap();
    std::fs::write(sd.join("users"), "").unwrap();
    (d, sd)
}

#[test]
fn i3_apply_then_check_is_clean_and_every_kind_of_damage_is_found() {
    let (_d, sd) = initialised();
    let w = all_me();
    let missing = apply(&sd, &state_layout(), &w).unwrap();
    assert!(missing.is_empty(), "{missing:?}");
    assert_eq!(std::fs::metadata(sd.join("authorized_keys")).unwrap().mode() & 0o7777, 0o640);
    assert_eq!(std::fs::metadata(&sd).unwrap().mode() & 0o7777, 0o755);
    assert_eq!(std::fs::metadata(sd.join("enroll")).unwrap().mode() & 0o7777, 0o770, "made, since the owner has not opened a window yet");
    assert!(std::fs::metadata(sd.join("audit")).unwrap().is_dir());
    let clean = check(&sd, &state_layout(), &w, true);
    assert!(clean.is_empty(), "{:?}", clean.iter().map(describe).collect::<Vec<_>>());
    // a key someone made readable
    std::fs::set_permissions(sd.join("ipc/executor/static.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(check(&sd, &state_layout(), &w, true).iter().any(|p| matches!(p, Problem::WrongMode { path, .. } if path == "ipc/executor/static.key")));
    std::fs::set_permissions(sd.join("ipc/executor/static.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    // a stray readable file, and a link
    std::fs::write(sd.join("notes.txt"), "x").unwrap();
    std::fs::set_permissions(sd.join("notes.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", sd.join("link")).unwrap();
    let p = check(&sd, &state_layout(), &w, true);
    assert!(p.iter().any(|x| matches!(x, Problem::Unexpected { path, .. } if path == "notes.txt")), "a stray file anybody can read");
    assert!(p.iter().any(|x| matches!(x, Problem::Unexpected { path, why } if path == "link" && *why == "a link")));
    assert!(!check(&sd, &state_layout(), &w, false).iter().any(|x| matches!(x, Problem::Unexpected { .. })), "strays are looked for only when asked");
    // a required file that is gone
    std::fs::remove_file(sd.join("static.key")).unwrap();
    assert!(check(&sd, &state_layout(), &w, false).contains(&Problem::Missing("static.key".into())));
    // apply never follows a link where a file belongs
    std::fs::remove_file(sd.join("link")).unwrap();
    std::fs::remove_file(sd.join("users")).unwrap();
    // the link points at a file of ours with a loose mode: if apply followed it, that file would be changed
    let target = sd.join("elsewhere");
    std::fs::write(&target, "x").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&target, sd.join("users")).unwrap();
    assert!(apply(&sd, &state_layout(), &w).is_err(), "a link in the place of a file is not followed");
    assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o7777, 0o644, "and what it points at is untouched");
}

#[test]
fn i4_the_commands_print_what_they_should() {
    let acc = accounts_script();
    for g in GROUPS {
        assert!(acc.contains(&format!("groupadd --system {g}")), "{g}");
    }
    for (u, groups) in MEMBERS {
        if *u == "root" {
            assert!(!acc.contains("useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin root"));
            continue;
        }
        assert!(acc.contains(&format!("--shell /usr/sbin/nologin {u}\n")), "{u} has no login shell");
        assert!(acc.contains(&format!("usermod -aG {} {u}\n", groups.join(","))), "{u}");
    }
    let t = tmpfiles_conf("/run/yrl");
    assert!(t.contains("d /run/yrl/audit 0750 yrl-audit yrl-to-audit -\n"));
    assert!(t.contains("d /run/yrl/exec 0750 root yrl-to-exec -\n"));
    assert!(t.contains("d /run/yrl 0755 root root -\n"));
    assert_eq!(t.lines().count(), run_layout().len());
}

// ---------------------------------------------------------------- the unit files

fn unit(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/systemd").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn val(text: &str, key: &str) -> Vec<String> {
    text.lines().filter_map(|l| l.strip_prefix(&format!("{key}="))).map(|s| s.trim().to_string()).collect()
}

fn words(v: Vec<String>) -> BTreeSet<String> {
    v.iter().flat_map(|s| s.split_whitespace().map(String::from)).collect()
}

#[test]
fn i5_the_unit_files_agree_with_the_table() {
    // (file, the user, the socket group the unit sets, its program, the paths it may write)
    let units = [
        ("yrl-audit.service", AUDIT, Some(G_TO_AUDIT), "audit", vec!["/var/lib/yrl/audit", "/run/yrl/audit"]),
        ("yrl-broker.service", BROKER, Some(G_TO_BROKER), "broker", vec!["/var/lib/yrl/broker", "/run/yrl/broker"]),
        ("yrl-executor.service", EXEC, Some(G_TO_EXEC), "executor", vec![]),
        ("yrl-firewall.service", FW, Some(G_TO_FW), "firewall", vec!["/run/yrl/fw"]),
        ("yrl-gatekeeper.service", GATE, None, "gatekeeper", vec!["/var/lib/yrl/enroll"]),
    ];
    for (file, user, sock_group, prog, writes) in units {
        let t = unit(file);
        assert_eq!(val(&t, "User"), vec![user.to_string()], "{file}: user");
        let want: BTreeSet<String> = MEMBERS.iter().find(|(u, _)| *u == user).unwrap().1.iter().map(|s| s.to_string()).collect();
        let got = words(val(&t, "SupplementaryGroups"));
        let conf = if user == EXEC || user == GATE { vec![G_CONF.to_string()] } else { vec![] };
        // the groups are exactly the ones the table gives that user (the executor and the gatekeeper also read the shared config)
        assert!(want.iter().all(|g| got.contains(g)), "{file}: a group is missing: want {want:?}, got {got:?}");
        assert!(got.iter().all(|g| want.contains(g)), "{file}: a group the table does not give: {got:?}");
        assert!(conf.iter().all(|g| got.contains(g)));
        assert_eq!(val(&t, "Environment").iter().filter(|e| e.starts_with("YRL_SOCKET_GROUP=")).cloned().collect::<Vec<_>>(), sock_group.map(|g| format!("YRL_SOCKET_GROUP={g}")).into_iter().collect::<Vec<_>>(), "{file}: the group of the door it opens");
        assert!(val(&t, "Environment").contains(&"YRL_RUN=/run/yrl".to_string()), "{file}");
        let exec = val(&t, "ExecStart");
        assert_eq!(exec.len(), 1);
        assert!(exec[0].starts_with(&format!("/opt/yrl/current/yrld {prog} /var/lib/yrl")), "{file}: {}", exec[0]);
        assert_eq!(val(&t, "NoNewPrivileges"), vec!["yes"], "{file}");
        assert_eq!(val(&t, "LimitCORE"), vec!["0"], "{file}: keys must not reach core dumps");
        assert_eq!(val(&t, "KillMode"), vec!["control-group"], "{file}: stop must include descendants");
        let rw: BTreeSet<String> = words(val(&t, "ReadWritePaths"));
        assert_eq!(rw, writes.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>(), "{file}: where it may write");
        if file != "yrl-executor.service" {
            assert_eq!(val(&t, "ProtectSystem"), vec!["strict"], "{file}");
            assert_eq!(val(&t, "ProtectHome"), vec!["yes"], "{file}");
        }
    }
    // the capabilities: nobody has more than the table of tasks says
    let caps = |f: &str| words(val(&unit(f), "CapabilityBoundingSet"));
    assert_eq!(caps("yrl-firewall.service"), ["CAP_NET_ADMIN".to_string()].into(), "the firewall program alone may change the packet filter");
    assert_eq!(caps("yrl-executor.service"), ["CAP_SETUID".to_string(), "CAP_SETGID".to_string()].into(), "the executor may only become another user");
    for f in ["yrl-audit.service", "yrl-broker.service", "yrl-gatekeeper.service"] {
        assert!(caps(f).is_empty(), "{f} has no capability at all");
        assert!(val(&unit(f), "AmbientCapabilities").is_empty(), "{f}");
    }
    for f in ["yrl-audit.service", "yrl-broker.service", "yrl-executor.service", "yrl-gatekeeper.service"] {
        assert!(!unit(f).contains("CAP_NET_ADMIN"), "{f}");
    }
    assert!(!unit("yrl-gatekeeper.service").contains("CAP_SETUID"));
    // only the gatekeeper reaches the network; the firewall program talks to the kernel's filter; the others only to sockets
    assert_eq!(words(val(&unit("yrl-gatekeeper.service"), "RestrictAddressFamilies")), ["AF_INET", "AF_INET6", "AF_UNIX"].iter().map(|s| s.to_string()).collect());
    assert_eq!(words(val(&unit("yrl-firewall.service"), "RestrictAddressFamilies")), ["AF_UNIX", "AF_NETLINK"].iter().map(|s| s.to_string()).collect());
    for f in ["yrl-audit.service", "yrl-broker.service"] {
        assert_eq!(words(val(&unit(f), "RestrictAddressFamilies")), ["AF_UNIX".to_string()].into(), "{f}");
    }
    // the doors across users: the program check through /proc is off exactly where the peer is another user, and a user id is named
    assert!(unit("yrl-executor.service").contains("--gate-uid yrl-gate --gate-exe -"));
    assert!(unit("yrl-firewall.service").contains("--gate-uid yrl-gate --gate-exe -"));
    assert!(unit("yrl-broker.service").contains("--exec-uid root --exec-exe -"));
    // Ordering is retained, but a component restart must not cascade-stop live Executor sessions.
    let g = unit("yrl-gatekeeper.service");
    for part in ["yrl-audit", "yrl-executor", "yrl-firewall"] {
        assert!(val(&g, "Wants").iter().any(|r| r.contains(&format!("{part}.service"))), "{part}");
    }
}

#[test]
fn i6_update_service_is_manual_offline_and_narrowly_writable() {
    let t = unit("yrl-update.service");
    assert_eq!(val(&t, "Type"), vec!["oneshot"]);
    assert!(val(&t, "ExecStart")[0].starts_with("/opt/yrl/current/yrl-update apply "));
    assert!(val(&t, "RestrictAddressFamilies").contains(&"AF_UNIX".to_string()));
    assert!(val(&t, "CapabilityBoundingSet").iter().all(|v| v.is_empty()));
    let rw = words(val(&t, "ReadWritePaths"));
    assert_eq!(rw, ["/opt/yrl".to_string(), "/var/lib/yrl-update".to_string()].into());
    assert!(!t.contains("[Install]"), "the updater must not be enabled automatically");
}

#[test]
fn i5b_services_have_global_budgets_and_restart_storm_protection() {
    for file in ["yrl-audit.service", "yrl-broker.service", "yrl-executor.service", "yrl-firewall.service", "yrl-gatekeeper.service"] {
        let text = unit(file);
        assert_eq!(val(&text, "StartLimitIntervalSec"), vec!["60s"], "{file}: restart window");
        assert_eq!(val(&text, "StartLimitBurst"), vec!["5"], "{file}: restart burst");
        assert_eq!(val(&text, "Restart"), vec!["on-failure"], "{file}");
        assert_eq!(val(&text, "Type"), vec!["notify"], "{file}: readiness is explicit");
        assert_eq!(val(&text, "NotifyAccess"), vec!["main"], "{file}");
        assert_eq!(val(&text, "WatchdogSec"), vec!["30s"], "{file}: hung event loop is restarted");
        assert!(!val(&text, "MemoryHigh").is_empty(), "{file}: soft memory budget");
        assert!(!val(&text, "MemoryMax").is_empty(), "{file}: hard memory budget");
        assert!(!val(&text, "TasksMax").is_empty(), "{file}: process budget");
        assert_eq!(val(&text, "CPUWeight"), vec!["100"], "{file}: CPU fair share without a hard quota");
        assert!(!val(&text, "IOWeight").is_empty(), "{file}: IO fair share without an implicit bandwidth cap");
        for accounting in ["MemoryAccounting", "TasksAccounting", "CPUAccounting", "IOAccounting"] {
            assert_eq!(val(&text, accounting), vec!["yes"], "{file}: {accounting}");
        }
    }
    let executor = unit("yrl-executor.service");
    assert_eq!(val(&executor, "OOMPolicy"), vec!["continue"], "a session OOM must not stop the Executor or its neighbors");
    assert_eq!(val(&executor, "Delegate"), vec!["yes"], "per-session cgroups remain delegated");
    assert!(val(&executor, "EnvironmentFile").iter().any(|v| v == "-/etc/yrl/yrl.env"), "session limits are configurable without editing the unit");
    assert!(!executor.contains("CPUQuota="));
    assert!(!executor.contains("IOReadBandwidthMax=") && !executor.contains("IOWriteBandwidthMax="), "no arbitrary service transfer-rate ceiling");
}

// ---------------------------------------------------------------- the small pieces

fn a_second_group() -> Option<u32> {
    let (_, g) = me();
    let mut buf = [0u32; 64];
    let n = unsafe { libc::getgroups(64, buf.as_mut_ptr()) };
    (0..n.max(0) as usize).map(|i| buf[i]).find(|x| *x != g)
}

#[test]
fn i6_door_directories_socket_groups_and_state_directories() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    // without YRL_RUN the sockets stay next to the files; with it each door has its directory
    std::env::remove_var("YRL_RUN");
    assert_eq!(yrl::ipc::sock_path(Path::new("/srv"), "audit", "audit.sock"), PathBuf::from("/srv/audit.sock"));
    std::env::set_var("YRL_RUN", "/run/yrl");
    assert_eq!(yrl::ipc::sock_path(Path::new("/srv"), "audit", "audit.sock"), PathBuf::from("/run/yrl/audit/audit.sock"));
    assert_eq!(yrl::ipc::sock_path(Path::new("/srv"), "exec", "ipc.sock"), PathBuf::from("/run/yrl/exec/ipc.sock"));
    assert_eq!(yrl::ipc::sock_path(Path::new("/srv"), "fw", "firewall.sock"), PathBuf::from("/run/yrl/fw/firewall.sock"));
    assert_eq!(yrl::ipc::sock_path(Path::new("/srv"), "broker", "broker.sock"), PathBuf::from("/run/yrl/broker/broker.sock"));
    std::env::remove_var("YRL_RUN");
    // state directories: a part's own if the installation made one
    assert_eq!(yrl::ipc::state_dir(d.path(), "exec"), d.path().to_path_buf());
    std::fs::create_dir(d.path().join("exec")).unwrap();
    assert_eq!(yrl::ipc::state_dir(d.path(), "exec"), d.path().join("exec"));
    // users by name or number
    assert_eq!(yrl::ipc::uid_arg("root").unwrap(), 0);
    assert_eq!(yrl::ipc::uid_arg("1234").unwrap(), 1234);
    assert!(yrl::ipc::uid_arg("no-such-user-yrl").is_err());
    // the socket: private by default; with a group, that group's and 0660; a group that cannot be set leaves no socket behind
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        std::env::remove_var("YRL_SOCKET_GROUP");
        let s1 = d.path().join("a.sock");
        let _l = yrl::ipc::bind_socket(&s1).unwrap();
        assert_eq!(std::fs::metadata(&s1).unwrap().mode() & 0o777, 0o600);
        if let Some(g) = a_second_group() {
            std::env::set_var("YRL_SOCKET_GROUP", g.to_string());
            let s2 = d.path().join("b.sock");
            let _l2 = yrl::ipc::bind_socket(&s2).unwrap();
            let m = std::fs::metadata(&s2).unwrap();
            assert_eq!((m.mode() & 0o777, m.gid()), (0o660, g), "the group may connect, others may not");
        } else {
            eprintln!("(this account is in no second group: the group case is skipped)");
        }
        std::env::set_var("YRL_SOCKET_GROUP", "no-such-group-yrl");
        let s3 = d.path().join("c.sock");
        assert!(yrl::ipc::bind_socket(&s3).is_err());
        assert!(!s3.exists(), "no half-open socket is left");
        std::env::remove_var("YRL_SOCKET_GROUP");
    });
}

#[test]
fn i7_a_server_key_in_a_shared_directory() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("state");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let kp = yrl::keys::init(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(yrl::keys::load_shared(&dir).unwrap().public, kp.public, "a directory others may walk through is fine when the file is private");
    assert!(yrl::keys::load(&dir).is_err(), "the strict loader still refuses such a directory");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(yrl::keys::load_shared(&dir).is_err(), "a directory the group can write into could have its key replaced");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o757)).unwrap();
    assert!(yrl::keys::load_shared(&dir).is_err());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    for bad in [0o640, 0o604, 0o644] {
        std::fs::set_permissions(dir.join("static.key"), std::fs::Permissions::from_mode(bad)).unwrap();
        assert!(yrl::keys::load_shared(&dir).is_err(), "{bad:o}");
    }
    std::fs::set_permissions(dir.join("static.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(yrl::keys::load_shared(&dir).is_ok());
    assert!(yrl::keys::load_shared(&d.path().join("nothing")).is_err());
}

#[test]
fn i8_an_unlock_leaves_the_files_with_the_user_that_uses_them() {
    use yrl::stepup::Lockouts;
    let d = tempfile::tempdir().unwrap();
    let _ = Lockouts::persistent(d.path(), "root");
    let Some(g) = a_second_group() else {
        eprintln!("(no second group in this account: the owner case is skipped)");
        return;
    };
    for f in ["lockouts.root", "lockouts.root.key"] {
        let c = std::ffi::CString::new(d.path().join(f).to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::chown(c.as_ptr(), u32::MAX, g) }, 0);
    }
    Lockouts::reset_files(d.path(), "root").unwrap();
    for f in ["lockouts.root", "lockouts.root.key"] {
        assert_eq!(std::fs::metadata(d.path().join(f)).unwrap().gid(), g, "{f} stayed with its group");
    }
}

// ---------------------------------------------------------------- the real programs with the options the unit files use

mod common;
use common::*;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Procs(Vec<Child>);
impl Drop for Procs {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn spawn(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_yrld")).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap()
}

async fn wait_for(p: PathBuf) {
    for _ in 0..200 {
        if p.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{} never appeared", p.display());
}

/// the executor expects its gatekeeper by user NAME and without the /proc check (as the unit file says); `gate_uid` is what the executor is told
async fn stand_with(gate_uid: &str) -> (tempfile::TempDir, Procs, String, Vec<u8>, Vec<u8>, yrl::keys::KeyPair) {
    stand_any(gate_uid, true).await
}

async fn stand_default_exe() -> (tempfile::TempDir, Procs, String, Vec<u8>, Vec<u8>, yrl::keys::KeyPair) {
    stand_any(&my_user_name(), false).await
}

async fn stand_any(gate_uid: &str, no_exe_check: bool) -> (tempfile::TempDir, Procs, String, Vec<u8>, Vec<u8>, yrl::keys::KeyPair) {
    let dir = tempfile::tempdir().unwrap();
    let sd = dir.path().join("srv");
    let out = Command::new(env!("CARGO_BIN_EXE_yrld")).args(["init", sd.to_str().unwrap()]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let server_pub = hex::decode(text.lines().find(|l| l.contains("server public")).unwrap().split_whitespace().last().unwrap()).unwrap();
    let exec_pub = hex::decode(text.lines().find(|l| l.contains("executor public")).unwrap().split_whitespace().last().unwrap()).unwrap();
    let client = yrl::keys::generate();
    yrl::keys::authorize(&sd.join("authorized_keys"), &hex::encode(&client.public), "laptop", "exec").unwrap();
    yrl::users::set_user(&sd.join("users"), "anna", "exec", PW).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let s = sd.to_str().unwrap().to_string();
    let mut procs = Procs(vec![]);
    procs.0.push(spawn(&["audit", &s]));
    wait_for(sd.join("audit.sock")).await;
    procs.0.push(spawn(&["broker", &s]));
    wait_for(sd.join("broker.sock")).await;
    if no_exe_check {
        procs.0.push(spawn(&["executor", &s, "--gate-uid", gate_uid, "--gate-exe", "-"]));
    } else {
        procs.0.push(spawn(&["executor", &s, "--gate-uid", gate_uid]));
    }
    wait_for(sd.join("ipc.sock")).await;
    // the gatekeeper is a COPY of the program, as another program would be: only a door that does not look at /proc/<pid>/exe lets it in
    let copy = dir.path().join("gatekeeper-yrld");
    std::fs::copy(env!("CARGO_BIN_EXE_yrld"), &copy).unwrap();
    procs.0.push(Command::new(&copy).args(["gatekeeper", &s, &format!("127.0.0.1:{port}")]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    tokio::time::sleep(Duration::from_millis(700)).await;
    (dir, procs, format!("127.0.0.1:{port}"), server_pub, exec_pub, client)
}

fn my_user_name() -> String {
    yrl::identity::lookup_uid(me().0).map(|p| p.name).unwrap_or_else(|| me().0.to_string())
}

#[tokio::test]
async fn i9_the_door_between_users_is_kept_by_user_id_and_the_proc_check_can_be_off() {
    // told the gatekeeper's user by name, with the program check off: it works
    let (_d, _p, addr, server_pub, exec_pub, client) = stand_with(&my_user_name()).await;
    let c = yrl::client::Client::connect_opts(&addr, &client, &server_pub, yrl::client::ClientOptions { executor_public: Some(exec_pub), ..fast_opts() }).await.unwrap();
    c.login("anna", PW, T).await.expect("the gatekeeper is the expected user");
    assert_eq!(c.exec(&[b"echo", b"across"], 5000, Duration::from_secs(20)).await.unwrap().stdout, b"across\n");
    // told another user: the same gatekeeper is a stranger at the door
    // ... and when the program check is on (the default), the same copy is a stranger even with the right user id
    let (_d3, _p3, addr3, server_pub3, exec_pub3, client3) = stand_default_exe().await;
    let c3 = yrl::client::Client::connect_opts(&addr3, &client3, &server_pub3, yrl::client::ClientOptions { executor_public: Some(exec_pub3), ..fast_opts() }).await;
    assert!(c3.is_err(), "by default the door wants the very same program");
    let other = if me().0 == 1 { "2" } else { "1" };
    let (_d2, _p2, addr2, server_pub2, exec_pub2, client2) = stand_with(other).await;
    let c2 = yrl::client::Client::connect_opts(&addr2, &client2, &server_pub2, yrl::client::ClientOptions { executor_public: Some(exec_pub2), ..fast_opts() }).await;
    assert!(c2.is_err(), "the door checks the user id");
}

#[test]
fn i10_the_owners_commands_leave_the_files_with_the_part_that_reads_them() {
    use yrl::stepup::{Level, Verifier};
    let Some(g) = a_second_group() else {
        eprintln!("(no second group in this account: the owner case is skipped)");
        return;
    };
    let d = tempfile::tempdir().unwrap();
    let regroup = |p: &Path, mode: u32| {
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::chown(c.as_ptr(), u32::MAX, g) }, 0);
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    // the accounts file: read by the gatekeeper through a group
    let users = d.path().join("users");
    yrl::users::set_user(&users, "anna", "exec", b"correct horse battery").unwrap();
    assert_eq!(std::fs::metadata(&users).unwrap().mode() & 0o7777, 0o600, "a first file is private");
    regroup(&users, 0o640);
    yrl::users::set_user(&users, "bob", "exec", b"another long password").unwrap();
    let m = std::fs::metadata(&users).unwrap();
    assert_eq!((m.gid(), m.mode() & 0o7777), (g, 0o640), "a second account does not change who may read the file");
    assert!(std::fs::read_to_string(&users).unwrap().contains("anna"), "and the first account is still there");
    // the verifiers of the phrases
    Verifier::set(d.path(), Level::Sudo, b"a long enough phrase here").unwrap();
    regroup(&d.path().join("words"), 0o640);
    Verifier::set(d.path(), Level::Sudo, b"a different long phrase now").unwrap();
    let m = std::fs::metadata(d.path().join("words")).unwrap();
    assert_eq!((m.gid(), m.mode() & 0o7777), (g, 0o640));
    // a file that has no old one to take from
    assert!(yrl::keys::inherit(&d.path().join("nothing"), &users).is_ok());
}

#[test]
fn i11_secret_files_read_through_a_group_are_read_and_the_loose_ones_are_not() {
    use yrl::stepup::{Level, Verifier};
    let d = tempfile::tempdir().unwrap();
    let set = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    let users = d.path().join("users");
    yrl::users::set_user(&users, "anna", "exec", b"correct horse battery").unwrap();
    let tunnels = d.path().join("tunnels");
    std::fs::write(&tunnels, "allow anna example.org 22\n").unwrap();
    Verifier::set(d.path(), Level::Sudo, b"a long enough phrase here").unwrap();
    Verifier::set(d.path(), Level::Root, b"another long enough phrase").unwrap();
    let words = d.path().join("words");
    let words_root = d.path().join("words.root");
    let readable = |mode: u32| -> [bool; 4] {
        for p in [&users, &tunnels, &words, &words_root] {
            set(p, mode);
        }
        [!yrl::users::read_users(&users).is_empty(), !yrl::tunnel::read_rules(&tunnels).is_empty(), Verifier::check(d.path(), Level::Sudo, b"a long enough phrase here"), Verifier::check(d.path(), Level::Root, b"another long enough phrase")]
    };
    assert_eq!(readable(0o600), [true; 4], "one user: private");
    assert_eq!(readable(0o640), [true; 4], "read through a group");
    assert_eq!(readable(0o440), [true; 4]);
    for loose in [0o660, 0o620, 0o644, 0o604, 0o601, 0o602, 0o666, 0o700 | 0o007] {
        assert_eq!(readable(loose), [false; 4], "{loose:o}: writable by the group, or open to others");
    }
}

#[test]
fn i12_the_audit_directory_is_private_and_stays_as_the_installation_made_it() {
    let d = tempfile::tempdir().unwrap();
    let svc = yrl::audit::AuditService::open(d.path(), 100).unwrap();
    drop(svc);
    assert_eq!(std::fs::metadata(d.path().join("audit")).unwrap().mode() & 0o7777, 0o700, "a new journal directory is private");
    // the installation (or the owner) made it something else: the process does not widen it, nor narrow it
    std::fs::set_permissions(d.path().join("audit"), std::fs::Permissions::from_mode(0o750)).unwrap();
    let svc = yrl::audit::AuditService::open(d.path(), 100).unwrap();
    drop(svc);
    assert_eq!(std::fs::metadata(d.path().join("audit")).unwrap().mode() & 0o7777, 0o750);
}

#[test]
fn i13_a_failed_login_says_why_in_the_owners_log_and_nothing_to_the_sender() {
    let d = tempfile::tempdir().unwrap();
    let users = d.path().join("users");
    assert!(yrl::users::why_unreadable(&users).unwrap().contains("missing"));
    yrl::users::set_user(&users, "anna", "exec", b"correct horse battery").unwrap();
    assert_eq!(yrl::users::why_unreadable(&users), None);
    std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(yrl::users::why_unreadable(&users).unwrap().contains("refused"));
    std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(yrl::users::why_unreadable(&users), None, "read through a group is allowed");
}

#[tokio::test]
async fn i14_the_server_log_tells_a_wrong_password_from_a_lock_and_from_a_bad_file() {
    let r = rig("exec").await;
    let log = |needle: &str| r.log.lock().unwrap().iter().any(|l| l.contains(needle));
    let c = yrl::client::Client::connect_pinned(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T).await.unwrap();
    assert!(c.login("anna", b"not the password at all", T).await.is_err());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(log("wrong password, or no such account"), "{:?}", r.log.lock().unwrap());
    // the file the gatekeeper reads is made unreadable for it: the log says that, not 'wrong password'
    let users = r.server_dir().join("users");
    std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o666)).unwrap();
    let c2 = yrl::client::Client::connect_pinned(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T).await.unwrap();
    assert!(c2.login("anna", PW, T).await.is_err());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(log("accounts file is writable by its group or open to others"), "{:?}", r.log.lock().unwrap());
    std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o600)).unwrap();
    // enough failures: the lock is named
    for _ in 0..8 {
        if let Ok(c) = yrl::client::Client::connect_pinned(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T).await {
            let _ = c.login("anna", b"wrong wrong wrong", T).await;
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(log("locked after repeated failures"), "{:?}", r.log.lock().unwrap());
}
