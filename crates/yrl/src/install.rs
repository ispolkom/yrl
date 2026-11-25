//! How the parts are laid out on a machine where they run as DIFFERENT system users: who owns what, who may read what, which door is open to whom.
//! One table is the single source: the commands that make the accounts and the directories, the check that finds anything that differs from it,
//! and the tests that compare the systemd unit files with it all come from here, so they cannot drift apart.
//!
//! The parts: gatekeeper (network, user `yrl-gate`), firewall (`yrl-fw`, the only one with CAP_NET_ADMIN), audit (`yrl-audit`), broker (`yrl-broker`),
//! executor (root, but with nothing in its capability set except changing to the account's user): it acts for the logged-in people, which a non-root user cannot do.
use anyhow::{bail, Result};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const GATE: &str = "yrl-gate";
pub const FW: &str = "yrl-fw";
pub const AUDIT: &str = "yrl-audit";
pub const BROKER: &str = "yrl-broker";
/// the executor runs as root and keeps only the right to become another user
pub const EXEC: &str = "root";

pub const G_CONF: &str = "yrl-conf"; // may read authorized_keys and users: the gatekeeper (checks the key and the password) and the executor
pub const G_TO_AUDIT: &str = "yrl-to-audit"; // may connect to the audit door
pub const G_TO_EXEC: &str = "yrl-to-exec";
pub const G_TO_BROKER: &str = "yrl-to-broker";
pub const G_TO_FW: &str = "yrl-to-fw";

/// (system user, groups it needs besides its own). The executor is root; it is listed so the unit file test can check it too.
pub const MEMBERS: &[(&str, &[&str])] = &[
    (GATE, &[G_CONF, G_TO_AUDIT, G_TO_EXEC, G_TO_FW]),
    (FW, &[G_TO_AUDIT, G_TO_FW]),
    (AUDIT, &[G_TO_AUDIT]),
    (BROKER, &[G_TO_AUDIT, G_TO_BROKER]),
    (EXEC, &[G_CONF, G_TO_AUDIT, G_TO_BROKER, G_TO_EXEC]),
];

pub const GROUPS: &[&str] = &[G_CONF, G_TO_AUDIT, G_TO_EXEC, G_TO_BROKER, G_TO_FW];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
}

#[derive(Clone, Debug)]
pub struct Item {
    /// relative to the base directory; empty = the directory itself
    pub path: String,
    pub kind: Kind,
    pub owner: &'static str,
    pub group: &'static str,
    pub mode: u32,
    /// without it the installation is not complete (a file the owner makes later with a command is not required)
    pub required: bool,
    pub why: &'static str,
}

fn it(path: &str, kind: Kind, owner: &'static str, group: &'static str, mode: u32, required: bool, why: &'static str) -> Item {
    Item { path: path.into(), kind, owner, group, mode, required, why }
}

/// the sides that have a key of their own for the doors (`ipc/<side>/static.key`) and whose user keeps it
pub const SIDES: &[(&str, &str)] = &[("gatekeeper", GATE), ("executor", EXEC), ("broker", BROKER), ("audit", AUDIT), ("firewall", FW), ("firewall-door", FW), ("owner", "root")];

/// the state directory (/var/lib/yrl)
pub fn state_layout() -> Vec<Item> {
    use Kind::*;
    let mut v = vec![
        it("", Dir, "root", "root", 0o755, true, "others may walk through it; the secrets are in files that say who reads them"),
        it("static.key", File, GATE, GATE, 0o600, true, "the server's identity: the gatekeeper alone"),
        it("authorized_keys", File, "root", G_CONF, 0o640, true, "the devices that may come in: read by the gatekeeper and the executor, written by the owner"),
        it("users", File, "root", G_CONF, 0o640, true, "accounts and password verifiers: read by the gatekeeper and the executor, written by the owner"),
        it("tunnels", File, "root", G_CONF, 0o640, false, "which destinations tunnels may reach: read by the executor"),
        it("words", File, EXEC, "root", 0o600, false, "SUDO phrase verifiers: the executor alone"),
        it("words.root", File, "root", "yrl-broker", 0o640, false, "ROOT phrase verifiers: the broker alone"),
        it("ipc", Dir, "root", "root", 0o755, true, "public halves of the door keys"),
        it("audit", Dir, AUDIT, AUDIT, 0o700, true, "the journals and the signing key: the audit process alone"),
        it("enroll", Dir, "root", GATE, 0o770, true, "the enrolment window: the owner's command writes the window, the gatekeeper puts the request"),
        it("exec", Dir, EXEC, "root", 0o700, true, "the executor's own state (its lockouts)"),
        it("broker", Dir, BROKER, BROKER, 0o700, true, "the broker's own state (its lockouts)"),
    ];
    for (side, user) in SIDES {
        v.push(it(&format!("ipc/{side}.pub"), File, "root", "root", 0o644, true, "a public key"));
        v.push(it(&format!("ipc/{side}"), Dir, user, if *user == "root" { "root" } else { user }, 0o700, true, "this side's private key: its own user alone"));
        v.push(it(&format!("ipc/{side}/static.key"), File, user, if *user == "root" { "root" } else { user }, 0o600, true, "this side's private key"));
    }
    v
}

/// the runtime directory (/run/yrl): each door in a directory of its own user, opened only to the group that may knock on it
pub fn run_layout() -> Vec<Item> {
    use Kind::*;
    vec![
        it("", Dir, "root", "root", 0o755, true, "parent of the doors"),
        it("audit", Dir, AUDIT, G_TO_AUDIT, 0o750, true, "audit door"),
        it("exec", Dir, EXEC, G_TO_EXEC, 0o750, true, "executor door"),
        it("broker", Dir, BROKER, G_TO_BROKER, 0o750, true, "broker door"),
        it("fw", Dir, FW, G_TO_FW, 0o750, true, "firewall door"),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub is_dir: bool,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    Missing(String),
    WrongKind(String),
    WrongOwner { path: String, want: u32, got: u32 },
    WrongGroup { path: String, want: u32, got: u32 },
    WrongMode { path: String, want: u32, got: u32 },
    UnknownName(String),
    /// something in the directory that the table does not know and that anybody can read, or a link
    Unexpected { path: String, why: &'static str },
}

pub trait Names {
    fn uid(&self, name: &str) -> Option<u32>;
    fn gid(&self, name: &str) -> Option<u32>;
}

pub struct SystemNames;

impl Names for SystemNames {
    fn uid(&self, name: &str) -> Option<u32> {
        crate::identity::lookup_name(name).map(|p| p.uid)
    }
    fn gid(&self, name: &str) -> Option<u32> {
        crate::ipc::gid_of_group(name).ok().or_else(|| crate::identity::lookup_name(name).map(|p| p.gid))
    }
}

/// the group of a private item is the group of its user: root's is `root`
pub fn judge(item: &Item, stat: Option<Stat>, names: &dyn Names) -> Vec<Problem> {
    let p = item.path.clone();
    let Some(st) = stat else {
        return if item.required { vec![Problem::Missing(p)] } else { vec![] };
    };
    if st.is_dir != (item.kind == Kind::Dir) {
        return vec![Problem::WrongKind(p)];
    }
    let mut out = vec![];
    match names.uid(item.owner) {
        Some(u) if u != st.uid => out.push(Problem::WrongOwner { path: p.clone(), want: u, got: st.uid }),
        None => out.push(Problem::UnknownName(item.owner.into())),
        _ => {}
    }
    match names.gid(item.group) {
        Some(g) if g != st.gid => out.push(Problem::WrongGroup { path: p.clone(), want: g, got: st.gid }),
        None => out.push(Problem::UnknownName(item.group.into())),
        _ => {}
    }
    if st.mode & 0o7777 != item.mode {
        out.push(Problem::WrongMode { path: p, want: item.mode, got: st.mode & 0o7777 });
    }
    out
}

fn stat_of(path: &Path) -> Option<Stat> {
    let m = std::fs::symlink_metadata(path).ok()?;
    Some(Stat { is_dir: m.is_dir(), uid: m.uid(), gid: m.gid(), mode: m.mode() })
}

fn at(base: &Path, rel: &str) -> PathBuf {
    if rel.is_empty() {
        base.to_path_buf()
    } else {
        base.join(rel)
    }
}

/// every difference between the machine and the table; the state directory also gets a look for strays (links, files anybody can read that the table does not list)
pub fn check(base: &Path, layout: &[Item], names: &dyn Names, scan_strays: bool) -> Vec<Problem> {
    let mut out = vec![];
    for item in layout {
        out.extend(judge(item, stat_of(&at(base, &item.path)), names));
    }
    if scan_strays {
        let known: std::collections::HashSet<&str> = layout.iter().map(|i| i.path.as_str()).collect();
        let mut stack = vec![(base.to_path_buf(), String::new())];
        while let Some((dir, rel)) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let r = if rel.is_empty() { name } else { format!("{rel}/{name}") };
                let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
                if m.file_type().is_symlink() {
                    out.push(Problem::Unexpected { path: r, why: "a link" });
                    continue;
                }
                if !known.contains(r.as_str()) && m.mode() & 0o007 != 0 && !r.starts_with("audit/") {
                    out.push(Problem::Unexpected { path: r.clone(), why: "readable or writable by anybody, and not in the table" });
                }
                // the audit directory is the audit process's own business; the others' own state is looked into too
                if m.is_dir() && !r.starts_with("audit") {
                    stack.push((e.path(), r));
                }
            }
        }
    }
    out
}

pub fn describe(p: &Problem) -> String {
    match p {
        Problem::Missing(x) => format!("missing: {x}"),
        Problem::WrongKind(x) => format!("a file where a directory belongs, or the reverse: {x}"),
        Problem::WrongOwner { path, want, got } => format!("{path}: owner is uid {got}, should be {want}"),
        Problem::WrongGroup { path, want, got } => format!("{path}: group is gid {got}, should be {want}"),
        Problem::WrongMode { path, want, got } => format!("{path}: mode is {got:o}, should be {want:o}"),
        Problem::UnknownName(n) => format!("no such system user or group: {n}"),
        Problem::Unexpected { path, why } => format!("{path}: {why}"),
    }
}

/// make the directories, give everything its owner, group and mode (as root). A required file that is not there is reported, not invented.
pub fn apply(base: &Path, layout: &[Item], names: &dyn Names) -> Result<Vec<Problem>> {
    let mut missing = vec![];
    for item in layout {
        let path = at(base, &item.path);
        if !path.exists() {
            if item.kind == Kind::Dir {
                std::fs::create_dir(&path).or_else(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })?;
            } else {
                if item.required {
                    missing.push(Problem::Missing(item.path.clone()));
                }
                continue;
            }
        }
        let (Some(u), Some(g)) = (names.uid(item.owner), names.gid(item.group)) else { bail!("no such system user or group for {}: {} / {}", item.path, item.owner, item.group) };
        // never follow a link planted where a file belongs
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            bail!("{} is a link; refusing to touch it", path.display());
        }
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::chown(c.as_ptr(), u, g) } != 0 {
            bail!("cannot give {} to {}:{}: {}", path.display(), item.owner, item.group, std::io::Error::last_os_error());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(item.mode))?;
    }
    Ok(missing)
}

/// shell commands that make the accounts (idempotent); the owner reads them before running them
pub fn accounts_script() -> String {
    let mut s = String::from("set -e\n");
    for g in GROUPS {
        s.push_str(&format!("getent group {g} >/dev/null || groupadd --system {g}\n"));
    }
    for (u, groups) in MEMBERS {
        if *u == "root" {
            continue;
        }
        s.push_str(&format!("getent passwd {u} >/dev/null || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin {u}\n"));
        s.push_str(&format!("usermod -aG {} {u}\n", groups.join(",")));
    }
    s
}

/// the runtime directories come back after every boot: systemd-tmpfiles makes them
pub fn tmpfiles_conf(run: &str) -> String {
    let mut s = String::new();
    for i in run_layout() {
        let p = if i.path.is_empty() { run.to_string() } else { format!("{run}/{}", i.path) };
        s.push_str(&format!("d {p} {:04o} {} {} -\n", i.mode, i.owner, i.group));
    }
    s
}
