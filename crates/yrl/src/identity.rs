//! Who a session's commands run as. Decided once, at login, by `resolve`; fails closed.
//! - an account may name an operating-system user (`os=` in the users file); the server switches to that user only when it runs as root;
//! - a server running as root refuses accounts that name nobody (it would hand out root);
//! - uid 0 is reachable only with the right `root`;
//! - a server that is not root can only serve accounts whose user is the one it already runs as.
use std::fs;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pw {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub pw: Pw,
    /// the child must change to this user (only possible from root)
    pub switch: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NoOsUserAsRoot,
    UnknownUser,
    RootNeedsRight,
    CannotSwitch,
}

impl Refusal {
    pub fn why(&self) -> &'static str {
        match self {
            Refusal::NoOsUserAsRoot => "the server is root and the account names no system user",
            Refusal::UnknownUser => "the system user of the account does not exist",
            Refusal::RootNeedsRight => "the account maps to uid 0 without the right 'root'",
            Refusal::CannotSwitch => "the account needs another system user and the server is not root",
        }
    }
}

pub fn parse_passwd(text: &str) -> Vec<Pw> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 6 {
                return None;
            }
            Some(Pw { name: f[0].to_string(), uid: f[2].parse().ok()?, gid: f[3].parse().ok()?, home: f[5].to_string(), shell: f.get(6).unwrap_or(&"").to_string() })
        })
        .collect()
}

pub fn lookup_name(name: &str) -> Option<Pw> {
    parse_passwd(&fs::read_to_string("/etc/passwd").ok()?).into_iter().find(|p| p.name == name)
}

pub fn lookup_uid(uid: u32) -> Option<Pw> {
    parse_passwd(&fs::read_to_string("/etc/passwd").ok()?).into_iter().find(|p| p.uid == uid)
}

pub fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn resolve(os_user: Option<&str>, my_euid: u32, rights: &[String], by_name: impl Fn(&str) -> Option<Pw>, by_uid: impl Fn(u32) -> Option<Pw>) -> Result<Target, Refusal> {
    let Some(name) = os_user else {
        if my_euid == 0 {
            return Err(Refusal::NoOsUserAsRoot);
        }
        let pw = by_uid(my_euid).unwrap_or(Pw { name: "yrl".into(), uid: my_euid, gid: my_euid, home: "/".into(), shell: String::new() });
        return Ok(Target { pw, switch: false });
    };
    let pw = by_name(name).ok_or(Refusal::UnknownUser)?;
    if pw.uid == 0 && !rights.iter().any(|r| r == "root") {
        return Err(Refusal::RootNeedsRight);
    }
    if pw.uid == my_euid {
        return Ok(Target { pw, switch: false });
    }
    if my_euid != 0 {
        return Err(Refusal::CannotSwitch);
    }
    Ok(Target { pw, switch: true })
}

/// an interactive shell is started only from the list of login shells of the system and only if it is a real executable
pub fn usable_shell(shell: &str, shells_file: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    shell.starts_with('/')
        && !shell.ends_with("/nologin")
        && !shell.ends_with("/false")
        && shells_file.lines().any(|l| l.trim() == shell)
        && std::fs::metadata(shell).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}
