//! Whose rights a session's commands get (src/identity.rs) and what the program sees of the server.
mod common;
use common::*;
use yrl::client::Client;
use yrl::identity::{parse_passwd, resolve, Pw, Refusal};

fn pw(name: &str, uid: u32) -> Pw {
    Pw { name: name.into(), uid, gid: uid, home: format!("/home/{name}"), shell: "/bin/bash".into() }
}
fn by_name(n: &str) -> Option<Pw> {
    match n {
        "root" => Some(pw("root", 0)),
        "anna" => Some(pw("anna", 1000)),
        "bob" => Some(pw("bob", 1001)),
        _ => None,
    }
}
fn by_uid(u: u32) -> Option<Pw> {
    ["root", "anna", "bob"].iter().filter_map(|n| by_name(n)).find(|p| p.uid == u)
}
fn r(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn i1_decision_matrix() {
    let go = |os: Option<&str>, euid: u32, rights: &[&str]| resolve(os, euid, &r(rights), by_name, by_uid);
    // a root server never hands out root by default
    assert_eq!(go(None, 0, &["exec", "root"]), Err(Refusal::NoOsUserAsRoot));
    // an unprivileged server serves only itself
    let t = go(None, 1000, &["exec"]).unwrap();
    assert_eq!((t.pw.name.as_str(), t.switch), ("anna", false));
    assert_eq!(go(Some("anna"), 1000, &["exec"]).unwrap().switch, false);
    assert_eq!(go(Some("bob"), 1000, &["exec"]), Err(Refusal::CannotSwitch));
    // root server switches to the named user
    let t = go(Some("bob"), 0, &["exec"]).unwrap();
    assert_eq!((t.pw.uid, t.switch), (1001, true));
    // unknown user
    assert_eq!(go(Some("ghost"), 0, &["exec", "root"]), Err(Refusal::UnknownUser));
    // uid 0 only with the right 'root', from any server
    assert_eq!(go(Some("root"), 0, &["exec"]), Err(Refusal::RootNeedsRight));
    assert_eq!(go(Some("root"), 0, &[]), Err(Refusal::RootNeedsRight));
    let t = go(Some("root"), 0, &["root"]).unwrap();
    assert_eq!((t.pw.uid, t.switch), (0, false), "root server, root account: no switch needed");
    assert_eq!(go(Some("root"), 1000, &["root"]), Err(Refusal::CannotSwitch));
    // having 'root' does not let a non-root account become anybody else
    assert_eq!(go(Some("bob"), 1000, &["exec", "root"]), Err(Refusal::CannotSwitch));
}

#[test]
fn i2_passwd_parsing_skips_damaged_lines() {
    let t = "root:x:0:0:root:/root:/bin/bash\nbroken line\nbob:x:notanumber:5:b:/home/bob:/bin/sh\nanna:x:1000:1000:A,,,:/home/anna:/bin/bash\n::\n";
    let v = parse_passwd(t);
    assert_eq!(v.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["root", "anna"]);
    assert_eq!((v[1].uid, v[1].gid, v[1].home.as_str()), (1000, 1000, "/home/anna"));
    assert!(parse_passwd("short:x:1:1:no-home-field").is_empty(), "a line without a home field is not an account");
    assert_eq!(parse_passwd("min:x:5:6::/h").len(), 1, "an empty comment field is fine");
}

fn me() -> Option<Pw> {
    yrl::identity::lookup_uid(yrl::identity::euid())
}

#[tokio::test]
async fn i3_the_program_sees_only_a_small_known_environment() {
    std::env::set_var("YRL_SERVER_SECRET", "must-not-leak");
    std::env::set_var("LD_PRELOAD_TEST_MARK", "x");
    let r = rig("exec").await;
    let c = open(&r).await;
    let out = c.exec(&[b"env"], 5000, T).await.unwrap().stdout;
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(!text.contains("must-not-leak") && !text.contains("LD_PRELOAD_TEST_MARK"), "the server's environment leaked: {text}");
    let mut keys: Vec<&str> = text.lines().filter_map(|l| l.split('=').next()).collect();
    keys.sort();
    keys.retain(|k| !matches!(*k, "PWD" | "SHLVL" | "_" | "OLDPWD")); // added by the tool itself
    assert_eq!(keys, vec!["HOME", "LOGNAME", "PATH", "USER"]);
    if let Some(m) = me() {
        assert!(text.contains(&format!("USER={}", m.name)) && text.contains(&format!("HOME={}", m.home)));
        let pwd = c.exec(&[b"pwd"], 5000, T).await.unwrap().stdout;
        if std::path::Path::new(&m.home).is_dir() {
            assert_eq!(String::from_utf8_lossy(&pwd).trim(), std::fs::canonicalize(&m.home).unwrap().to_string_lossy(), "starts in the home of the user");
        }
    }
}

async fn account(r: &Rig, login: &str, rights: &str, os: Option<&str>) {
    yrl::users::set_user_os(&r.server_dir().join("users"), login, rights, os, b"some good password").unwrap();
}

async fn try_login(r: &Rig, login: &str) -> bool {
    let c = Client::connect(&r.addr, &r.client, &r.server_pub, T).await.unwrap();
    c.login(login, b"some good password", T).await.is_ok()
}

#[tokio::test]
async fn i4_an_account_that_cannot_get_a_safe_identity_is_refused_even_with_the_right_password() {
    let r = rig_with("exec,root", |c| c.with_lock(1000, std::time::Duration::from_secs(1), std::time::Duration::from_secs(1))).await;
    if yrl::identity::euid() == 0 {
        return; // the matrix above covers root; this live check is for an unprivileged server
    }
    account(&r, "wantsroot", "exec,root", Some("root")).await;
    account(&r, "other", "exec", Some("daemon")).await;
    account(&r, "ghost", "exec", Some("no-such-user-qq")).await;
    for l in ["wantsroot", "other", "ghost"] {
        assert!(!try_login(&r, l).await, "{l}: a server that is not root cannot give another identity");
    }
    let log = r.log.lock().unwrap().join("\n");
    assert!(log.contains("not root") && log.contains("does not exist"));
    let m = me().expect("the user running the tests is in /etc/passwd");
    account(&r, "myself", "exec", Some(&m.name)).await;
    assert!(try_login(&r, "myself").await, "naming the user the server already runs as is fine");
    let c = Client::connect(&r.addr, &r.client, &r.server_pub, T).await.unwrap();
    c.login("myself", b"some good password", T).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&c.exec(&[b"id", b"-un"], 5000, T).await.unwrap().stdout).trim(), m.name);
}

#[test]
fn i5_system_user_names_and_the_users_file() {
    use yrl::users::{read_users, set_user_os, valid_os_name};
    for good in ["anna", "_x", "a-b_c9", "a".repeat(32).as_str()] {
        assert!(valid_os_name(good), "{good}");
    }
    for bad in ["", "Anna", "9a", "-a", "a b", "a:b", "a/b", "../etc", "a\n", "root;id", &"a".repeat(33)] {
        assert!(!valid_os_name(bad), "{bad:?}");
    }
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("users");
    assert!(set_user_os(&f, "bob", "exec", Some("Bad Name"), b"long enough pw").is_err());
    set_user_os(&f, "bob", "exec", Some("anna"), b"long enough pw").unwrap();
    set_user_os(&f, "carl", "exec", None, b"long enough pw").unwrap();
    let u = read_users(&f);
    assert_eq!((u[0].os_user.as_deref(), u[1].os_user.as_deref()), (Some("anna"), None));
    // a hand-edited line with a bad os= field is dropped as a whole, not half-trusted
    let mut t = std::fs::read_to_string(&f).unwrap();
    t.push_str(&format!("evil exec {} os=Root;id\n", yrl::users::hash_password(b"whatever pw").unwrap()));
    t.push_str(&format!("evil2 exec {} root\n", yrl::users::hash_password(b"whatever pw").unwrap()));
    std::fs::write(&f, t).unwrap();
    std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    assert_eq!(read_users(&f).len(), 2);
}
