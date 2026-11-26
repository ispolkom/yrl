//! Transactional activation of already signed YRL release bundles.
use crate::auditlog::{Event, LEVEL_NONE, RESULT_ERROR, RESULT_OK};
use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
struct State {
    max: u64,
    current: Option<u64>,
    previous: Option<u64>,
    time_floor: u64,
    data_format: u32,
    metadata_expiry: u64,
}
impl Default for State {
    fn default() -> Self {
        Self {
            max: 0,
            current: None,
            previous: None,
            time_floor: 0,
            data_format: 1,
            metadata_expiry: 0,
        }
    }
}
impl State {
    fn encode(&self) -> Vec<u8> {
        format!(
            "YRL-UPDATE-STATE-1 {} {} {} {} {} {}\n",
            self.max,
            opt(self.current),
            opt(self.previous),
            self.time_floor,
            self.data_format,
            self.metadata_expiry
        )
        .into_bytes()
    }
    fn parse(b: &[u8]) -> Result<Self> {
        let binding = std::str::from_utf8(b)?;
        let f: Vec<_> = binding.split_whitespace().collect();
        if f.len() != 7 || f[0] != "YRL-UPDATE-STATE-1" {
            bail!("invalid update state")
        };
        Ok(Self {
            max: f[1].parse()?,
            current: unopt(f[2])?,
            previous: unopt(f[3])?,
            time_floor: f[4].parse()?,
            data_format: f[5].parse()?,
            metadata_expiry: f[6].parse()?,
        })
    }
}
fn opt(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
}
fn unopt(v: &str) -> Result<Option<u64>> {
    Ok(if v == "-" { None } else { Some(v.parse()?) })
}

fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(path.parent().context("no parent")?)?.sync_all()?;
    Ok(())
}
fn load_state(dir: &Path) -> Result<State> {
    let p = dir.join("state");
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
        Err(e) => return Err(e.into()),
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.permissions().mode() & 0o077 != 0
        || m.len() > 4096
    {
        bail!("unsafe update state file");
    }
    let mut bytes = Vec::new();
    use std::io::Read;
    file.read_to_end(&mut bytes)?;
    State::parse(&bytes)
}
fn save_state(dir: &Path, s: &State) -> Result<()> {
    atomic(&dir.join("state"), &s.encode())
}
fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.permissions().mode() & 0o022 != 0 {
        bail!("unsafe update directory {}", path.display())
    }
    Ok(())
}

fn bundle_paths(bundle: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    (
        bundle.join("artifacts"),
        bundle.join("manifest.txt"),
        bundle.join("manifest.sig"),
        bundle.join("delegation.txt"),
    )
}
fn release_dir(root: &Path, n: u64) -> PathBuf {
    root.join("releases").join(format!("{n:020}"))
}

fn copy_file(from: &Path, to: &Path, mode: u32) -> Result<()> {
    let m = fs::symlink_metadata(from)?;
    if !m.is_file() || m.nlink() != 1 {
        bail!("unsafe update artifact")
    };
    let b = fs::read(from)?;
    if b.len() as u64 != m.len() {
        bail!("artifact changed while staging")
    };
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(to)?;
    f.write_all(&b)?;
    f.sync_all()?;
    Ok(())
}
fn stage_bundle(bundle: &Path, stage: &Path, m: &crate::release::Manifest) -> Result<()> {
    fs::create_dir(stage)?;
    fs::set_permissions(stage, fs::Permissions::from_mode(0o755))?;
    let art = stage.join("artifacts");
    fs::create_dir(&art)?;
    for (path, _, _) in &m.files {
        let source = bundle.join("artifacts").join(path);
        let executable = fs::symlink_metadata(&source)?.permissions().mode() & 0o111 != 0;
        copy_file(
            &source,
            &art.join(path),
            if executable { 0o755 } else { 0o644 },
        )?;
    }
    let meta = stage.join("metadata");
    fs::create_dir(&meta)?;
    for name in ["manifest.txt", "manifest.sig", "delegation.txt"] {
        copy_file(&bundle.join(name), &meta.join(name), 0o644)?;
    }
    File::open(&art)?.sync_all()?;
    File::open(stage)?.sync_all()?;
    Ok(())
}

fn health(release: &Path, yrl_state: &Path) -> Result<()> {
    let yrld = release.join("artifacts/yrld");
    if !yrld.exists() {
        bail!("release has no yrld health-check binary")
    };
    let mut child = Command::new(yrld)
        .args(["install", "check"])
        .arg(yrl_state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            bail!("new release health check failed")
        };
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            bail!("new release health check timed out")
        };
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn switch(root: &Path, target: Option<u64>) -> Result<()> {
    let current = root.join("current");
    let tmp = root.join(format!(".current-{}", std::process::id()));
    if tmp.exists() {
        fs::remove_file(&tmp)?;
    }
    match target {
        Some(n) => std::os::unix::fs::symlink(format!("releases/{n:020}/artifacts"), &tmp)?,
        None => std::os::unix::fs::symlink("unconfigured", &tmp)?,
    }
    fs::rename(&tmp, &current)?;
    File::open(root)?.sync_all()?;
    Ok(())
}

async fn note(audit: &crate::audit::AuditClient, op: &str, n: u64, result: u8) -> Result<()> {
    audit
        .record_critical(Event::new(op, LEVEL_NONE, result).target(&format!("release={n}")))
        .await?;
    Ok(())
}

fn verify_installed(
    root: &Path,
    n: u64,
    trust: &Path,
    now: u64,
) -> Result<crate::release::Manifest> {
    let dir = release_dir(root, n);
    let meta = dir.join("metadata");
    crate::release::verify_release(
        &dir.join("artifacts"),
        &meta.join("manifest.txt"),
        &meta.join("manifest.sig"),
        &meta.join("delegation.txt"),
        trust,
        now,
    )
}

fn verify_rollback(root: &Path, n: u64, trust: &Path) -> Result<crate::release::Manifest> {
    let dir = release_dir(root, n);
    let meta = dir.join("metadata");
    let manifest = crate::release::Manifest::parse(&fs::read(meta.join("manifest.txt"))?)?;
    let store = crate::release::load_trust(trust)?;
    let delegation = crate::release::parse_delegation(&meta.join("delegation.txt"), &store)?;
    let at = manifest.created.max(delegation.valid_from);
    if at > manifest.expires.min(delegation.valid_until) {
        bail!("rollback release never had a common valid metadata interval")
    }
    verify_installed(root, n, trust, at)
}

pub async fn apply(
    bundle: &Path,
    trust: &Path,
    root: &Path,
    ledger: &Path,
    yrl_state: &Path,
    now: u64,
    audit: &crate::audit::AuditClient,
) -> Result<()> {
    ensure_dir(root, 0o755)?;
    ensure_dir(&root.join("releases"), 0o755)?;
    ensure_dir(ledger, 0o700)?;
    if ledger.join("transaction").exists() {
        bail!("an interrupted update exists; run yrl-update recover first")
    }
    let mut state = load_state(ledger)?;
    if now < state.time_floor {
        bail!("system time moved behind the trusted update time floor")
    }
    let (a, m, s, d) = bundle_paths(bundle);
    let manifest = crate::release::verify_release(&a, &m, &s, &d, trust, now)?;
    if manifest.number <= state.max {
        bail!("release is not newer than the maximum trusted release")
    }
    if state.data_format < manifest.data_min || state.data_format > manifest.data_max {
        bail!("release is incompatible with persistent data format")
    }
    if manifest.data_target != state.data_format {
        bail!("release requires a persistent-state migration that this updater does not implement")
    }
    if manifest.expires < state.metadata_expiry {
        bail!("release metadata expiry regressed")
    }
    state.time_floor = now;
    state.metadata_expiry = state.metadata_expiry.max(manifest.expires);
    save_state(ledger, &state)?;
    note(audit, "update_prepare", manifest.number, RESULT_OK).await?;
    let stage = root.join(format!(".staging-{:020}", manifest.number));
    if stage.exists() || release_dir(root, manifest.number).exists() {
        bail!("release staging or destination already exists")
    }
    let tx = format!(
        "YRL-UPDATE-TXN-1 {} {} {}\n",
        manifest.number,
        opt(state.current),
        hex::encode(blake3::hash(&fs::read(&m)?).as_bytes())
    );
    atomic(&ledger.join("transaction"), tx.as_bytes())?;
    if let Err(e) = stage_bundle(bundle, &stage, &manifest).and_then(|_| health(&stage, yrl_state))
    {
        let _ = fs::remove_dir_all(&stage);
        let _ = fs::remove_file(ledger.join("transaction"));
        let _ = note(audit, "update_failed", manifest.number, RESULT_ERROR).await;
        return Err(e);
    }
    let final_dir = release_dir(root, manifest.number);
    fs::rename(&stage, &final_dir)?;
    File::open(&root.join("releases"))?.sync_all()?;
    switch(root, Some(manifest.number))?;
    let old = state.current;
    state.previous = old;
    state.current = Some(manifest.number);
    state.max = manifest.number;
    state.data_format = manifest.data_target;
    state.time_floor = state.time_floor.max(now);
    save_state(ledger, &state)?;
    let accepted = health(&final_dir, yrl_state).and_then(|_| Ok(()));
    if let Err(e) = accepted {
        switch(root, old)?;
        state.current = old;
        state.previous = None;
        save_state(ledger, &state)?;
        let _ = note(audit, "update_failed", manifest.number, RESULT_ERROR).await;
        let _ = fs::remove_file(ledger.join("transaction"));
        return Err(e);
    }
    if let Err(e) = note(audit, "update_activate", manifest.number, RESULT_OK).await {
        switch(root, old)?;
        state.current = old;
        state.previous = None;
        save_state(ledger, &state)?;
        let _ = fs::remove_file(ledger.join("transaction"));
        return Err(e);
    }
    fs::remove_file(ledger.join("transaction"))?;
    File::open(ledger)?.sync_all()?;
    Ok(())
}

pub async fn recover(
    trust: &Path,
    root: &Path,
    ledger: &Path,
    yrl_state: &Path,
    now: u64,
    audit: &crate::audit::AuditClient,
) -> Result<()> {
    let tx = fs::read_to_string(ledger.join("transaction"))?;
    let f: Vec<_> = tx.split_whitespace().collect();
    if f.len() != 4 || f[0] != "YRL-UPDATE-TXN-1" {
        bail!("invalid update transaction")
    };
    let n: u64 = f[1].parse()?;
    let old = unopt(f[2])?;
    let final_dir = release_dir(root, n);
    if !final_dir.exists() {
        let stage = root.join(format!(".staging-{n:020}"));
        if !stage.exists() {
            bail!("interrupted update has neither staged nor published release")
        }
        let meta = stage.join("metadata");
        let manifest = crate::release::verify_release(
            &stage.join("artifacts"),
            &meta.join("manifest.txt"),
            &meta.join("manifest.sig"),
            &meta.join("delegation.txt"),
            trust,
            now,
        );
        match manifest {
            Ok(_)
                if hex::encode(blake3::hash(&fs::read(meta.join("manifest.txt"))?).as_bytes())
                    == f[3] =>
            {
                health(&stage, yrl_state)?;
                fs::rename(&stage, &final_dir)?;
                File::open(&root.join("releases"))?.sync_all()?;
            }
            _ => {
                let quarantine = root.join(format!(".failed-{n:020}-{}", std::process::id()));
                fs::rename(&stage, quarantine)?;
                fs::remove_file(ledger.join("transaction"))?;
                note(audit, "update_failed", n, RESULT_ERROR).await?;
                bail!("incomplete staged release was quarantined")
            }
        }
    }
    let manifest = verify_installed(root, n, trust, now)?;
    if hex::encode(blake3::hash(&fs::read(final_dir.join("metadata/manifest.txt"))?).as_bytes())
        != f[3]
    {
        bail!("published manifest differs from transaction")
    }
    health(&final_dir, yrl_state)?;
    switch(root, Some(n))?;
    let mut state = load_state(ledger)?;
    state.max = state.max.max(n);
    state.current = Some(n);
    state.previous = old;
    state.time_floor = state.time_floor.max(now);
    state.metadata_expiry = state.metadata_expiry.max(manifest.expires);
    save_state(ledger, &state)?;
    note(audit, "update_activate", n, RESULT_OK).await?;
    fs::remove_file(ledger.join("transaction"))?;
    Ok(())
}

pub async fn rollback(
    trust: &Path,
    root: &Path,
    ledger: &Path,
    yrl_state: &Path,
    audit: &crate::audit::AuditClient,
) -> Result<()> {
    let mut state = load_state(ledger)?;
    let target = state
        .previous
        .context("no pre-authorized rollback release")?;
    let dir = release_dir(root, target);
    verify_rollback(root, target, trust)?;
    health(&dir, yrl_state)?;
    note(audit, "update_rollback", target, RESULT_OK).await?;
    switch(root, Some(target))?;
    state.current = Some(target);
    state.previous = None;
    save_state(ledger, &state)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r66_rollback_pointer_never_lowers_the_trusted_high_water_mark() {
        let state = State {
            max: 9,
            current: Some(8),
            previous: None,
            time_floor: 100,
            data_format: 1,
            metadata_expiry: 200,
        };
        let decoded = State::parse(&state.encode()).unwrap();
        assert_eq!(decoded.max, 9);
        assert_eq!(decoded.current, Some(8));
    }

    #[test]
    fn r66_activation_switches_one_release_directory_pointer() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("releases")).unwrap();
        switch(d.path(), Some(17)).unwrap();
        assert_eq!(
            fs::read_link(d.path().join("current")).unwrap(),
            PathBuf::from("releases/00000000000000000017/artifacts")
        );
    }

    #[test]
    fn r66_update_ledger_refuses_symlinks() {
        let d = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("missing", d.path().join("state")).unwrap();
        assert!(load_state(d.path()).is_err());
    }
}
