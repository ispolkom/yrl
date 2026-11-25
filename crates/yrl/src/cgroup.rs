//! Per-session cgroup v2 containment for processes started by Executor.
//! The child writes itself to cgroup.procs in pre_exec, before any user code runs.
use anyhow::{anyhow, bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuMax {
    /// None means no hard CPU bandwidth ceiling. Weight still provides fairness between sessions.
    pub quota_micros: Option<u64>,
    pub period_micros: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoLimit {
    pub major: u32,
    pub minor: u32,
    pub read_bytes_per_sec: Option<u64>,
    pub write_bytes_per_sec: Option<u64>,
    pub read_ios_per_sec: Option<u64>,
    pub write_ios_per_sec: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLimits {
    pub memory_max: Option<u64>,
    pub memory_high: Option<u64>,
    pub pids_max: Option<u64>,
    pub cpu_max: CpuMax,
    pub cpu_weight: u16,
    /// Applied when the kernel delegates the IO controller. It is a fair-share weight, not a rate cap.
    pub io_weight: Option<u16>,
    /// Optional explicit limits for block devices. Empty by default: file throughput is not capped.
    pub io_max: Vec<IoLimit>,
}

impl Default for SessionLimits {
    fn default() -> Self {
        SessionLimits {
            memory_max: Some(2 << 30),
            memory_high: Some(1 << 30),
            pids_max: Some(512),
            cpu_max: CpuMax {
                quota_micros: None,
                period_micros: 100_000,
            },
            cpu_weight: 100,
            io_weight: Some(100),
            io_max: vec![],
        }
    }
}

fn parse_size(value: &str) -> Result<Option<u64>> {
    if value == "max" {
        return Ok(None);
    }
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let n: u64 = value[..split]
        .parse()
        .context("resource size is not a number")?;
    let factor = match &value[split..] {
        "" | "B" => 1,
        "K" | "KiB" => 1 << 10,
        "M" | "MiB" => 1 << 20,
        "G" | "GiB" => 1 << 30,
        _ => bail!("resource size has an unsupported suffix"),
    };
    Ok(Some(
        n.checked_mul(factor)
            .ok_or_else(|| anyhow!("resource size overflow"))?,
    ))
}

fn parse_cpu_max(value: &str) -> Result<CpuMax> {
    let fields: Vec<&str> = value.split_ascii_whitespace().collect();
    if fields.len() != 2 {
        bail!("cpu.max must be '<quota|max> <period>'");
    }
    let quota_micros = if fields[0] == "max" {
        None
    } else {
        Some(fields[0].parse()?)
    };
    let period_micros: u64 = fields[1].parse()?;
    if !(1_000..=1_000_000).contains(&period_micros) || quota_micros == Some(0) {
        bail!("invalid cpu.max quota or period");
    }
    Ok(CpuMax {
        quota_micros,
        period_micros,
    })
}

fn parse_count(value: &str) -> Result<Option<u64>> {
    if value == "max" {
        Ok(None)
    } else {
        Ok(Some(value.parse()?))
    }
}

fn parse_io_limit(value: &str) -> Result<IoLimit> {
    let mut fields = value.split_ascii_whitespace();
    let device = fields
        .next()
        .ok_or_else(|| anyhow!("io.max device is missing"))?;
    let (major, minor) = device
        .split_once(':')
        .ok_or_else(|| anyhow!("io.max device must be MAJOR:MINOR"))?;
    let mut limit = IoLimit {
        major: major.parse()?,
        minor: minor.parse()?,
        read_bytes_per_sec: None,
        write_bytes_per_sec: None,
        read_ios_per_sec: None,
        write_ios_per_sec: None,
    };
    let mut any = false;
    for field in fields {
        let (name, value) = field
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid io.max field"))?;
        if value == "max" {
            bail!("omit an unlimited io.max field instead of writing max");
        }
        let n: u64 = value.parse()?;
        if n == 0 {
            bail!("io.max values must be positive");
        }
        let dst = match name {
            "rbps" => &mut limit.read_bytes_per_sec,
            "wbps" => &mut limit.write_bytes_per_sec,
            "riops" => &mut limit.read_ios_per_sec,
            "wiops" => &mut limit.write_ios_per_sec,
            _ => bail!("unknown io.max field"),
        };
        if dst.replace(n).is_some() {
            bail!("duplicate io.max field");
        }
        any = true;
    }
    if !any {
        bail!("io.max needs at least one limit");
    }
    Ok(limit)
}

impl SessionLimits {
    pub fn validate(&self) -> Result<()> {
        if self.memory_max == Some(0) || self.memory_high == Some(0) || self.pids_max == Some(0) {
            bail!("memory and process limits must be positive or max");
        }
        if matches!((self.memory_high, self.memory_max), (Some(high), Some(max)) if high > max) {
            bail!("memory.high cannot exceed memory.max");
        }
        if !(1..=10_000).contains(&self.cpu_weight)
            || self.io_weight.is_some_and(|w| !(1..=10_000).contains(&w))
        {
            bail!("CPU and IO weights must be in 1..=10000");
        }
        if !(1_000..=1_000_000).contains(&self.cpu_max.period_micros)
            || self.cpu_max.quota_micros == Some(0)
        {
            bail!("invalid cpu.max quota or period");
        }
        let mut devices = std::collections::HashSet::new();
        for limit in &self.io_max {
            let values = [
                limit.read_bytes_per_sec,
                limit.write_bytes_per_sec,
                limit.read_ios_per_sec,
                limit.write_ios_per_sec,
            ];
            if values.iter().all(Option::is_none) || values.iter().any(|n| *n == Some(0)) {
                bail!("each io.max device needs at least one positive limit");
            }
            if !devices.insert((limit.major, limit.minor)) {
                bail!("duplicate io.max device");
            }
        }
        Ok(())
    }

    /// Installed services read optional overrides from `/etc/yrl/yrl.env` through systemd.
    pub fn from_env() -> Result<Self> {
        let mut limits = SessionLimits::default();
        if let Ok(v) = std::env::var("YRL_SESSION_MEMORY_MAX") {
            limits.memory_max = parse_size(&v)?;
        }
        if let Ok(v) = std::env::var("YRL_SESSION_MEMORY_HIGH") {
            limits.memory_high = parse_size(&v)?;
        }
        if let Ok(v) = std::env::var("YRL_SESSION_PIDS_MAX") {
            limits.pids_max = parse_count(&v)?;
        }
        if let Ok(v) = std::env::var("YRL_SESSION_CPU_MAX") {
            limits.cpu_max = parse_cpu_max(&v)?;
        }
        if let Ok(v) = std::env::var("YRL_SESSION_CPU_WEIGHT") {
            limits.cpu_weight = v.parse()?;
        }
        if let Ok(v) = std::env::var("YRL_SESSION_IO_WEIGHT") {
            limits.io_weight = if v == "none" { None } else { Some(v.parse()?) };
        }
        if let Ok(v) = std::env::var("YRL_SESSION_IO_MAX") {
            limits.io_max = v
                .split(';')
                .filter(|s| !s.trim().is_empty())
                .map(|s| parse_io_limit(s.trim()))
                .collect::<Result<Vec<_>>>()?;
        }
        limits.validate()?;
        Ok(limits)
    }
}

#[derive(Clone)]
pub struct Attachment {
    procs: Arc<File>,
    path: Arc<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Events {
    pub oom: u64,
    pub oom_kill: u64,
    pub pids_max: u64,
}

impl Attachment {
    pub fn events(&self) -> Events {
        read_events(&self.path)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub struct SessionCgroup {
    path: Arc<PathBuf>,
    procs: Arc<File>,
    kill: File,
    finished: bool,
}

fn root() -> Result<PathBuf> {
    let text = fs::read_to_string("/proc/self/cgroup")?;
    let relative = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| anyhow!("unified cgroup v2 is required"))?;
    if !relative.starts_with('/') || relative.split('/').any(|s| s == "..") {
        return Err(anyhow!("invalid cgroup path"));
    }
    let mount = Path::new("/sys/fs/cgroup");
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statfs(
            std::ffi::CString::new("/sys/fs/cgroup")?.as_ptr(),
            &mut stat,
        )
    } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(anyhow!("/sys/fs/cgroup is not cgroup v2"));
    }
    Ok(mount.join(relative.trim_start_matches('/')))
}

fn value(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "max".into())
}

fn io_line(limit: &IoLimit) -> String {
    let mut line = format!("{}:{}", limit.major, limit.minor);
    for (name, n) in [
        ("rbps", limit.read_bytes_per_sec),
        ("wbps", limit.write_bytes_per_sec),
        ("riops", limit.read_ios_per_sec),
        ("wiops", limit.write_ios_per_sec),
    ] {
        if let Some(n) = n {
            line.push_str(&format!(" {name}={n}"));
        }
    }
    line
}

fn write_control(path: &Path, name: &str, value: &str) -> Result<()> {
    fs::write(path.join(name), value).with_context(|| format!("cannot set {name}={value}"))
}

fn apply_limits(path: &Path, limits: &SessionLimits) -> Result<()> {
    limits.validate()?;
    write_control(path, "memory.max", &value(limits.memory_max))?;
    write_control(path, "memory.high", &value(limits.memory_high))?;
    write_control(path, "memory.oom.group", "1")?;
    write_control(path, "pids.max", &value(limits.pids_max))?;
    let quota = limits
        .cpu_max
        .quota_micros
        .map(|n| n.to_string())
        .unwrap_or_else(|| "max".into());
    write_control(
        path,
        "cpu.max",
        &format!("{quota} {}", limits.cpu_max.period_micros),
    )?;
    write_control(path, "cpu.weight", &limits.cpu_weight.to_string())?;
    if let Some(weight) = limits.io_weight {
        if path.join("io.weight").exists() {
            write_control(path, "io.weight", &format!("default {weight}"))?;
        }
    }
    if !limits.io_max.is_empty() {
        if !path.join("io.max").exists() {
            bail!("io.max was requested but the IO controller is not delegated");
        }
        for limit in &limits.io_max {
            write_control(path, "io.max", &io_line(limit))?;
        }
    }
    Ok(())
}

fn event_value(path: &Path, file: &str, name: &str) -> u64 {
    fs::read_to_string(path.join(file))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let (key, value) = line.split_once(' ')?;
                (key == name).then(|| value.parse().ok()).flatten()
            })
        })
        .unwrap_or(0)
}

fn read_events(path: &Path) -> Events {
    Events {
        oom: event_value(path, "memory.events", "oom"),
        oom_kill: event_value(path, "memory.events", "oom_kill"),
        pids_max: event_value(path, "pids.events", "max"),
    }
}

/// Called at Executor startup when cgroups are required by the installed service.
pub fn verify_delegation() -> Result<()> {
    verify_delegation_with(&SessionLimits::default())
}

pub fn verify_delegation_with(limits: &SessionLimits) -> Result<()> {
    let root = root()?;
    // A killed process may remain as a zombie briefly; retry removing its old empty cgroup
    // when Executor starts again after a service restart.
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("yrl-session-")
            && entry.file_type()?.is_dir()
        {
            let path = entry.path();
            let _ = fs::write(path.join("cgroup.kill"), b"1");
            let _ = fs::remove_dir(path);
        }
    }
    let path = root.join(format!("yrl-probe-{}", std::process::id()));
    fs::create_dir(&path)
        .with_context(|| format!("Executor cgroup is not delegated: {}", path.display()))?;
    let result = apply_limits(&path, limits);
    let _ = fs::remove_dir(&path);
    result
}

impl SessionCgroup {
    pub fn create(session_no: u64, limits: &SessionLimits) -> Result<Self> {
        let path = root()?.join(format!("yrl-session-{}-{session_no}", std::process::id()));
        fs::create_dir(&path)
            .with_context(|| format!("cannot create session cgroup {}", path.display()))?;
        let opened = (|| -> Result<(Arc<File>, File)> {
            apply_limits(&path, limits)?;
            let procs = Arc::new(
                OpenOptions::new()
                    .write(true)
                    .open(path.join("cgroup.procs"))?,
            );
            let kill = OpenOptions::new()
                .write(true)
                .open(path.join("cgroup.kill"))?;
            Ok((procs, kill))
        })();
        match opened {
            Ok((procs, kill)) => Ok(Self {
                path: Arc::new(path),
                procs,
                kill,
                finished: false,
            }),
            Err(e) => {
                let _ = fs::remove_dir(&path);
                Err(e)
            }
        }
    }

    pub fn attachment(&self) -> Attachment {
        Attachment {
            procs: self.procs.clone(),
            path: self.path.clone(),
        }
    }
    pub fn events(&self) -> Events {
        read_events(&self.path)
    }

    pub fn attach(cmd: &mut Command, attachment: &Attachment) {
        let procs = attachment.procs.clone();
        unsafe {
            cmd.pre_exec(move || {
                // Writing zero moves the calling child, before exec, into this session's cgroup.
                // A failed move aborts spawn; it never runs user code outside the cgroup.
                if libc::write(procs.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    pub fn spawn_error(error: &std::io::Error) -> &'static str {
        match error.raw_os_error() {
            Some(libc::EAGAIN) => "session process limit reached",
            Some(libc::ENOMEM) => "session memory limit reached",
            _ => "cannot start the program",
        }
    }

    pub fn kill(&mut self) -> Result<()> {
        self.kill.write_all(b"1").context("cgroup.kill failed")
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.kill()?;
        for _ in 0..50 {
            if fs::read_to_string(self.path.join("cgroup.events"))?
                .lines()
                .any(|l| l == "populated 0")
            {
                match fs::remove_dir(&*self.path) {
                    Ok(()) => {
                        self.finished = true;
                        return Ok(());
                    }
                    Err(e) if e.kind() != std::io::ErrorKind::DirectoryNotEmpty => {
                        return Err(e.into())
                    }
                    Err(_) => {}
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        Err(anyhow!("session cgroup did not empty within one second"))
    }
}

impl Drop for SessionCgroup {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.kill();
            let _ = fs::remove_dir(&*self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controls(path: &Path) {
        for name in [
            "memory.max",
            "memory.high",
            "memory.oom.group",
            "pids.max",
            "cpu.max",
            "cpu.weight",
            "io.weight",
            "io.max",
        ] {
            fs::write(path.join(name), "").unwrap();
        }
    }

    #[test]
    fn limits_are_validated_and_written_without_an_implicit_bandwidth_cap() {
        let dir = tempfile::tempdir().unwrap();
        controls(dir.path());
        let limits = SessionLimits::default();
        apply_limits(dir.path(), &limits).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("memory.max")).unwrap(),
            (2u64 << 30).to_string()
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("memory.high")).unwrap(),
            (1u64 << 30).to_string()
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("pids.max")).unwrap(),
            "512"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("memory.oom.group")).unwrap(),
            "1"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("cpu.max")).unwrap(),
            "max 100000"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("io.max")).unwrap(),
            "",
            "default file throughput is not rate-limited"
        );
    }

    #[test]
    fn explicit_io_limits_and_event_counters_are_typed() {
        let dir = tempfile::tempdir().unwrap();
        controls(dir.path());
        let mut limits = SessionLimits::default();
        limits.io_max = vec![parse_io_limit("8:0 rbps=1048576 wiops=20").unwrap()];
        apply_limits(dir.path(), &limits).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("io.max")).unwrap(),
            "8:0 rbps=1048576 wiops=20"
        );
        fs::write(
            dir.path().join("memory.events"),
            "low 0\noom 2\noom_kill 1\n",
        )
        .unwrap();
        fs::write(dir.path().join("pids.events"), "max 3\n").unwrap();
        assert_eq!(
            read_events(dir.path()),
            Events {
                oom: 2,
                oom_kill: 1,
                pids_max: 3
            }
        );
    }

    #[test]
    fn explicit_memory_process_cpu_and_io_controls_are_applied_together() {
        let dir = tempfile::tempdir().unwrap();
        controls(dir.path());
        let limits = SessionLimits {
            memory_max: Some(768 << 20),
            memory_high: Some(512 << 20),
            pids_max: Some(96),
            cpu_max: parse_cpu_max("150000 100000").unwrap(),
            cpu_weight: 250,
            io_weight: Some(300),
            io_max: vec![],
        };
        apply_limits(dir.path(), &limits).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("memory.max")).unwrap(),
            (768u64 << 20).to_string()
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("memory.high")).unwrap(),
            (512u64 << 20).to_string()
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("pids.max")).unwrap(),
            "96"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("cpu.max")).unwrap(),
            "150000 100000"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("cpu.weight")).unwrap(),
            "250"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("io.weight")).unwrap(),
            "default 300"
        );
        assert_eq!(
            SessionCgroup::spawn_error(&std::io::Error::from_raw_os_error(libc::EAGAIN)),
            "session process limit reached"
        );
        assert_eq!(
            SessionCgroup::spawn_error(&std::io::Error::from_raw_os_error(libc::ENOMEM)),
            "session memory limit reached"
        );
    }
}
