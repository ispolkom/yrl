//! Per-session cgroup v2 containment for processes started by Executor.
//! The child writes itself to cgroup.procs in pre_exec, before any user code runs.
use anyhow::{anyhow, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;

pub type Attachment = Arc<File>;

pub struct SessionCgroup {
    path: PathBuf,
    procs: Arc<File>,
    kill: File,
    finished: bool,
}

fn root() -> Result<PathBuf> {
    let text = fs::read_to_string("/proc/self/cgroup")?;
    let relative = text.lines().find_map(|l| l.strip_prefix("0::")).ok_or_else(|| anyhow!("unified cgroup v2 is required"))?;
    if !relative.starts_with('/') || relative.split('/').any(|s| s == "..") { return Err(anyhow!("invalid cgroup path")); }
    let mount = Path::new("/sys/fs/cgroup");
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(std::ffi::CString::new("/sys/fs/cgroup")?.as_ptr(), &mut stat) } != 0 || stat.f_type as u64 != 0x6367_7270 {
        return Err(anyhow!("/sys/fs/cgroup is not cgroup v2"));
    }
    Ok(mount.join(relative.trim_start_matches('/')))
}

/// Called at Executor startup when cgroups are required by the installed service.
pub fn verify_delegation() -> Result<()> {
    let root = root()?;
    // A killed process may remain as a zombie briefly; retry removing its old empty cgroup
    // when Executor starts again after a service restart.
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("yrl-session-") && entry.file_type()?.is_dir() {
            let path = entry.path();
            let _ = fs::write(path.join("cgroup.kill"), b"1");
            let _ = fs::remove_dir(path);
        }
    }
    let path = root.join(format!("yrl-probe-{}", std::process::id()));
    fs::create_dir(&path).with_context(|| format!("Executor cgroup is not delegated: {}", path.display()))?;
    fs::remove_dir(&path)?;
    Ok(())
}

impl SessionCgroup {
    pub fn create(session_no: u64) -> Result<Self> {
        let path = root()?.join(format!("yrl-session-{}-{session_no}", std::process::id()));
        fs::create_dir(&path).with_context(|| format!("cannot create session cgroup {}", path.display()))?;
        let opened = (|| -> Result<(Arc<File>, File)> {
            let procs = Arc::new(OpenOptions::new().write(true).open(path.join("cgroup.procs"))?);
            let kill = OpenOptions::new().write(true).open(path.join("cgroup.kill"))?;
            Ok((procs, kill))
        })();
        match opened {
            Ok((procs, kill)) => Ok(Self { path, procs, kill, finished: false }),
            Err(e) => { let _ = fs::remove_dir(&path); Err(e) }
        }
    }

    pub fn attachment(&self) -> Arc<File> { self.procs.clone() }

    pub fn attach(cmd: &mut Command, procs: &Arc<File>) {
        let procs = procs.clone();
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

    pub fn kill(&mut self) -> Result<()> {
        self.kill.write_all(b"1").context("cgroup.kill failed")
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.kill()?;
        for _ in 0..50 {
            if fs::read_to_string(self.path.join("cgroup.events"))?.lines().any(|l| l == "populated 0") {
                match fs::remove_dir(&self.path) {
                    Ok(()) => { self.finished = true; return Ok(()); }
                    Err(e) if e.kind() != std::io::ErrorKind::DirectoryNotEmpty => return Err(e.into()),
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
            let _ = fs::remove_dir(&self.path);
        }
    }
}
