//! Process-wide syscall walls for the five services. Every policy is synchronized to all
//! existing threads and inherited by threads and children created later. Executor retains the
//! syscalls needed to start commands and change to the account uid; Firewall retains exec for nft.
//! Linux only. The list is a DENY list on purpose: a network program needs hundreds of ordinary system calls, and a mistake in an allow list would stop it from working
//! at all; the dangerous ones are few and known.
use anyhow::{bail, Result};

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

fn denied(allow_exec: bool, allow_identity_switch: bool) -> Vec<i64> {
    let mut v = vec![
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_open_by_handle_at,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setgroups,
        libc::SYS_capset,
    ];
    if allow_exec {
        v.retain(|n| *n != libc::SYS_execve && *n != libc::SYS_execveat);
    }
    if allow_identity_switch {
        v.retain(|n| ![
            libc::SYS_setuid, libc::SYS_setgid, libc::SYS_setresuid, libc::SYS_setresgid,
            libc::SYS_setreuid, libc::SYS_setregid, libc::SYS_setgroups,
        ].contains(n));
    }
    v.sort_unstable();
    v.dedup();
    v
}

/// the filter as a list of instructions: wrong architecture -> refuse everything; a listed call -> EPERM; anything else -> allowed
fn program(allow_exec: bool, allow_identity_switch: bool) -> Vec<libc::sock_filter> {
    const LD_ABS_W: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K
    let ret_allow = 0x7fff_0000u32; // SECCOMP_RET_ALLOW
    let ret_eperm = 0x0005_0000u32 | libc::EPERM as u32; // SECCOMP_RET_ERRNO | EPERM
    let ret_kill = 0x0000_0000u32; // SECCOMP_RET_KILL_THREAD
    let ins = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    let mut p = vec![ins(LD_ABS_W, 0, 0, 4), ins(JEQ_K, 1, 0, AUDIT_ARCH), ins(RET_K, 0, 0, ret_kill), ins(LD_ABS_W, 0, 0, 0)];
    for nr in denied(allow_exec, allow_identity_switch) {
        p.push(ins(JEQ_K, 0, 1, nr as u32));
        p.push(ins(RET_K, 0, 0, ret_eperm));
    }
    p.push(ins(RET_K, 0, 0, ret_allow));
    p
}

/// Irreversible for every thread in this process, including Tokio workers started before this
/// call. A per-thread prctl filter would leave those workers unconfined.
pub fn apply() -> Result<()> {
    apply_policy(false, false)
}

/// Executor must spawn commands and switch to the account's uid. The other privileged syscalls
/// stay denied in Executor and are inherited by user processes.
pub fn apply_executor() -> Result<()> {
    apply_policy(true, true)
}

/// Firewall must execute the fixed `nft` program; it has no reason to change identity.
pub fn apply_firewall() -> Result<()> {
    apply_policy(true, false)
}

fn apply_policy(allow_exec: bool, allow_identity_switch: bool) -> Result<()> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            bail!("cannot set no_new_privs: {}", std::io::Error::last_os_error());
        }
        let prog = program(allow_exec, allow_identity_switch);
        let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut libc::sock_filter };
        if libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, libc::SECCOMP_FILTER_FLAG_TSYNC, &fprog as *const libc::sock_fprog) != 0 {
            bail!("cannot synchronize the filter across all threads: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// what the kernel says about this process: (no_new_privs, seccomp mode)
pub fn status() -> (bool, u32) {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(k)).and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(0);
    (get("NoNewPrivs:") == 1, get("Seccomp:"))
}
