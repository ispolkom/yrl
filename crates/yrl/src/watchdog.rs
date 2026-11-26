//! Minimal systemd readiness/watchdog notification without adding a service dependency.
use std::os::unix::ffi::OsStrExt;

pub fn start() {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    if std::env::var("WATCHDOG_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|p| p != std::process::id())
    {
        return;
    }
    let usec = std::env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let bytes = socket.as_bytes().to_vec();
    let _ = notify(&bytes, b"READY=1");
    if let Some(usec) = usec.filter(|n| *n >= 1_000_000) {
        tokio::spawn(async move {
            let every = std::time::Duration::from_micros((usec / 3).max(250_000));
            loop {
                tokio::time::sleep(every).await;
                let _ = notify(&bytes, b"WATCHDOG=1");
            }
        });
    }
}

fn notify(name: &[u8], message: &[u8]) -> std::io::Result<()> {
    if name.is_empty() || name.len() >= 108 {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let abstract_name = name[0] == b'@';
        let src = if abstract_name { &name[1..] } else { name };
        let start = if abstract_name { 1 } else { 0 };
        for (i, b) in src.iter().enumerate() {
            addr.sun_path[start + i] = *b as libc::c_char;
        }
        let path_len = start + src.len() + usize::from(!abstract_name);
        let addr_len = (std::mem::size_of::<libc::sa_family_t>() + path_len) as libc::socklen_t;
        let sent = libc::sendto(
            fd,
            message.as_ptr().cast(),
            message.len(),
            libc::MSG_NOSIGNAL,
            (&addr as *const libc::sockaddr_un).cast(),
            addr_len,
        );
        let error = if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        };
        libc::close(fd);
        error
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pathname_and_abstract_names_are_bounded_before_syscall() {
        assert!(super::notify(&[], b"x").is_err());
        assert!(super::notify(&vec![b'x'; 108], b"x").is_err());
    }
}
