//! Reading a password: from the terminal without echo, or from the first line of a pipe. Never from an argument or the environment (both are visible to other programs).
use std::io::{BufRead, IsTerminal, Write};
use std::process::Command;

pub fn read_password(prompt: &str) -> std::io::Result<Vec<u8>> {
    let tty = std::io::stdin().is_terminal();
    if tty {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let _ = Command::new("stty").arg("-echo").status();
    }
    let mut line = String::new();
    let r = std::io::stdin().lock().read_line(&mut line);
    if tty {
        let _ = Command::new("stty").arg("echo").status();
        eprintln!();
    }
    r?;
    Ok(line.trim_end_matches(['\r', '\n']).as_bytes().to_vec())
}
