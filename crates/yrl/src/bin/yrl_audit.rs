use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use yrl::auditexport::Outcome;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = run(&args).await;
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(64);
        }
    }
}

async fn run(a: &[String]) -> Result<i32> {
    match a.get(1).map(String::as_str) {
        Some("verify") if a.len() == 3 || a.len() == 4 => {
            let dir = PathBuf::from(&a[2]);
            if dir.join("manifest.txt").exists() {
                if let Err(e) = yrl::auditexport::verify_export(&dir) {
                    println!("damaged export: {e}");
                    return Ok(3);
                }
            }
            let key = yrl::auditlog::load_verifying_key(&dir).ok();
            let anchor = match a.get(3) { Some(p) => Some(yrl::auditsegments::TrustAnchor::decode(&std::fs::read(p)?, key.as_ref())?), None => None };
            let (outcome, detail) = yrl::auditexport::verify(&dir, anchor.as_ref());
            println!("{detail}");
            Ok(match outcome { Outcome::Full => 0, Outcome::Partial => 2, Outcome::Damaged => 3, Outcome::Unverifiable => 4 })
        }
        Some("export") if a.len() == 4 => {
            let source = PathBuf::from(&a[2]);
            let client = yrl::ipc::audit_client(&source, "owner").context("Audit owner IPC is not configured")?;
            yrl::auditexport::export(&source, &PathBuf::from(&a[3]), &client).await?;
            println!("authenticated Audit export created"); Ok(0)
        }
        _ => bail!("usage: yrl-audit verify <state-or-export-dir> [trusted-anchor] | export <state-dir> <new-export-dir>"),
    }
}
