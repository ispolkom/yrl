use anyhow::{bail, Context, Result};
use std::path::PathBuf;
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
#[tokio::main]
async fn main() {
    if let Err(e) = run(&std::env::args().collect::<Vec<_>>()).await {
        eprintln!("error: {e}");
        std::process::exit(1)
    }
}
async fn run(a: &[String]) -> Result<()> {
    match a.get(1).map(String::as_str){
Some("apply") if a.len()==7=>{let state=PathBuf::from(&a[6]);let audit=yrl::ipc::audit_client(&state,"owner").context("Audit owner IPC is required for updates")?;yrl::update::apply(&PathBuf::from(&a[2]),&PathBuf::from(&a[3]),&PathBuf::from(&a[4]),&PathBuf::from(&a[5]),&state,now(),&audit).await},
Some("recover") if a.len()==6=>{let state=PathBuf::from(&a[5]);let audit=yrl::ipc::audit_client(&state,"owner").context("Audit owner IPC is required for updates")?;yrl::update::recover(&PathBuf::from(&a[2]),&PathBuf::from(&a[3]),&PathBuf::from(&a[4]),&state,now(),&audit).await},
Some("rollback") if a.len()==6=>{let state=PathBuf::from(&a[5]);let audit=yrl::ipc::audit_client(&state,"owner").context("Audit owner IPC is required for updates")?;yrl::update::rollback(&PathBuf::from(&a[2]),&PathBuf::from(&a[3]),&PathBuf::from(&a[4]),&state,&audit).await},
_=>bail!("usage: yrl-update apply BUNDLE TRUST INSTALL_ROOT LEDGER YRL_STATE | recover TRUST INSTALL_ROOT LEDGER YRL_STATE | rollback TRUST INSTALL_ROOT LEDGER YRL_STATE")}
}
