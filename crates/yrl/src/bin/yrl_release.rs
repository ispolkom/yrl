use anyhow::{bail, Result};
use std::path::PathBuf;
fn n<T: std::str::FromStr>(s: &str) -> Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    Ok(s.parse()?)
}
fn main() {
    if let Err(e) = run(&std::env::args().collect::<Vec<_>>()) {
        eprintln!("error: {e}");
        std::process::exit(1)
    }
}
fn run(a: &[String]) -> Result<()> {
    match a.get(1).map(String::as_str) {
    #[cfg(feature="hybrid-signatures")]
    Some("hybrid-keygen") if a.len()==6 => {
        let purpose=yrl::hybrid_signature::Purpose::parse(&a[2])?;
        let key=yrl::hybrid_signature::SigningKey::generate_files(&PathBuf::from(&a[4]),&PathBuf::from(&a[5]),purpose,n(&a[3])?)?;
        println!("hybrid key id: {}",hex::encode(key.key_id));
        Ok(())
    },
    #[cfg(feature="hybrid-signatures")]
    Some("hybrid-sign") if a.len()==7 => {
        let purpose=yrl::hybrid_signature::Purpose::parse(&a[2])?;
        let key=yrl::hybrid_signature::SigningKey::load_files(&PathBuf::from(&a[3]),&PathBuf::from(&a[4]),purpose)?;
        let sig=key.sign(&std::fs::read(&a[5])?)?;
        std::fs::write(&a[6],format!("{}\n",hex::encode(sig.encode())))?;
        Ok(())
    },
    #[cfg(feature="hybrid-signatures")]
    Some("hybrid-verify") if a.len()==6 => {
        let purpose=yrl::hybrid_signature::Purpose::parse(&a[2])?;
        let public=yrl::hybrid_signature::PublicKey::load_file(&PathBuf::from(&a[3]),purpose)?;
        let sig=yrl::hybrid_signature::SignatureEnvelope::decode(&hex::decode(std::fs::read_to_string(&a[5])?.trim())?)?;
        public.verify(&std::fs::read(&a[4])?,&sig)?; println!("hybrid Ed25519 + ML-DSA-65 signature verifies"); Ok(())
    },
    Some("keygen") if a.len()==4 => yrl::release::generate_key(&PathBuf::from(&a[2]),&PathBuf::from(&a[3])),
    Some("trust-init") if a.len()==4 => yrl::release::init_trust(&PathBuf::from(&a[2]),&PathBuf::from(&a[3])),
    Some("root-rotate") if a.len()==6 => yrl::release::rotate_root(&PathBuf::from(&a[2]),&PathBuf::from(&a[3]),&PathBuf::from(&a[4]),&PathBuf::from(&a[5])),
    Some("delegate") if a.len()==11 => yrl::release::delegate(&PathBuf::from(&a[2]),&PathBuf::from(&a[3]),&PathBuf::from(&a[4]),n(&a[5])?,n(&a[6])?,n(&a[7])?,n(&a[8])?,n(&a[9])?,&PathBuf::from(&a[10])),
    Some("revoke") if a.len()==7 => yrl::release::revoke_delegate(&PathBuf::from(&a[2]),&PathBuf::from(&a[3]),n(&a[4])?,&PathBuf::from(&a[5]),n(&a[6])?),
    Some("manifest") if a.len()==14 => yrl::release::create_manifest(&PathBuf::from(&a[2]),n(&a[3])?,&a[4],&a[5],&a[6],n(&a[7])?,n(&a[8])?,n(&a[9])?,n(&a[10])?,n(&a[11])?,n(&a[12])?,&PathBuf::from(&a[13])),
    Some("sign") if a.len()==7 => yrl::release::sign_manifest(&PathBuf::from(&a[2]),&PathBuf::from(&a[3]),&PathBuf::from(&a[4]),&PathBuf::from(&a[5]),&PathBuf::from(&a[6])),
    Some("verify") if a.len()==8 => { let m=yrl::release::verify_release(&PathBuf::from(&a[2]),&PathBuf::from(&a[3]),&PathBuf::from(&a[4]),&PathBuf::from(&a[5]),&PathBuf::from(&a[6]),n(&a[7])?)?; println!("release {} {} {}-{} verifies",m.number,m.version,m.platform,m.arch);Ok(()) },
    _=>bail!("usage: yrl-release keygen PRIVATE PUBLIC | trust-init ROOT_PUBLIC TRUST_DIR | root-rotate TRUST_DIR OLD_PRIVATE NEW_PRIVATE NEW_PUBLIC | delegate TRUST ROOT_PRIVATE DELEGATE_PUBLIC GEN VALID_FROM VALID_UNTIL MIN_RELEASE MAX_RELEASE OUT | revoke TRUST ROOT_PRIVATE GEN DELEGATE_PUBLIC AT | manifest ARTIFACTS NUMBER VERSION PLATFORM ARCH DATA_MIN DATA_MAX DATA_TARGET CREATED EXPIRES DELEGATION OUT | sign MANIFEST DELEGATION DELEGATE_PRIVATE SIGNATURE TRUST | verify ARTIFACTS MANIFEST SIGNATURE DELEGATION TRUST NOW")
}
}
