//! Offline Audit verification and authenticated, non-blocking snapshot export.
use crate::auditlog::{Journal, Record, MAX_RECORD};
use crate::auditsegments::{self, TrustAnchor};
use anyhow::{bail, Context, Result};
use crate::auditsign::{Public, Purpose, Verify};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Full,
    Partial,
    Damaged,
    Unverifiable,
}

pub fn verify(dir: &Path, anchor: Option<&TrustAnchor>) -> (Outcome, String) {
    if crate::auditlog::load_verifying_key(dir).is_err() {
        return (
            Outcome::Unverifiable,
            "public verification key is unavailable or invalid".into(),
        );
    }
    match auditsegments::verify_chain(dir, anchor) {
        Ok(r) if r.deleted == 0 && r.revoked_key_segments == 0 => (Outcome::Full, format!("complete: {} archives and {} active records verify", r.archived, r.active_records)),
        Ok(r) => (Outcome::Partial, format!("partial: {} retained archives, {} witnessed deletions, {} revoked-key segments and {} active records verify", r.archived, r.deleted, r.revoked_key_segments, r.active_records)),
        Err(e) => (Outcome::Damaged, format!("damaged: {e}")),
    }
}

fn json(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn records(bytes: &[u8]) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        if at + 4 > bytes.len() {
            bail!("cut Audit frame");
        }
        let n = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        if n < 64 || n > MAX_RECORD || at + 4 + n > bytes.len() {
            bail!("invalid Audit frame");
        }
        out.push(Record::parse(&bytes[at + 4..at + 4 + n - 64])?);
        at += 4 + n;
    }
    Ok(out)
}

fn copy_snapshot(source: &Path, stage: &Path) -> Result<()> {
    fs::create_dir(stage)?;
    fs::set_permissions(stage, fs::Permissions::from_mode(0o700))?;
    let out = stage.join("audit");
    fs::create_dir(&out)?;
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700))?;
    fn copy_dir(
        src: &Path,
        dst: &Path,
        count: &mut usize,
        total: &mut u64,
        depth: usize,
    ) -> Result<()> {
        if depth > 3 {
            bail!("Audit export directory depth exceeded");
        }
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_text = name.to_string_lossy();
            if matches!(name_text.as_ref(), "sign.key" | "lock" | "audit.sock")
                || name_text.ends_with(".pending")
                || name_text.contains(".tmp-")
            {
                continue;
            }
            let meta = fs::symlink_metadata(entry.path())?;
            if meta.is_dir() {
                let child = dst.join(&name);
                fs::create_dir(&child)?;
                fs::set_permissions(&child, fs::Permissions::from_mode(0o700))?;
                copy_dir(&entry.path(), &child, count, total, depth + 1)?;
                continue;
            }
            if !meta.is_file() || meta.nlink() != 1 {
                bail!("unsafe Audit export source {}", entry.path().display());
            }
            *count += 1;
            *total = total
                .checked_add(meta.len())
                .context("Audit export size overflow")?;
            if *count > 4096 || *total > 8 << 30 {
                bail!("Audit export limit exceeded");
            }
            let bytes = fs::read(entry.path())?;
            if bytes.len() as u64 != meta.len() {
                bail!("Audit file changed during export");
            }
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(dst.join(name))?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        Ok(())
    }
    let (mut count, mut total) = (0usize, 0u64);
    copy_dir(&source.join("audit"), &out, &mut count, &mut total, 0)?;
    File::open(&out)?.sync_all()?;
    Ok(())
}

fn write_ndjson(stage: &Path) -> Result<()> {
    let mut paths: Vec<_> = fs::read_dir(stage.join("audit"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension().is_some_and(|x| x == "log")
                && p.file_name().is_some_and(|x| x != "deletions.log")
        })
        .collect();
    paths.sort();
    let mut out = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(stage.join("events.ndjson"))?;
    for path in paths {
        let journal = if path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("ordinary")
        {
            Journal::Ordinary
        } else {
            Journal::Security
        };
        for r in records(&fs::read(&path)?)? {
            writeln!(out, "{{\"journal\":{},\"segment\":{},\"seq\":{},\"time\":{},\"kind\":{},\"source\":{},\"user\":{},\"op\":{},\"target_hex\":\"{}\",\"request_id\":{},\"result\":{},\"code\":{}}}", json(journal.file()), json(&path.file_name().unwrap().to_string_lossy()), r.seq, r.time, r.kind, json(r.source.name()), json(&r.ev.user), json(&r.ev.op), hex::encode(r.ev.target), r.ev.request_id, r.ev.result, r.ev.code)?;
        }
    }
    out.sync_all()?;
    Ok(())
}

fn inventory(stage: &Path) -> Result<Vec<(String, u64, [u8; 32])>> {
    fn walk(base: &Path, at: &Path, out: &mut Vec<(String, u64, [u8; 32])>) -> Result<()> {
        for e in fs::read_dir(at)? {
            let e = e?;
            let p = e.path();
            let m = fs::symlink_metadata(&p)?;
            if m.is_dir() {
                walk(base, &p, out)?;
            } else if m.is_file() {
                let rel = p
                    .strip_prefix(base)?
                    .to_str()
                    .context("non-UTF8 export path")?
                    .to_owned();
                if rel != "manifest.txt" && rel != "manifest.auth" {
                    out.push((rel, m.len(), *blake3::hash(&fs::read(&p)?).as_bytes()));
                }
            } else {
                bail!("special file in Audit export");
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(stage, stage, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn manifest(stage: &Path) -> Result<Vec<u8>> {
    let mut text = String::from("YRL-AUDIT-EXPORT-MANIFEST-1\n");
    for (path, size, hash) in inventory(stage)? {
        text.push_str(&format!("{} {} {}\n", size, hex::encode(hash), path));
    }
    Ok(text.into_bytes())
}

pub fn verify_export(dir: &Path) -> Result<()> {
    let manifest = fs::read(dir.join("manifest.txt"))?;
    if manifest != self::manifest(dir)? {
        bail!("Audit export manifest does not match files");
    }
    let auth = fs::read(dir.join("manifest.auth"))?;
    if auth.len() < 4 + 64 {
        bail!("invalid export authentication");
    }
    let n = u32::from_be_bytes(auth[..4].try_into().unwrap()) as usize;
    if n > auth.len() - 4 - 64 {
        bail!("invalid export authentication length");
    }
    let anchor = TrustAnchor::decode(&auth[4..4 + n], None)?;
    let key = Public::decode(&anchor.key, Purpose::Journal, None)?;
    let mut msg = b"yrl-audit-export-v1".to_vec();
    msg.extend_from_slice(blake3::hash(&manifest).as_bytes());
    msg.extend_from_slice(blake3::hash(&auth[4..4 + n]).as_bytes());
    key.verify_bytes(&msg, &auth[4 + n..])
        .context("invalid export manifest signature")?;
    let (outcome, detail) = verify(dir, Some(&anchor));
    if matches!(outcome, Outcome::Damaged | Outcome::Unverifiable) {
        bail!("exported journal does not verify: {detail}");
    }
    Ok(())
}

pub async fn export(
    source: &Path,
    destination: &Path,
    client: &crate::audit::AuditClient,
) -> Result<()> {
    if destination.exists() {
        bail!("Audit export destination already exists");
    }
    for attempt in 0..3u32 {
        let stage =
            destination.with_extension(format!("audit-export-{}-{attempt}", std::process::id()));
        if stage.exists() {
            bail!("Audit export staging path already exists");
        }
        let result = async {
            copy_snapshot(source, &stage)?;
            let (outcome, detail) = verify(&stage, None);
            if matches!(outcome, Outcome::Damaged | Outcome::Unverifiable) {
                bail!("inconsistent live snapshot: {detail}");
            }
            write_ndjson(&stage)?;
            let body = manifest(&stage)?;
            let auth = client
                .sign_export_digest(*blake3::hash(&body).as_bytes())
                .await?;
            auditsegments::atomic_write(&stage.join("manifest.txt"), &body, 0o600)?;
            auditsegments::atomic_write(&stage.join("manifest.auth"), &auth, 0o600)?;
            verify_export(&stage)?;
            fs::rename(&stage, destination)?;
            File::open(
                destination
                    .parent()
                    .context("export destination needs parent")?,
            )?
            .sync_all()?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 2 => {
                let _ = fs::remove_dir_all(&stage);
                let _ = e;
            }
            Err(e) => {
                let _ = fs::remove_dir_all(&stage);
                return Err(e);
            }
        }
    }
    unreachable!()
}
