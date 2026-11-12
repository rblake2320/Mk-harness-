//! `mk-audit-anchor` (contract S14): anchor every tenant's audit chain head to an
//! independently protected destination, and verify the live database against
//! every anchor ever written.
//!
//!   mk-audit-anchor anchor            # cron, e.g. hourly; read-only DB identity
//!   mk-audit-anchor verify <path>…    # JSONL file(s) or a directory of .json objects
//!
//! anchor env: MK_ANCHOR_SIGNING_KEY (base64url 32-byte Ed25519 seed — never given to
//! the database or the API), MK_ANCHOR_KEY_ID, MK_ANCHOR_SINK = `file:/path.jsonl` |
//! `s3:https://<bucket>.s3.<region>.amazonaws.com/<prefix>/` (Object Lock bucket;
//! AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN / AWS_REGION),
//! MK_ANCHOR_RETENTION_DAYS (default 800 = the 24-month audit retention + margin).
//! verify env: MK_ANCHOR_PUBLIC_KEYS = `kid=base64url,kid2=…`.
//! Exit status is non-zero on any failure.

use std::io::Write as _;

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mk_store::Store;
use mk_worker::anchor::{self, Anchor, Leaf};
use mk_worker::config::init_tracing;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn env(k: &str) -> anyhow::Result<String> {
    std::env::var(k).map_err(|_| anyhow::anyhow!("{k} is not set"))
}

async fn do_anchor(store: &Store) -> anyhow::Result<()> {
    let seed: [u8; 32] = B64
        .decode(env("MK_ANCHOR_SIGNING_KEY")?.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("MK_ANCHOR_SIGNING_KEY must be 32 bytes"))?;
    let key = SigningKey::from_bytes(&seed);
    let kid = env("MK_ANCHOR_KEY_ID")?;
    let leaves: Vec<Leaf> = anchor::heads(store.pool())
        .await?
        .into_iter()
        .map(|(t, count, last_hash)| Leaf {
            tenant_ref: anchor::tenant_ref(t),
            count,
            last_hash,
        })
        .collect();
    let now = chrono::Utc::now();
    let a = anchor::build(leaves, &kid, &key, now);
    let line = serde_json::to_string(&a)?;
    let sink = env("MK_ANCHOR_SINK")?;
    if let Some(path) = sink.strip_prefix("file:") {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        f.write_all(format!("{line}\n").as_bytes())?;
        f.sync_all()?;
    } else if let Some(endpoint) = sink.strip_prefix("s3:") {
        let days: i64 = std::env::var("MK_ANCHOR_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(800);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        let object = format!(
            "{}-{}.json",
            now.format("%Y%m%dT%H%M%SZ"),
            &a.merkle_root[..16]
        );
        let token = std::env::var("AWS_SESSION_TOKEN").ok();
        anchor::put_s3(
            &client,
            endpoint,
            &object,
            line.as_bytes(),
            now + chrono::Duration::days(days),
            &env("AWS_ACCESS_KEY_ID")?,
            &env("AWS_SECRET_ACCESS_KEY")?,
            token.as_deref(),
            &env("AWS_REGION")?,
            now,
        )
        .await?;
    } else {
        anyhow::bail!("MK_ANCHOR_SINK must be file:<path> or s3:<https endpoint>/<prefix>/");
    }
    tracing::info!(tenants = a.leaves.len(), root = %a.merkle_root, "anchored");
    println!(
        "anchored {} tenant head(s), root {}",
        a.leaves.len(),
        a.merkle_root
    );
    Ok(())
}

fn load(paths: &[String]) -> anyhow::Result<Vec<Anchor>> {
    let mut out = Vec::new();
    for p in paths {
        let meta = std::fs::metadata(p)?;
        let files: Vec<std::path::PathBuf> = if meta.is_dir() {
            let mut v: Vec<_> = std::fs::read_dir(p)?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|x| x.extension().is_some_and(|e| e == "json" || e == "jsonl"))
                .collect();
            v.sort();
            v
        } else {
            vec![p.into()]
        };
        for f in files {
            for (i, line) in std::fs::read_to_string(&f)?
                .lines()
                .enumerate()
                .filter(|(_, l)| !l.trim().is_empty())
            {
                out.push(
                    serde_json::from_str(line)
                        .map_err(|e| anyhow::anyhow!("{}:{}: {e}", f.display(), i + 1))?,
                );
            }
        }
    }
    Ok(out)
}

async fn do_verify(store: &Store, paths: &[String]) -> anyhow::Result<()> {
    let keys: Vec<(String, VerifyingKey)> = env("MK_ANCHOR_PUBLIC_KEYS")?
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|kv| {
            let (k, v) = kv
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("MK_ANCHOR_PUBLIC_KEYS: kid=key"))?;
            let b: [u8; 32] = B64
                .decode(v.trim())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("public key length"))?;
            Ok((k.trim().to_owned(), VerifyingKey::from_bytes(&b)?))
        })
        .collect::<anyhow::Result<_>>()?;
    let anchors = load(paths)?;
    anyhow::ensure!(!anchors.is_empty(), "no anchors found");
    let failures = anchor::verify_against(store.pool(), &anchors, &keys).await?;
    for f in &failures {
        println!("FAIL {f}");
    }
    println!(
        "{} anchor(s) checked, {} failure(s)",
        anchors.len(),
        failures.len()
    );
    anyhow::ensure!(
        failures.is_empty(),
        "anchored audit history does not match the database"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let db = mk_store::database_url_from_env().map_err(|e| anyhow::anyhow!("database url: {e}"))?;
    let store = Store::connect(&db, 2).await?;
    match args.first().map(String::as_str) {
        Some("anchor") => do_anchor(&store).await,
        Some("verify") if args.len() > 1 => do_verify(&store, &args[1..]).await,
        _ => anyhow::bail!("usage: mk-audit-anchor anchor | verify <file-or-dir>…"),
    }
}
