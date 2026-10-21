//! `mk-keyctl`: envelope-key operations (contract S6, S10). Runs as the
//! database OWNER identity (migrations role), never as a runtime login.
//!
//!   mk-keyctl status                      versions, current, rows still sealed under other versions
//!   mk-keyctl rotate [note]               new DEK version wrapped by MK_KEK → active; previous → retiring
//!   mk-keyctl reencrypt                   re-seal every row under the current version (resumable)
//!   mk-keyctl retire <version>            retire a version once no row uses it
//!   mk-keyctl fingerprint-status          per table: rows lacking the current fingerprint kid / orphaned
//!                                         (exit 1 if any — do not remove an old MK_FINGERPRINT_KEYS entry)
//!   mk-keyctl fingerprint-rekey           add every configured fingerprint key's tag to every row
//!   mk-keyctl fingerprint-prune <kid>     strip a removed kid's tags; hash columns → current kid
//!
//! Env: MK_DATABASE_URL (owner), MK_MASTER_KEY (fingerprint key / legacy v0),
//! MK_KEK (base64 32 bytes), MK_KEK_ID (default kek-1), MK_LEGACY_SEAL_RETIRED=1
//! once version 0 has no rows (status reports it). MK_FINGERPRINT_KEYS
//! (`kid=base64,...`, first = current; default `m0` = MK_MASTER_KEY).
use mk_crypto::{LEGACY_VERSION, MasterKey};
use mk_store::{Store, keys};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let db = mk_store::database_url_from_env()?;
    let master = MasterKey::from_base64(&std::env::var("MK_MASTER_KEY")?)
        .map_err(|e| anyhow::anyhow!("MK_MASTER_KEY: {e}"))?;
    let store = Store::connect(&db, 4).await?;
    let pool = store.pool();
    let kek = match std::env::var("MK_KEK") {
        Ok(b) if !b.trim().is_empty() => Some(
            mk_crypto::EnvKek::from_base64(
                std::env::var("MK_KEK_ID").unwrap_or_else(|_| "kek-1".into()),
                &b,
            )
            .map_err(|e| anyhow::anyhow!("MK_KEK: {e}"))?,
        ),
        _ => None,
    };
    match args.get(1).map(String::as_str) {
        Some("status") => {
            let ring = keys::keyring_from_env(pool, &master).await?;
            println!(
                "current_version={} loaded_versions={:?}",
                ring.current_version(),
                ring.versions()
            );
            for v in keys::list(pool).await? {
                println!(
                    "version={} status={} kek_id={} created={} by={} {}",
                    v.version, v.status, v.kek_id, v.created_at, v.created_by, v.note
                );
            }
            let mut legacy_rows = 0u64;
            for (table, stale) in keys::stale_counts(pool, &ring, None).await? {
                println!("{table}: rows_not_under_current={stale}");
                legacy_rows += stale;
            }
            if ring.versions().contains(&LEGACY_VERSION) {
                println!(
                    "legacy_version_0_loaded=true (set MK_LEGACY_SEAL_RETIRED=1 after reencrypt reports 0 stale rows)"
                );
            }
            if ring.current_version() == LEGACY_VERSION {
                println!(
                    "WARNING: sealing with the legacy single master key; run `rotate` with MK_KEK set"
                );
            }
            let _ = legacy_rows;
        }
        Some("rotate") => {
            let kek = kek.ok_or_else(|| anyhow::anyhow!("rotate requires MK_KEK"))?;
            let by = std::env::var("USER").unwrap_or_else(|_| "operator".into());
            let v = keys::rotate(pool, &kek, &by, args.get(2).map_or("", String::as_str)).await?;
            println!(
                "rotated: version {v} is active; previous versions are retiring. Run `reencrypt`, then `retire <old>`."
            );
        }
        Some("reencrypt") => {
            let ring = keys::keyring_from_env(pool, &master).await?;
            let rep = keys::reencrypt(pool, &ring, None).await?;
            println!(
                "re-sealed {} rows under version {}; unreadable (foreign/lost key material, left untouched): {}",
                rep.resealed,
                ring.current_version(),
                rep.unreadable
            );
            if rep.unreadable > 0 {
                println!(
                    "WARNING: {} rows cannot be read with the loaded keyring — investigate before retiring any version",
                    rep.unreadable
                );
            }
            for (table, stale) in keys::stale_counts(pool, &ring, None).await? {
                println!("{table}: rows_not_under_current={stale}");
            }
        }
        Some("retire") => {
            let v: i32 = args
                .get(2)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| anyhow::anyhow!("usage: retire <version>"))?;
            let ring = keys::keyring_from_env(pool, &master).await?;
            keys::retire(pool, &ring, v, chrono::Utc::now()).await?;
            println!("retired version {v}");
        }
        Some("fingerprint-status") => {
            let fk = mk_store::fingerprint::FingerprintKeys::from_env(&master)?;
            println!(
                "fingerprint current_kid={} configured={:?}",
                fk.current_kid(),
                fk.kids()
            );
            let mut blocking = 0u64;
            for t in mk_store::fingerprint::status(pool, &fk, None).await? {
                println!(
                    "{}: lacking_current={} orphaned={}",
                    t.table, t.lacking_current, t.orphaned
                );
                blocking += t.lacking_current + t.orphaned;
            }
            if blocking > 0 {
                println!(
                    "NOT SAFE to remove any fingerprint key: run `fingerprint-rekey`; orphaned rows mean a key was removed early — restore it"
                );
                std::process::exit(1);
            }
            println!("all destination rows carry the current kid; older kids may be removed");
        }
        Some("fingerprint-rekey") => {
            let fk = mk_store::fingerprint::FingerprintKeys::from_env(&master)?;
            let ring = keys::keyring_from_env(pool, &master).await?;
            let rep = mk_store::fingerprint::rekey(pool, &ring, &fk, None).await?;
            println!(
                "fingerprint rekey: updated={} unresolved={} (unresolved rows keep blocking key removal)",
                rep.updated, rep.unresolved
            );
            for t in mk_store::fingerprint::status(pool, &fk, None).await? {
                println!(
                    "{}: lacking_current={} orphaned={}",
                    t.table, t.lacking_current, t.orphaned
                );
            }
        }
        Some("fingerprint-prune") => {
            let kid = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: fingerprint-prune <kid>"))?;
            let fk = mk_store::fingerprint::FingerprintKeys::from_env(&master)?;
            let n = mk_store::fingerprint::prune(pool, &fk, kid, None).await?;
            println!(
                "pruned kid {kid}: {n} rows rewritten under {}",
                fk.current_kid()
            );
        }
        _ => {
            eprintln!(
                "usage: mk-keyctl status | rotate [note] | reencrypt | retire <version> | fingerprint-status | fingerprint-rekey | fingerprint-prune <kid>"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}
