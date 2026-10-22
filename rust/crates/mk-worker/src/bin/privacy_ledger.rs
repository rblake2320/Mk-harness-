//! Export/replay the external, content-free deletion recovery ledger. Never
//! enables traffic, confirms provider cleanup or certifies backup expiration.
use std::io::Write as _;
use std::path::Path;

use mk_crypto::Digest;
use mk_store::{Store, privacy_ledger};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let operation = args.get(1).map(String::as_str).unwrap_or_default();
    if !matches!(operation, "export" | "replay") {
        anyhow::bail!("expected export or replay");
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut index = 2;
    while index < args.len() {
        let name = args[index].as_str();
        if !seen.insert(name) {
            anyhow::bail!("repeated option");
        }
        if name == "--apply" && operation == "replay" {
            index += 1;
            continue;
        }
        if !(name == "--ledger"
            || (operation == "replay" && matches!(name, "--sha256" | "--not-before")))
            || args
                .get(index + 1)
                .is_none_or(|value| value.starts_with("--"))
        {
            anyhow::bail!("unknown option or missing value");
        }
        index += 2;
    }
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let path = Path::new(arg("--ledger").ok_or_else(|| anyhow::anyhow!("--ledger is required"))?);
    let store = Store::connect(&mk_store::database_url_from_env()?, 1).await?;
    match operation {
        "export" => {
            let raw = privacy_ledger::export(&store).await?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut output = options.open(path)?;
            output.write_all(&raw)?;
            output.sync_all()?;
            println!(
                "{}",
                json!({"sha256":Digest::of(&raw).to_string(),"bytes":raw.len(),"traffic_enabled":false})
            );
        }
        "replay" => {
            let ledger = mk_worker::privacy_recovery::load_pinned(
                path,
                arg("--sha256").ok_or_else(|| anyhow::anyhow!("external --sha256 is required"))?,
                arg("--not-before")
                    .ok_or_else(|| anyhow::anyhow!("external --not-before is required"))?,
            )?;
            let result =
                privacy_ledger::replay(&store, &ledger, args.iter().any(|a| a == "--apply"))
                    .await?;
            println!("{}", serde_json::to_string(&result)?);
            if !result.enforced {
                std::process::exit(1);
            }
        }
        _ => anyhow::bail!(
            "usage: mk-privacy-ledger export|replay --ledger <file> [--sha256 <externally pinned digest> --not-before <UTC> --apply]"
        ),
    }
    Ok(())
}
