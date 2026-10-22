//! Bounded filesystem input for the two recovery operator commands.
use std::io::Read as _;
use std::path::Path;

use chrono::{DateTime, Utc};
use mk_store::privacy_ledger::{self, Ledger, MAX_LEDGER_BYTES};

pub fn load_pinned(path: &Path, expected: &str, not_before: &str) -> anyhow::Result<Ledger> {
    let not_before = DateTime::parse_from_rfc3339(not_before)?.with_timezone(&Utc);
    let mut raw = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_LEDGER_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    Ok(privacy_ledger::load(
        &raw,
        expected,
        not_before,
        Utc::now(),
    )?)
}
