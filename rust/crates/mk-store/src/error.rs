//! Store errors. Database driver errors are wrapped so callers never see
//! raw SQLSTATE text in problem details.

use mk_domain::TransitionError;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database unavailable")]
    Unavailable(#[source] sqlx::Error),
    #[error("database error")]
    Db(#[source] sqlx::Error),
    /// Deadlock, serialization failure or lock timeout: safe to retry the whole
    /// transaction (it was rolled back).
    #[error("transient database conflict")]
    Transient(#[source] sqlx::Error),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("illegal transition")]
    Transition(#[from] TransitionError),
    #[error("audit error")]
    Audit(#[from] mk_audit::AuditError),
    #[error("contract error")]
    Contract(#[from] mk_contracts::ContractError),
    #[error("crypto error")]
    Crypto,
    #[error("corrupt row: {0}")]
    Corrupt(&'static str),
}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                Self::Conflict("unique violation")
            }
            sqlx::Error::Database(db)
                if matches!(db.code().as_deref(), Some("40P01" | "40001" | "55P03")) =>
            {
                Self::Transient(e)
            }
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => {
                Self::Unavailable(e)
            }
            _ => Self::Db(e),
        }
    }
}

impl StoreError {
    /// The transaction was rolled back for a reason a retry can clear.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }

    /// Stable code for problem details / metrics.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "STORE_UNAVAILABLE",
            Self::Db(_) => "STORE_ERROR",
            Self::Transient(_) => "STORE_TRANSIENT",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::Transition(_) => "ILLEGAL_TRANSITION",
            Self::Audit(_) => "AUDIT_ERROR",
            Self::Contract(_) => "CONTRACT_VIOLATION",
            Self::Crypto => "CRYPTO_ERROR",
            Self::Corrupt(_) => "CORRUPT_ROW",
        }
    }
}
