//! Connection pool and tenant-scoped transactions.

use mk_domain::TenantId;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Transaction};
use std::str::FromStr;
use std::time::Duration;

use crate::error::StoreError;

#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Connect with bounded pool and statement timeouts. Readiness fails if
    /// this cannot be established.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let opts = PgConnectOptions::from_str(url)
            .map_err(StoreError::Unavailable)?
            .application_name("mk-action-kernel")
            .options([("statement_timeout", "15000"), ("lock_timeout", "5000")]);
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await
            .map_err(StoreError::Unavailable)?;
        Ok(Self { pool })
    }

    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        crate::migrator()
            .run(&self.pool)
            .await
            .map_err(|e| StoreError::Db(sqlx::Error::Migrate(Box::new(e))))
    }

    /// Liveness/readiness probe: a round trip that must complete quickly.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Begin a transaction scoped to one tenant. Every query inside is also
    /// filtered by RLS on `kernel.tenant_id`.
    pub async fn begin(&self, tenant: TenantId) -> Result<TenantTx<'_>, StoreError> {
        self.begin_scoped(tenant, false).await
    }

    /// Erasure excludes all ordinary tenant transactions, before either side
    /// acquires row, control-path or audit locks. Never upgrade a shared lock.
    pub async fn begin_erasure(&self, tenant: TenantId) -> Result<TenantTx<'_>, StoreError> {
        self.begin_scoped(tenant, true).await
    }

    async fn begin_scoped(
        &self,
        tenant: TenantId,
        erasure: bool,
    ) -> Result<TenantTx<'_>, StoreError> {
        let mut tx = self.pool.begin().await?;
        // SET LOCAL cannot take a bind parameter; the value is a validated UUID.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SET LOCAL kernel.tenant_id = '{}'",
            tenant.0
        )))
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT kernel.privacy_tenant_lock($1,$2)")
            .bind(tenant.0)
            .bind(erasure)
            .execute(&mut *tx)
            .await?;
        Ok(TenantTx {
            tx,
            tenant,
            erasure,
        })
    }
}

/// A transaction bound to one tenant. Dropping without `commit` rolls back.
#[derive(Debug)]
pub struct TenantTx<'a> {
    pub(crate) tx: Transaction<'a, Postgres>,
    pub(crate) tenant: TenantId,
    pub(crate) erasure: bool,
}

impl TenantTx<'_> {
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub async fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> Result<(), StoreError> {
        self.tx.rollback().await?;
        Ok(())
    }

    pub(crate) fn conn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }

    /// Raw connection for test harnesses and migrations tooling. Production
    /// code paths use the repository modules, which keep tenant predicates.
    #[doc(hidden)]
    pub fn raw_conn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }

    /// Guard used by every repository: the caller's tenant must match the
    /// transaction's tenant. This is the application-level half of tenant
    /// isolation; RLS is the database half.
    pub(crate) fn assert_tenant(&self, tenant: TenantId) -> Result<(), StoreError> {
        if tenant == self.tenant {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }
}
