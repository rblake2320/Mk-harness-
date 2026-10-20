//! Redis Streams transport. Streams are sharded by tenant so a noisy tenant
//! cannot starve others, and every message carries `tenant_id` and
//! `action_id` only — never payload PII.

use mk_domain::{ActionId, TenantId};
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, Value};
use serde::{Deserialize, Serialize};

pub const CONSUMER_GROUP: &str = "mk-workers";
pub const SHARDS: u8 = 16;
/// Trim streams to this many entries (approximate) to bound memory; acked
/// and unacked alike — the outbox is the durable record.
const MAXLEN: usize = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("redis unavailable")]
    Unavailable(#[source] redis::RedisError),
    #[error("redis error")]
    Redis(#[source] redis::RedisError),
    #[error("malformed message")]
    Malformed,
}

impl From<redis::RedisError> for StreamError {
    fn from(e: redis::RedisError) -> Self {
        if e.is_connection_refusal() || e.is_io_error() || e.is_timeout() {
            Self::Unavailable(e)
        } else {
            Self::Redis(e)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchMessage {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub outbox_id: i64,
    pub event_kind: String,
}

/// A delivered message with the stream id needed to ack it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub stream: String,
    pub id: String,
    pub message: DispatchMessage,
    /// How many times Redis has delivered this entry (1 = first time).
    pub delivery_count: u64,
}

#[derive(Clone)]
pub struct StreamClient {
    conn: MultiplexedConnection,
    prefix: String,
}

impl std::fmt::Debug for StreamClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StreamClient(prefix={})", self.prefix)
    }
}

#[must_use]
pub fn shard_for(tenant: TenantId) -> u8 {
    tenant.0.as_bytes()[15] % SHARDS
}

impl StreamClient {
    pub async fn connect(url: &str, prefix: &str) -> Result<Self, StreamError> {
        let client = redis::Client::open(url).map_err(StreamError::Unavailable)?;
        let conn = client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(StreamError::Unavailable)?;
        Ok(Self {
            conn,
            prefix: prefix.to_owned(),
        })
    }

    #[must_use]
    pub fn stream_name(&self, shard: u8) -> String {
        format!("{}:dispatch:{shard:02}", self.prefix)
    }

    /// Create the consumer group on every shard (idempotent).
    pub async fn ensure_groups(&self) -> Result<(), StreamError> {
        let mut c = self.conn.clone();
        for shard in 0..SHARDS {
            let name = self.stream_name(shard);
            let r: Result<Value, redis::RedisError> = redis::cmd("XGROUP")
                .arg("CREATE")
                .arg(&name)
                .arg(CONSUMER_GROUP)
                .arg("$")
                .arg("MKSTREAM")
                .query_async(&mut c)
                .await;
            match r {
                Ok(_) => {}
                Err(e) if e.code() == Some("BUSYGROUP") => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    pub async fn ping(&self) -> Result<(), StreamError> {
        let mut c = self.conn.clone();
        let _: String = redis::cmd("PING").query_async(&mut c).await?;
        Ok(())
    }

    /// Append a dispatch message. Returns the stream entry id.
    pub async fn publish(&self, m: &DispatchMessage) -> Result<String, StreamError> {
        let mut c = self.conn.clone();
        let name = self.stream_name(shard_for(m.tenant_id));
        let id: String = redis::cmd("XADD")
            .arg(&name)
            .arg("MAXLEN")
            .arg("~")
            .arg(MAXLEN)
            .arg("*")
            .arg("tenant_id")
            .arg(m.tenant_id.to_string())
            .arg("action_id")
            .arg(m.action_id.to_string())
            .arg("outbox_id")
            .arg(m.outbox_id)
            .arg("event_kind")
            .arg(&m.event_kind)
            .query_async(&mut c)
            .await?;
        Ok(id)
    }

    /// Read new messages for this consumer across all shards, blocking up to
    /// `block_ms`. Then reclaim entries another consumer left pending for
    /// longer than `min_idle_ms` (worker death recovery).
    pub async fn read(
        &self,
        consumer: &str,
        count: usize,
        block_ms: u64,
        min_idle_ms: u64,
    ) -> Result<Vec<Delivery>, StreamError> {
        let mut out = Vec::new();
        let mut c = self.conn.clone();
        let names: Vec<String> = (0..SHARDS).map(|s| self.stream_name(s)).collect();
        let mut cmd = redis::cmd("XREADGROUP");
        cmd.arg("GROUP")
            .arg(CONSUMER_GROUP)
            .arg(consumer)
            .arg("COUNT")
            .arg(count)
            .arg("BLOCK")
            .arg(block_ms)
            .arg("STREAMS");
        for n in &names {
            cmd.arg(n);
        }
        for _ in &names {
            cmd.arg(">");
        }
        let v: Value = cmd.query_async(&mut c).await?;
        parse_xread(&v, &mut out)?;
        // Reclaim stale pending entries (round-robin shards is unnecessary at
        // this scale: scan all).
        for n in &names {
            let v: Value = redis::cmd("XAUTOCLAIM")
                .arg(n)
                .arg(CONSUMER_GROUP)
                .arg(consumer)
                .arg(min_idle_ms)
                .arg("0-0")
                .arg("COUNT")
                .arg(count)
                .query_async(&mut c)
                .await?;
            // XAUTOCLAIM returns [next-id, [entries...], [deleted-ids]]
            if let Value::Array(parts) = v
                && let Some(entries) = parts.get(1)
            {
                parse_entries(n, entries, &mut out, 2)?;
            }
        }
        Ok(out)
    }

    pub async fn ack(&self, stream: &str, id: &str) -> Result<(), StreamError> {
        let mut c = self.conn.clone();
        let _: i64 = c.xack(stream, CONSUMER_GROUP, &[id]).await?;
        Ok(())
    }

    /// Pending (delivered, unacked) count across shards, for metrics.
    pub async fn pending_total(&self) -> Result<u64, StreamError> {
        let mut c = self.conn.clone();
        let mut total = 0u64;
        for shard in 0..SHARDS {
            let v: Value = redis::cmd("XPENDING")
                .arg(self.stream_name(shard))
                .arg(CONSUMER_GROUP)
                .query_async(&mut c)
                .await?;
            if let Value::Array(parts) = v
                && let Some(Value::Int(n)) = parts.first()
            {
                total += u64::try_from(*n).unwrap_or(0);
            }
        }
        Ok(total)
    }
}

fn parse_xread(v: &Value, out: &mut Vec<Delivery>) -> Result<(), StreamError> {
    match v {
        Value::Nil => Ok(()),
        Value::Array(streams) => {
            for s in streams {
                if let Value::Array(pair) = s {
                    let name = match pair.first() {
                        Some(Value::BulkString(b)) => String::from_utf8_lossy(b).into_owned(),
                        Some(Value::SimpleString(s)) => s.clone(),
                        _ => return Err(StreamError::Malformed),
                    };
                    if let Some(entries) = pair.get(1) {
                        parse_entries(&name, entries, out, 1)?;
                    }
                }
            }
            Ok(())
        }
        Value::Map(m) => {
            for (k, entries) in m {
                let name = match k {
                    Value::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
                    Value::SimpleString(s) => s.clone(),
                    _ => return Err(StreamError::Malformed),
                };
                parse_entries(&name, entries, out, 1)?;
            }
            Ok(())
        }
        _ => Err(StreamError::Malformed),
    }
}

fn parse_entries(
    stream: &str,
    entries: &Value,
    out: &mut Vec<Delivery>,
    delivery_count: u64,
) -> Result<(), StreamError> {
    let Value::Array(items) = entries else {
        return Ok(());
    };
    for item in items {
        let Value::Array(pair) = item else { continue };
        let id = match pair.first() {
            Some(Value::BulkString(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => return Err(StreamError::Malformed),
        };
        let fields: Vec<(String, String)> = match pair.get(1) {
            Some(Value::Array(kv)) => kv
                .chunks(2)
                .filter_map(|c| match (c.first(), c.get(1)) {
                    (Some(Value::BulkString(k)), Some(Value::BulkString(v))) => Some((
                        String::from_utf8_lossy(k).into_owned(),
                        String::from_utf8_lossy(v).into_owned(),
                    )),
                    _ => None,
                })
                .collect(),
            Some(Value::Map(m)) => m
                .iter()
                .filter_map(|(k, v)| match (k, v) {
                    (Value::BulkString(k), Value::BulkString(v)) => Some((
                        String::from_utf8_lossy(k).into_owned(),
                        String::from_utf8_lossy(v).into_owned(),
                    )),
                    _ => None,
                })
                .collect(),
            _ => return Err(StreamError::Malformed),
        };
        let get = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v.clone());
        let message = DispatchMessage {
            tenant_id: get("tenant_id")
                .and_then(|s| s.parse().ok())
                .ok_or(StreamError::Malformed)?,
            action_id: get("action_id")
                .and_then(|s| s.parse().ok())
                .ok_or(StreamError::Malformed)?,
            outbox_id: get("outbox_id")
                .and_then(|s| s.parse().ok())
                .ok_or(StreamError::Malformed)?,
            event_kind: get("event_kind").unwrap_or_default(),
        };
        out.push(Delivery {
            stream: stream.to_owned(),
            id,
            message,
            delivery_count,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[test]
    fn sharding_is_stable_and_bounded() {
        let t = TenantId::new();
        assert_eq!(shard_for(t), shard_for(t));
        assert!(shard_for(t) < SHARDS);
    }
}
