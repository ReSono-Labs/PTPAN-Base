//! The adapter's exchange store (D1): peer store, identity observations,
//! exact event bytes, peer inbox and outbox, delivery status, actor
//! revisions and this platform's own manifest. It never holds grants, leases,
//! ownership or nonces: those stay on the platform.

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use federation_base::identity_evidence::FieldObservation;
use federation_base::peer_transitions::PeerRecord;
use federation_base::PlatformId;
use tokio_postgres::NoTls;

pub type StoreError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, StoreError>;

const MIGRATION_1: &str = "
CREATE TABLE IF NOT EXISTS ptpan_peers (
    platform_id TEXT PRIMARY KEY,
    record TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS ptpan_identity_observations (
    id BIGSERIAL PRIMARY KEY,
    platform_id TEXT NOT NULL,
    manifest_digest BYTEA NOT NULL,
    observations TEXT NOT NULL,
    recorded_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS ptpan_outbox (
    event_id TEXT PRIMARY KEY,
    handoff_id TEXT UNIQUE,
    peer_platform_id TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('control', 'peer')),
    kind TEXT NOT NULL,
    exact_bytes BYTEA NOT NULL,
    body_digest BYTEA NOT NULL CHECK (length(body_digest) = 32),
    expires_at BIGINT NOT NULL,
    -- queued: not yet accepted by the peer; receipted: the peer's receipt is
    -- stored but the platform has not confirmed it; delivered: done.
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'receipted', 'delivered', 'expired')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL DEFAULT 0,
    receipt BYTEA,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ptpan_outbox_due ON ptpan_outbox (peer_platform_id, next_attempt_at)
    WHERE state = 'queued';
CREATE TABLE IF NOT EXISTS ptpan_peer_leases (
    peer_platform_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    until_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS ptpan_inbox (
    sender_platform_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    body_digest BYTEA NOT NULL CHECK (length(body_digest) = 32),
    receipt BYTEA NOT NULL,
    received_at BIGINT NOT NULL,
    PRIMARY KEY (sender_platform_id, event_id)
);
CREATE TABLE IF NOT EXISTS ptpan_actor_revisions (
    scope TEXT PRIMARY KEY,
    revision BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS ptpan_own_manifest (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    pending_bytes BYTEA,
    pending_effective_at BIGINT
);
";

#[derive(Clone)]
pub struct Store {
    pool: Pool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEvent {
    pub event_id: String,
    pub handoff_id: Option<String>,
    pub peer: PlatformId,
    pub channel: Channel,
    pub kind: String,
    pub exact_bytes: Vec<u8>,
    pub body_digest: [u8; 32],
    pub expires_at: u64,
    pub attempts: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Channel {
    /// `federation-control/v3` relationship events.
    Control,
    /// `federation-peer/v2` provider messages.
    Peer,
}

impl Channel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Peer => "peer",
        }
    }
    fn parse(value: &str) -> Self {
        if value == "peer" {
            Self::Peer
        } else {
            Self::Control
        }
    }
}

fn i64_of(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| "value out of range".into())
}

fn digest_of(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| "digest length".into())
}

impl Store {
    pub async fn connect(url: &str) -> Result<Self> {
        let config: tokio_postgres::Config = url.parse()?;
        let manager = Manager::from_config(
            config,
            NoTls,
            ManagerConfig { recycling_method: RecyclingMethod::Fast },
        );
        let pool = Pool::builder(manager).max_size(16).build()?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<()> {
        let client = self.pool.get().await?;
        client.batch_execute(MIGRATION_1).await?;
        Ok(())
    }

    // --- Peer store -------------------------------------------------------

    pub async fn peers(&self) -> Result<Vec<(PlatformId, PeerRecord)>> {
        let client = self.pool.get().await?;
        let rows = client
            .query("SELECT platform_id, record FROM ptpan_peers ORDER BY platform_id", &[])
            .await?;
        rows.iter()
            .map(|row| {
                let id: String = row.get(0);
                let record: String = row.get(1);
                Ok((PlatformId::new(id)?, serde_json::from_str(&record)?))
            })
            .collect()
    }

    pub async fn peer(&self, id: &PlatformId) -> Result<Option<PeerRecord>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt("SELECT record FROM ptpan_peers WHERE platform_id = $1", &[&id.as_str()])
            .await?;
        row.map(|row| Ok(serde_json::from_str(&row.get::<_, String>(0))?)).transpose()
    }

    /// Insert a new peer. Fails if it already exists.
    pub async fn add_peer(&self, id: &PlatformId, record: &PeerRecord, now: u64) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO ptpan_peers (platform_id, record, updated_at) VALUES ($1, $2, $3)",
                &[&id.as_str(), &serde_json::to_string(record)?, &i64_of(now)?],
            )
            .await?;
        Ok(())
    }

    /// Read-modify-write one peer record under a row lock. `change` returns
    /// a value passed back to the caller; an error rolls back.
    pub async fn update_peer<T, F>(&self, id: &PlatformId, now: u64, change: F) -> Result<T>
    where
        F: FnOnce(&mut PeerRecord) -> Result<T>,
    {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let row = tx
            .query_opt("SELECT record FROM ptpan_peers WHERE platform_id = $1 FOR UPDATE", &[&id.as_str()])
            .await?
            .ok_or("unknown peer")?;
        let mut record: PeerRecord = serde_json::from_str(&row.get::<_, String>(0))?;
        let out = change(&mut record)?;
        tx.execute(
            "UPDATE ptpan_peers SET record = $2, updated_at = $3 WHERE platform_id = $1",
            &[&id.as_str(), &serde_json::to_string(&record)?, &i64_of(now)?],
        )
        .await?;
        tx.commit().await?;
        Ok(out)
    }

    /// Latest change time across all peers, so a running adapter can notice
    /// operator changes without a restart (principle 10).
    pub async fn peers_version(&self) -> Result<u64> {
        let client = self.pool.get().await?;
        let row = client
            .query_one("SELECT COALESCE(MAX(updated_at), 0), COUNT(*) FROM ptpan_peers", &[])
            .await?;
        let latest: i64 = row.get(0);
        let count: i64 = row.get(1);
        Ok((latest as u64).wrapping_mul(1_000).wrapping_add(count as u64))
    }

    pub async fn record_observations(
        &self,
        id: &PlatformId,
        digest: &[u8; 32],
        observations: &[FieldObservation],
        now: u64,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO ptpan_identity_observations (platform_id, manifest_digest, observations, recorded_at)
                 VALUES ($1, $2, $3, $4)",
                &[&id.as_str(), &digest.as_slice(), &serde_json::to_string(observations)?, &i64_of(now)?],
            )
            .await?;
        Ok(())
    }

    // --- Outbox -----------------------------------------------------------

    /// Store exact event bytes once. Returns false when the event (or the
    /// hand-off it came from) was already stored, so a retried hand-off never
    /// produces a second event.
    pub async fn enqueue(&self, event: &OutboxEvent, now: u64) -> Result<bool> {
        let client = self.pool.get().await?;
        let inserted = client
            .execute(
                "INSERT INTO ptpan_outbox (event_id, handoff_id, peer_platform_id, channel, kind, exact_bytes,
                     body_digest, expires_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT DO NOTHING",
                &[
                    &event.event_id,
                    &event.handoff_id,
                    &event.peer.as_str(),
                    &event.channel.as_str(),
                    &event.kind,
                    &event.exact_bytes,
                    &event.body_digest.as_slice(),
                    &i64_of(event.expires_at)?,
                    &i64_of(now)?,
                ],
            )
            .await?;
        Ok(inserted == 1)
    }

    pub async fn handoff_stored(&self, handoff_id: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt("SELECT 1 FROM ptpan_outbox WHERE handoff_id = $1", &[&handoff_id])
            .await?
            .is_some())
    }

    /// Peers that have queued events, for worker assignment.
    pub async fn peers_with_queued(&self) -> Result<Vec<PlatformId>> {
        let client = self.pool.get().await?;
        let rows = client
            .query("SELECT DISTINCT peer_platform_id FROM ptpan_outbox WHERE state = 'queued'", &[])
            .await?;
        rows.iter().map(|row| Ok(PlatformId::new(row.get::<_, String>(0))?)).collect()
    }

    pub async fn due(&self, peer: &PlatformId, now: u64, limit: i64) -> Result<Vec<OutboxEvent>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT event_id, handoff_id, channel, kind, exact_bytes, body_digest, expires_at, attempts
                 FROM ptpan_outbox
                 WHERE state = 'queued' AND peer_platform_id = $1 AND next_attempt_at <= $2
                 ORDER BY created_at, event_id LIMIT $3",
                &[&peer.as_str(), &i64_of(now)?, &limit],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(OutboxEvent {
                    event_id: row.get(0),
                    handoff_id: row.get(1),
                    peer: peer.clone(),
                    channel: Channel::parse(row.get::<_, &str>(2)),
                    kind: row.get(3),
                    exact_bytes: row.get(4),
                    body_digest: digest_of(row.get(5))?,
                    expires_at: row.get::<_, i64>(6) as u64,
                    attempts: row.get::<_, i32>(7) as u32,
                })
            })
            .collect()
    }

    pub async fn queued_count(&self, peer: &PlatformId) -> Result<u64> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*) FROM ptpan_outbox WHERE state = 'queued' AND peer_platform_id = $1",
                &[&peer.as_str()],
            )
            .await?;
        Ok(row.get::<_, i64>(0) as u64)
    }

    /// Store the peer's receipt. Events from a hand-off wait for the
    /// platform's confirmation; adapter-originated ones are done.
    pub async fn mark_receipted(&self, event: &OutboxEvent, receipt: &[u8]) -> Result<()> {
        let state = if event.handoff_id.is_some() { "receipted" } else { "delivered" };
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE ptpan_outbox SET state = $3, receipt = $2 WHERE event_id = $1 AND state = 'queued'",
                &[&event.event_id, &receipt, &state],
            )
            .await?;
        Ok(())
    }

    /// Receipts the platform has not yet confirmed: (hand-off ID, event ID,
    /// receipt bytes).
    pub async fn unconfirmed(&self, limit: i64) -> Result<Vec<(String, String, Vec<u8>)>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT handoff_id, event_id, receipt FROM ptpan_outbox
                 WHERE state = 'receipted' ORDER BY created_at LIMIT $1",
                &[&limit],
            )
            .await?;
        Ok(rows.iter().map(|row| (row.get(0), row.get(1), row.get(2))).collect())
    }

    pub async fn mark_confirmed(&self, event_id: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("UPDATE ptpan_outbox SET state = 'delivered' WHERE event_id = $1 AND state = 'receipted'", &[&event_id])
            .await?;
        Ok(())
    }

    pub async fn mark_expired(&self, event_id: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("UPDATE ptpan_outbox SET state = 'expired' WHERE event_id = $1 AND state = 'queued'", &[&event_id])
            .await?;
        Ok(())
    }

    /// Exponential backoff, at most five minutes between attempts.
    pub async fn reschedule(&self, event_id: &str, attempts: u32, now: u64) -> Result<()> {
        let delay = 1u64 << attempts.min(8);
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE ptpan_outbox SET attempts = $2, next_attempt_at = $3 WHERE event_id = $1",
                &[&event_id, &(attempts as i32 + 1), &i64_of(now + delay.min(300))?],
            )
            .await?;
        Ok(())
    }

    /// Fence: one adapter copy at a time delivers to a given peer. The lease
    /// is renewed by its owner and taken over only after it lapses.
    pub async fn acquire_peer_lease(&self, peer: &PlatformId, owner: &str, now: u64, ttl: u64) -> Result<bool> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "INSERT INTO ptpan_peer_leases (peer_platform_id, owner, until_at) VALUES ($1, $2, $3)
                 ON CONFLICT (peer_platform_id) DO UPDATE SET owner = $2, until_at = $3
                 WHERE ptpan_peer_leases.owner = $2 OR ptpan_peer_leases.until_at < $4
                 RETURNING owner",
                &[&peer.as_str(), &owner, &i64_of(now + ttl)?, &i64_of(now)?],
            )
            .await?;
        Ok(row.is_some())
    }

    // --- Inbox ------------------------------------------------------------

    /// The stored receipt for an already received event. The same sender,
    /// event and bytes return it again; altered bytes are a conflict.
    pub async fn inbox_receipt(&self, sender: &PlatformId, event_id: &str, digest: &[u8; 32]) -> Result<Option<std::result::Result<Vec<u8>, ()>>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT body_digest, receipt FROM ptpan_inbox WHERE sender_platform_id = $1 AND event_id = $2",
                &[&sender.as_str(), &event_id],
            )
            .await?;
        Ok(row.map(|row| {
            let stored: Vec<u8> = row.get(0);
            if stored == digest.as_slice() {
                Ok(row.get(1))
            } else {
                Err(())
            }
        }))
    }

    pub async fn store_inbox(&self, sender: &PlatformId, event_id: &str, digest: &[u8; 32], receipt: &[u8], now: u64) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO ptpan_inbox (sender_platform_id, event_id, body_digest, receipt, received_at)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                &[&sender.as_str(), &event_id, &digest.as_slice(), &receipt, &i64_of(now)?],
            )
            .await?;
        Ok(())
    }

    // --- Actor revisions ----------------------------------------------------

    /// Next monotonic actor revision for one relationship (or pair) and side.
    pub async fn next_actor_revision(&self, scope: &str) -> Result<u64> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "INSERT INTO ptpan_actor_revisions (scope, revision) VALUES ($1, 1)
                 ON CONFLICT (scope) DO UPDATE SET revision = ptpan_actor_revisions.revision + 1
                 RETURNING revision",
                &[&scope],
            )
            .await?;
        Ok(row.get::<_, i64>(0) as u64)
    }

    // --- Own manifest (D8) --------------------------------------------------

    pub async fn pending_own_manifest(&self) -> Result<Option<(Vec<u8>, u64)>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT pending_bytes, pending_effective_at FROM ptpan_own_manifest
                 WHERE id = 1 AND pending_bytes IS NOT NULL",
                &[],
            )
            .await?;
        Ok(row.map(|row| (row.get(0), row.get::<_, i64>(1) as u64)))
    }

    pub async fn set_pending_own_manifest(&self, pending: Option<(&[u8], u64)>) -> Result<()> {
        let client = self.pool.get().await?;
        let (bytes, at) = match pending {
            Some((bytes, at)) => (Some(bytes.to_vec()), Some(i64_of(at)?)),
            None => (None, None),
        };
        client
            .execute(
                "INSERT INTO ptpan_own_manifest (id, pending_bytes, pending_effective_at) VALUES (1, $1, $2)
                 ON CONFLICT (id) DO UPDATE SET pending_bytes = $1, pending_effective_at = $2",
                &[&bytes, &at],
            )
            .await?;
        Ok(())
    }
}
