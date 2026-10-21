//! The reference platform's own record (SQLite). It owns accounts, agents,
//! addresses, Sent and Inbox, decisions, leases, grants, foreign keys,
//! nonces, pair blocks and the hand-off queue (D1). The schema is this
//! fixture's choice; PTPAN ships none.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

const SCHEMA: &str = "
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    given_name TEXT NOT NULL,
    family_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    ownership_revision INTEGER NOT NULL,
    key_seed BLOB NOT NULL CHECK (length(key_seed) = 32),
    key_revision INTEGER NOT NULL
);
-- Never reassigned: the address is the key and rows are never deleted (H2).
CREATE TABLE IF NOT EXISTS addresses (
    address TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    retired INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sent (
    request_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inbox (
    source_platform_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    account_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    ownership_revision INTEGER NOT NULL,
    state TEXT NOT NULL,
    intent_json TEXT,
    PRIMARY KEY (source_platform_id, request_id)
);
CREATE TABLE IF NOT EXISTS handoff (
    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    handoff_id TEXT NOT NULL UNIQUE,
    kind INTEGER NOT NULL,
    peer_platform_id TEXT NOT NULL,
    relationship_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    actor_side INTEGER NOT NULL,
    committed_at TEXT NOT NULL,
    acked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS relationships (
    relationship_id TEXT PRIMARY KEY,
    side TEXT NOT NULL CHECK (side IN ('source', 'destination')),
    peer_platform_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    ownership_revision INTEGER NOT NULL,
    request_json TEXT NOT NULL,
    lease_json TEXT NOT NULL,
    local_terms_digest BLOB NOT NULL,
    remote_terms_digest BLOB,
    owner_given_name TEXT NOT NULL,
    owner_family_name TEXT NOT NULL,
    peer_ca_root TEXT NOT NULL DEFAULT '',
    peer_edge_service_id TEXT NOT NULL DEFAULT '',
    revoked INTEGER NOT NULL DEFAULT 0,
    grant_usable INTEGER NOT NULL DEFAULT 0,
    source_withdrawn INTEGER NOT NULL DEFAULT 0,
    key_revision INTEGER NOT NULL,
    acknowledged_configuration INTEGER NOT NULL DEFAULT 0,
    foreign_key_did TEXT,
    foreign_key_revision INTEGER
);
CREATE TABLE IF NOT EXISTS pair_blocks (
    source_platform_id TEXT NOT NULL,
    requester_reference TEXT NOT NULL,
    destination_address TEXT NOT NULL,
    state TEXT NOT NULL,
    block_revision INTEGER NOT NULL,
    PRIMARY KEY (source_platform_id, requester_reference, destination_address)
);
CREATE TABLE IF NOT EXISTS block_enforcement (
    account_id TEXT NOT NULL,
    destination_address TEXT NOT NULL,
    state TEXT NOT NULL,
    block_revision INTEGER NOT NULL,
    PRIMARY KEY (account_id, destination_address)
);
CREATE TABLE IF NOT EXISTS nonces (
    jti TEXT PRIMARY KEY,
    relationship_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inbound_events (
    source_platform_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    result INTEGER NOT NULL,
    PRIMARY KEY (source_platform_id, event_id)
);
";

pub struct Db {
    pub conn: Mutex<Connection>,
}

#[derive(Clone, Debug)]
pub struct Relationship {
    pub relationship_id: String,
    pub side: String,
    pub peer_platform_id: String,
    pub account_id: String,
    pub agent_id: String,
    pub ownership_revision: u64,
    pub request_json: String,
    pub lease_json: String,
    pub local_terms_digest: [u8; 32],
    pub remote_terms_digest: Option<[u8; 32]>,
    pub owner_given_name: String,
    pub owner_family_name: String,
    pub peer_ca_root: String,
    pub peer_edge_service_id: String,
    pub revoked: bool,
    pub grant_usable: bool,
    pub source_withdrawn: bool,
    pub key_revision: u64,
    pub acknowledged_configuration: bool,
    pub foreign_key_did: Option<String>,
    pub foreign_key_revision: Option<u64>,
}

fn digest(bytes: Vec<u8>) -> [u8; 32] {
    bytes.try_into().unwrap_or([0; 32])
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.conn.lock().map_err(|_| "database lock")?;
        f(&conn)
    }

    /// One transaction (H7). `f` receives the transaction's connection.
    pub fn tx<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let mut conn = self.conn.lock().map_err(|_| "database lock")?;
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    pub fn relationship(conn: &Connection, id: &str) -> Result<Option<Relationship>> {
        Ok(conn
            .query_row(
                "SELECT relationship_id, side, peer_platform_id, account_id, agent_id, ownership_revision, request_json,
                        lease_json, local_terms_digest, remote_terms_digest, owner_given_name, owner_family_name,
                        peer_ca_root, revoked, grant_usable, source_withdrawn, key_revision, acknowledged_configuration,
                        foreign_key_did, foreign_key_revision, peer_edge_service_id
                 FROM relationships WHERE relationship_id = ?1",
                [id],
                |r| {
                    Ok(Relationship {
                        relationship_id: r.get(0)?,
                        side: r.get(1)?,
                        peer_platform_id: r.get(2)?,
                        account_id: r.get(3)?,
                        agent_id: r.get(4)?,
                        ownership_revision: r.get::<_, i64>(5)? as u64,
                        request_json: r.get(6)?,
                        lease_json: r.get(7)?,
                        local_terms_digest: digest(r.get(8)?),
                        remote_terms_digest: r.get::<_, Option<Vec<u8>>>(9)?.map(digest),
                        owner_given_name: r.get(10)?,
                        owner_family_name: r.get(11)?,
                        peer_ca_root: r.get(12)?,
                        revoked: r.get(13)?,
                        grant_usable: r.get(14)?,
                        source_withdrawn: r.get(15)?,
                        key_revision: r.get::<_, i64>(16)? as u64,
                        acknowledged_configuration: r.get(17)?,
                        foreign_key_did: r.get(18)?,
                        foreign_key_revision: r.get::<_, Option<i64>>(19)?.map(|v| v as u64),
                        peer_edge_service_id: r.get(20)?,
                    })
                },
            )
            .optional()?)
    }

    /// The agent and owning account behind one of this platform's own
    /// addresses (internal resolver, H3). Retired addresses do not resolve.
    pub fn resolve(conn: &Connection, address: &str) -> Result<Option<(String, String, u64)>> {
        Ok(conn
            .query_row(
                "SELECT g.agent_id, g.account_id, g.ownership_revision FROM addresses a
                 JOIN agents g ON g.agent_id = a.agent_id WHERE a.address = ?1 AND a.retired = 0",
                [address],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u64)),
            )
            .optional()?)
    }

    pub fn current_owner(conn: &Connection, agent_id: &str) -> Result<Option<(String, u64)>> {
        Ok(conn
            .query_row(
                "SELECT account_id, ownership_revision FROM agents WHERE agent_id = ?1",
                [agent_id],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
            )
            .optional()?)
    }

    pub fn name(conn: &Connection, account_id: &str) -> Result<(String, String)> {
        Ok(conn.query_row(
            "SELECT given_name, family_name FROM accounts WHERE account_id = ?1",
            [account_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    /// Append one cross-platform action to the hand-off queue (H15).
    #[allow(clippy::too_many_arguments)]
    pub fn handoff(
        conn: &Connection,
        handoff_id: &str,
        kind: i32,
        peer: &str,
        relationship_id: &str,
        request_id: &str,
        payload: &serde_json::Value,
        actor_side: i32,
        committed_at: &str,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO handoff (handoff_id, kind, peer_platform_id, relationship_id, request_id, payload_json,
                                  actor_side, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![handoff_id, kind, peer, relationship_id, request_id, payload.to_string(), actor_side, committed_at],
        )?;
        Ok(())
    }
}
