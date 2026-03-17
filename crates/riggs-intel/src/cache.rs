use redb::{Database, ReadableTableMetadata, TableDefinition};
use riggs_types::errors::RiggsError;
use riggs_types::verdict::{DetectionSource, ThreatLevel};
use serde::{Deserialize, Serialize};

const CACHE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("hash_verdicts");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVerdict {
    pub threat_level: ThreatLevel,
    pub confidence: f32,
    pub source: DetectionSource,
    pub cached_at: chrono::DateTime<chrono::Utc>,
    pub ttl_hours: u32,
}

impl CachedVerdict {
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now();
        let duration = chrono::Duration::hours(self.ttl_hours as i64);
        now.signed_duration_since(self.cached_at) > duration
    }
}

pub struct HashVerdictCache {
    db: Database,
    ttl_clean_hours: u32,
    ttl_malicious_hours: u32,
}

impl HashVerdictCache {
    pub fn new(
        path: &std::path::Path,
        ttl_clean: u32,
        ttl_malicious: u32,
    ) -> Result<Self, RiggsError> {
        let db = Database::create(path)
            .map_err(|e| RiggsError::Intel(format!("failed to open cache db: {e}")))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| RiggsError::Intel(format!("failed to begin write txn: {e}")))?;
        write_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| RiggsError::Intel(format!("failed to open cache table: {e}")))?;
        write_txn
            .commit()
            .map_err(|e| RiggsError::Intel(format!("failed to commit table creation: {e}")))?;

        Ok(Self {
            db,
            ttl_clean_hours: ttl_clean,
            ttl_malicious_hours: ttl_malicious,
        })
    }

    pub fn get(&self, hash: &str) -> Option<CachedVerdict> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(CACHE_TABLE).ok()?;
        let value = table.get(hash.as_bytes()).ok()??;
        let verdict: CachedVerdict = serde_json::from_slice(value.value()).ok()?;

        if verdict.is_expired() {
            return None;
        }

        Some(verdict)
    }

    pub fn put(&self, hash: &str, verdict: CachedVerdict) {
        let Ok(write_txn) = self.db.begin_write() else {
            tracing::warn!("failed to begin write txn for cache put");
            return;
        };

        let result = (|| {
            let mut table = write_txn
                .open_table(CACHE_TABLE)
                .map_err(|e| RiggsError::Intel(format!("open table: {e}")))?;
            let bytes = serde_json::to_vec(&verdict)
                .map_err(|e| RiggsError::Intel(format!("serialize verdict: {e}")))?;
            table
                .insert(hash.as_bytes(), bytes.as_slice())
                .map_err(|e| RiggsError::Intel(format!("insert: {e}")))?;
            Ok::<(), RiggsError>(())
        })();

        if let Err(e) = result {
            tracing::warn!("failed to write cache entry: {e}");
            return;
        }

        if let Err(e) = write_txn.commit() {
            tracing::warn!("failed to commit cache write: {e}");
        }
    }

    pub fn entry_count(&self) -> u64 {
        let Ok(read_txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(table) = read_txn.open_table(CACHE_TABLE) else {
            return 0;
        };
        table.len().unwrap_or(0)
    }

    pub fn ttl_for_level(&self, level: ThreatLevel) -> u32 {
        match level {
            ThreatLevel::Clean => self.ttl_clean_hours,
            ThreatLevel::Suspicious | ThreatLevel::Malicious => self.ttl_malicious_hours,
        }
    }
}
