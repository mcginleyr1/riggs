use chrono::Utc;
use redb::ReadableTable;
use riggs_types::errors::RiggsError;
use riggs_types::events::RiggsEvent;
use tracing::info;

use crate::store::RiggsStore;
use crate::tables::EVENTS_TABLE;

pub struct RetentionPolicy {
    pub max_age_days: u32,
}

impl RetentionPolicy {
    pub fn new(max_age_days: u32) -> Self {
        Self { max_age_days }
    }

    pub async fn run_cleanup(&self, store: &RiggsStore) -> Result<usize, RiggsError> {
        let cutoff = Utc::now()
            - chrono::Duration::days(i64::from(self.max_age_days));
        let mut removed = 0usize;

        let db = store.db();

        // Scan all events, collect keys older than cutoff.
        let keys_to_remove = {
            let read_txn = db
                .begin_read()
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            let table = read_txn
                .open_table(EVENTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;

            let mut expired_keys = Vec::new();
            let iter = table
                .iter()
                .map_err(|e| RiggsError::Store(e.to_string()))?;

            for entry in iter {
                let (key, value) = entry.map_err(|e| RiggsError::Store(e.to_string()))?;
                let compressed = value.value();
                let decompressed = zstd::decode_all(compressed)
                    .map_err(|e| RiggsError::Store(e.to_string()))?;

                if let Ok(event) = serde_json::from_slice::<RiggsEvent>(&decompressed) {
                    let ts = event_timestamp(&event);
                    if ts < cutoff {
                        expired_keys.push(key.value().to_vec());
                    }
                }
            }
            expired_keys
        };

        // Delete expired keys.
        if !keys_to_remove.is_empty() {
            let write_txn = db
                .begin_write()
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(EVENTS_TABLE)
                    .map_err(|e| RiggsError::Store(e.to_string()))?;
                for key in &keys_to_remove {
                    table
                        .remove(key.as_slice())
                        .map_err(|e| RiggsError::Store(e.to_string()))?;
                    removed += 1;
                }
            }
            write_txn
                .commit()
                .map_err(|e| RiggsError::Store(e.to_string()))?;
        }

        info!(removed, "retention cleanup complete");
        Ok(removed)
    }
}

fn event_timestamp(event: &RiggsEvent) -> chrono::DateTime<Utc> {
    match event {
        RiggsEvent::Process(e) => e.timestamp,
        RiggsEvent::File(e) => e.timestamp,
        RiggsEvent::Network(e) => e.timestamp,
        RiggsEvent::Dns(e) => e.timestamp,
        RiggsEvent::Auth(e) => e.timestamp,
        RiggsEvent::Kernel(e) => e.timestamp,
    }
}
