use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableTable};
use riggs_types::errors::RiggsError;
use riggs_types::events::{EventId, RiggsEvent, StorylineId};
use riggs_types::verdict::MergedVerdict;
use tracing::debug;

use crate::tables::{EVENTS_TABLE, RESPONSE_LOG_TABLE, VERDICTS_TABLE};

// Re-export for use by other crates that store response records.
pub use riggs_types::events;

pub struct RiggsStore {
    db: Arc<Database>,
}

impl RiggsStore {
    pub fn new(path: &Path) -> Result<Self, RiggsError> {
        let db = Database::create(path).map_err(|e| RiggsError::Store(e.to_string()))?;

        // Ensure all tables exist by opening a write transaction.
        let write_txn = db
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let _ = write_txn
                .open_table(EVENTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            let _ = write_txn
                .open_table(VERDICTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            let _ = write_txn
                .open_table(RESPONSE_LOG_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    pub fn store_event(&self, event: &RiggsEvent) -> Result<(), RiggsError> {
        let key = event_id_from(event);
        let json = serde_json::to_vec(event).map_err(|e| RiggsError::Store(e.to_string()))?;
        let compressed = zstd::encode_all(json.as_slice(), 3)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(EVENTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            table
                .insert(key.as_slice(), compressed.as_slice())
                .map_err(|e| RiggsError::Store(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        debug!("stored event");
        Ok(())
    }

    pub fn store_verdict(&self, verdict: &MergedVerdict) -> Result<(), RiggsError> {
        let key = verdict.event_id.0.as_bytes().to_vec();
        let json =
            serde_json::to_vec(verdict).map_err(|e| RiggsError::Store(e.to_string()))?;
        let compressed = zstd::encode_all(json.as_slice(), 3)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(VERDICTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            table
                .insert(key.as_slice(), compressed.as_slice())
                .map_err(|e| RiggsError::Store(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        debug!("stored verdict");
        Ok(())
    }

    pub fn get_event(&self, id: &EventId) -> Result<Option<RiggsEvent>, RiggsError> {
        let key = id.0.as_bytes().to_vec();

        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        let table = read_txn
            .open_table(EVENTS_TABLE)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let value = table
            .get(key.as_slice())
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        match value {
            Some(data) => {
                let compressed = data.value();
                let decompressed = zstd::decode_all(compressed)
                    .map_err(|e| RiggsError::Store(e.to_string()))?;
                let event: RiggsEvent = serde_json::from_slice(&decompressed)
                    .map_err(|e| RiggsError::Store(e.to_string()))?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    pub fn get_events_by_storyline(
        &self,
        storyline_id: &StorylineId,
    ) -> Result<Vec<RiggsEvent>, RiggsError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        let table = read_txn
            .open_table(EVENTS_TABLE)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let mut results = Vec::new();
        let iter = table
            .iter()
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        for entry in iter {
            let (_, value) = entry.map_err(|e| RiggsError::Store(e.to_string()))?;
            let compressed = value.value();
            let decompressed =
                zstd::decode_all(compressed).map_err(|e| RiggsError::Store(e.to_string()))?;
            let event: RiggsEvent = serde_json::from_slice(&decompressed)
                .map_err(|e| RiggsError::Store(e.to_string()))?;

            if event_storyline_id(&event) == Some(storyline_id) {
                results.push(event);
            }
        }

        Ok(results)
    }

    pub fn get_recent_events(&self, limit: usize) -> Result<Vec<RiggsEvent>, RiggsError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        let table = read_txn
            .open_table(EVENTS_TABLE)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let mut events = Vec::new();
        let iter = table
            .iter()
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        // UUIDv7 keys are time-ordered, so iterating gives chronological order.
        // Collect all then take the last N for "most recent".
        let all: Vec<_> = iter.collect();
        let start = all.len().saturating_sub(limit);

        for entry in &all[start..] {
            let (_, value) = entry.as_ref().map_err(|e| RiggsError::Store(e.to_string()))?;
            let compressed = value.value();
            if let Ok(decompressed) = zstd::decode_all(compressed) {
                if let Ok(event) = serde_json::from_slice::<RiggsEvent>(&decompressed) {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    pub fn get_verdicts_above_clean(&self, limit: usize) -> Result<Vec<MergedVerdict>, RiggsError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        let table = read_txn
            .open_table(VERDICTS_TABLE)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let mut verdicts = Vec::new();
        let iter = table
            .iter()
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        for entry in iter {
            let (_, value) = entry.map_err(|e| RiggsError::Store(e.to_string()))?;
            let compressed = value.value();
            if let Ok(decompressed) = zstd::decode_all(compressed) {
                if let Ok(verdict) = serde_json::from_slice::<MergedVerdict>(&decompressed) {
                    if verdict.final_threat_level > riggs_types::verdict::ThreatLevel::Clean {
                        verdicts.push(verdict);
                    }
                }
            }
        }

        // Return the most recent ones
        let start = verdicts.len().saturating_sub(limit);
        Ok(verdicts[start..].to_vec())
    }

    pub fn store_response_record(
        &self,
        record: &riggs_response_record::ResponseRecordData,
    ) -> Result<(), RiggsError> {
        let key = record.id.as_bytes().to_vec();
        let json =
            serde_json::to_vec(record).map_err(|e| RiggsError::Store(e.to_string()))?;
        let compressed = zstd::encode_all(json.as_slice(), 3)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(RESPONSE_LOG_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            table
                .insert(key.as_slice(), compressed.as_slice())
                .map_err(|e| RiggsError::Store(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        debug!("stored response record");
        Ok(())
    }

    pub(crate) fn db(&self) -> &Database {
        &self.db
    }
}

fn event_id_from(event: &RiggsEvent) -> Vec<u8> {
    let id = match event {
        RiggsEvent::Process(e) => &e.event_id,
        RiggsEvent::File(e) => &e.event_id,
        RiggsEvent::Network(e) => &e.event_id,
        RiggsEvent::Dns(e) => &e.event_id,
        RiggsEvent::Auth(e) => &e.event_id,
        RiggsEvent::Kernel(e) => &e.event_id,
    };
    id.0.as_bytes().to_vec()
}

fn event_storyline_id(event: &RiggsEvent) -> Option<&StorylineId> {
    let ctx = match event {
        RiggsEvent::Process(e) => &e.process_context,
        RiggsEvent::File(e) => &e.process_context,
        RiggsEvent::Network(e) => &e.process_context,
        RiggsEvent::Dns(e) => &e.process_context,
        RiggsEvent::Auth(e) => &e.process_context,
        RiggsEvent::Kernel(e) => &e.process_context,
    };
    Some(&ctx.storyline_id)
}

/// Minimal mirror of the response record to avoid circular dependency
/// (riggs-store cannot depend on riggs-response).
pub mod riggs_response_record {
    use chrono::{DateTime, Utc};
    use riggs_types::events::EventId;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ResponseRecordData {
        pub id: Uuid,
        pub action_description: String,
        pub event_id: EventId,
        pub executed_at: DateTime<Utc>,
        pub success: bool,
        pub detail: String,
    }
}
