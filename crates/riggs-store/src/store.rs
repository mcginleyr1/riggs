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
    compress: bool,
}

/// Decompress zstd data, falling back to the raw bytes when the value was
/// written uncompressed (so the store reads correctly across a toggle of
/// `compression_enabled`).
fn decode(bytes: &[u8]) -> Vec<u8> {
    zstd::decode_all(bytes).unwrap_or_else(|_| bytes.to_vec())
}

impl RiggsStore {
    pub fn new(path: &Path) -> Result<Self, RiggsError> {
        Self::with_compression(path, true)
    }

    pub fn with_compression(path: &Path, compress: bool) -> Result<Self, RiggsError> {
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

        Ok(Self {
            db: Arc::new(db),
            compress,
        })
    }

    fn encode(&self, json: &[u8]) -> Result<Vec<u8>, RiggsError> {
        if self.compress {
            zstd::encode_all(json, 3).map_err(|e| RiggsError::Store(e.to_string()))
        } else {
            Ok(json.to_vec())
        }
    }

    pub fn store_event(&self, event: &RiggsEvent) -> Result<(), RiggsError> {
        let key = event_id_from(event);
        let json = serde_json::to_vec(event).map_err(|e| RiggsError::Store(e.to_string()))?;
        let stored = self.encode(&json)?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(EVENTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            table
                .insert(key.as_slice(), stored.as_slice())
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
        let json = serde_json::to_vec(verdict).map_err(|e| RiggsError::Store(e.to_string()))?;
        let stored = self.encode(&json)?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(VERDICTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            table
                .insert(key.as_slice(), stored.as_slice())
                .map_err(|e| RiggsError::Store(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        debug!("stored verdict");
        Ok(())
    }

    /// Persist a batch of (event, verdict) pairs in a SINGLE transaction, so the
    /// hot path pays one fsync per batch instead of two per event.
    pub fn store_batch(&self, batch: &[(RiggsEvent, MergedVerdict)]) -> Result<(), RiggsError> {
        if batch.is_empty() {
            return Ok(());
        }
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let mut events = write_txn
                .open_table(EVENTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            let mut verdicts = write_txn
                .open_table(VERDICTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            for (event, verdict) in batch {
                let ekey = event_id_from(event);
                let ejson = serde_json::to_vec(event).map_err(|e| RiggsError::Store(e.to_string()))?;
                events
                    .insert(ekey.as_slice(), self.encode(&ejson)?.as_slice())
                    .map_err(|e| RiggsError::Store(e.to_string()))?;

                let vkey = verdict.event_id.0.as_bytes().to_vec();
                let vjson =
                    serde_json::to_vec(verdict).map_err(|e| RiggsError::Store(e.to_string()))?;
                verdicts
                    .insert(vkey.as_slice(), self.encode(&vjson)?.as_slice())
                    .map_err(|e| RiggsError::Store(e.to_string()))?;
            }
        }
        write_txn
            .commit()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        debug!(count = batch.len(), "stored batch");
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
                let json = decode(data.value());
                let event: RiggsEvent = serde_json::from_slice(&json)
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
            let json = decode(value.value());
            let event: RiggsEvent = serde_json::from_slice(&json)
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

        // UUIDv7 keys are time-ordered; iterate from the newest end and stop at
        // `limit` instead of materializing the whole table.
        let iter = table
            .iter()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        for entry in iter.rev() {
            if events.len() >= limit {
                break;
            }
            let (_, value) = entry.map_err(|e| RiggsError::Store(e.to_string()))?;
            let json = decode(value.value());
            if let Ok(event) = serde_json::from_slice::<RiggsEvent>(&json) {
                events.push(event);
            }
        }
        // Restore chronological (oldest-first) order.
        events.reverse();

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
            let json = decode(value.value());
            if let Ok(verdict) = serde_json::from_slice::<MergedVerdict>(&json) {
                if verdict.final_threat_level > riggs_types::verdict::ThreatLevel::Clean {
                    verdicts.push(verdict);
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
        let json = serde_json::to_vec(record).map_err(|e| RiggsError::Store(e.to_string()))?;
        let stored = self.encode(&json)?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(RESPONSE_LOG_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            table
                .insert(key.as_slice(), stored.as_slice())
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

#[cfg(test)]
mod tests {
    use super::*;
    use riggs_types::events::ProcessContext;
    use riggs_types::events::ProcessAction;
    use riggs_types::verdict::MergedVerdict;

    fn tmp_db() -> std::path::PathBuf {
        // Unique-enough path without Date/rand: use a UUIDv7 (time-ordered).
        let mut p = std::env::temp_dir();
        p.push(format!("riggs-store-test-{}.db", uuid::Uuid::now_v7()));
        p
    }

    fn proc_event(pid: u32) -> RiggsEvent {
        let ctx = ProcessContext {
            pid,
            ppid: 1,
            name: "p".into(),
            path: "/p".into(),
            cmdline: "p".into(),
            user: "root".into(),
            storyline_id: StorylineId::new(),
        };
        RiggsEvent::new_process(ProcessAction::Exec, ctx, None)
    }

    fn verdict_for(event: &RiggsEvent) -> MergedVerdict {
        MergedVerdict::from_verdicts(
            event.event_id().clone(),
            event_storyline_id(event).unwrap().clone(),
            Vec::new(),
        )
    }

    #[test]
    fn batch_round_trips_events() {
        let path = tmp_db();
        let store = RiggsStore::with_compression(&path, true).unwrap();
        let e1 = proc_event(10);
        let e2 = proc_event(11);
        let batch = vec![
            (e1.clone(), verdict_for(&e1)),
            (e2.clone(), verdict_for(&e2)),
        ];
        store.store_batch(&batch).unwrap();

        assert!(store.get_event(e1.event_id()).unwrap().is_some());
        assert!(store.get_event(e2.event_id()).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reads_uncompressed_when_compression_disabled() {
        let path = tmp_db();
        let store = RiggsStore::with_compression(&path, false).unwrap();
        let e = proc_event(20);
        store.store_event(&e).unwrap();
        let got = store.get_event(e.event_id()).unwrap();
        assert_eq!(got.map(|g| g.event_id().clone()), Some(e.event_id().clone()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recent_events_returns_chronological_and_capped() {
        let path = tmp_db();
        let store = RiggsStore::new(&path).unwrap();
        for pid in 0..5u32 {
            store.store_event(&proc_event(pid)).unwrap();
        }
        let recent = store.get_recent_events(3).unwrap();
        assert_eq!(recent.len(), 3);
        // UUIDv7 keys are time-ordered; result is oldest-first within the window.
        let ids: Vec<_> = recent.iter().map(|e| e.event_id().0).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        let _ = std::fs::remove_file(&path);
    }
}
