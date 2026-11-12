use chrono::{DateTime, Utc};
use redb::{Database, ReadableTable, TableDefinition};
use riggs_types::errors::RiggsError;
use tracing::info;

use crate::store::RiggsStore;
use crate::tables::{EVENTS_TABLE, PHISHING_VERDICTS_TABLE, RESPONSE_LOG_TABLE, VERDICTS_TABLE};

pub struct RetentionPolicy {
    pub max_age_days: u32,
}

impl RetentionPolicy {
    pub fn new(max_age_days: u32) -> Self {
        Self { max_age_days }
    }

    /// Delete events, verdicts, response-log records and phishing verdict-log
    /// rows older than the retention window. All four tables' keys start with a
    /// UUIDv7, whose first six bytes are a big-endian millisecond timestamp, so
    /// byte-ordered keys are chronological and we can prune by key without
    /// decompressing any value. Phishing logins and senders are never aged out.
    pub async fn run_cleanup(&self, store: &RiggsStore) -> Result<usize, RiggsError> {
        let cutoff = Utc::now() - chrono::Duration::days(i64::from(self.max_age_days));
        let cutoff_key = uuid_v7_floor_key(cutoff);
        let db = store.db();

        let mut removed = 0usize;
        removed += prune_before(db, EVENTS_TABLE, &cutoff_key)?;
        removed += prune_before(db, VERDICTS_TABLE, &cutoff_key)?;
        removed += prune_before(db, RESPONSE_LOG_TABLE, &cutoff_key)?;
        removed += prune_before(db, PHISHING_VERDICTS_TABLE, &cutoff_key)?;

        info!(
            removed,
            days = self.max_age_days,
            "retention cleanup complete"
        );
        Ok(removed)
    }
}

/// Remove every entry whose key sorts before `cutoff_key`.
fn prune_before(
    db: &Database,
    table: TableDefinition<&[u8], &[u8]>,
    cutoff_key: &[u8],
) -> Result<usize, RiggsError> {
    let keys_to_remove = {
        let read_txn = db
            .begin_read()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        let tbl = match read_txn.open_table(table) {
            Ok(tbl) => tbl,
            // A table that was never written yet simply has nothing to prune.
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(RiggsError::Store(e.to_string())),
        };

        let mut expired = Vec::new();
        for entry in tbl.iter().map_err(|e| RiggsError::Store(e.to_string()))? {
            let (key, _value) = entry.map_err(|e| RiggsError::Store(e.to_string()))?;
            if key.value() < cutoff_key {
                expired.push(key.value().to_vec());
            }
        }
        expired
    };

    if keys_to_remove.is_empty() {
        return Ok(0);
    }

    let write_txn = db
        .begin_write()
        .map_err(|e| RiggsError::Store(e.to_string()))?;
    {
        let mut tbl = write_txn
            .open_table(table)
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        for key in &keys_to_remove {
            tbl.remove(key.as_slice())
                .map_err(|e| RiggsError::Store(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| RiggsError::Store(e.to_string()))?;

    Ok(keys_to_remove.len())
}

/// Build a 16-byte key whose UUIDv7 timestamp prefix equals `cutoff`, with the
/// remaining bytes zeroed. Any UUIDv7 generated strictly before `cutoff` sorts
/// below this key.
fn uuid_v7_floor_key(cutoff: DateTime<Utc>) -> [u8; 16] {
    let ms = cutoff.timestamp_millis().max(0) as u64;
    let mut key = [0u8; 16];
    key[0] = (ms >> 40) as u8;
    key[1] = (ms >> 32) as u8;
    key[2] = (ms >> 24) as u8;
    key[3] = (ms >> 16) as u8;
    key[4] = (ms >> 8) as u8;
    key[5] = ms as u8;
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn floor_key_orders_before_later_uuids() {
        // A UUIDv7 minted "now" must sort at/after a floor key for an earlier time.
        let cutoff = Utc::now() - chrono::Duration::days(1);
        let floor = uuid_v7_floor_key(cutoff);
        let recent = *Uuid::now_v7().as_bytes();
        assert!(recent.as_slice() > floor.as_slice());
    }

    #[tokio::test]
    async fn cleanup_prunes_old_phishing_verdicts_and_keeps_logins_and_senders() {
        use crate::phishing::{PhishingWrite, SenderEntry, StoredVerdict};
        use riggs_types::phishing::{Level, LoginEntry, ObservationKind, VerdictEntry};
        use uuid::{NoContext, Timestamp};

        let path = std::env::temp_dir().join(format!("riggs-retention-test-{}.db", Uuid::now_v7()));
        let store = RiggsStore::new(&path).unwrap();
        let entry = VerdictEntry {
            time_ms: 1,
            kind: ObservationKind::Mail,
            domain: "example.com".into(),
            cues: vec!["example_cue".into()],
            score: 0.5,
            level: Level::Caution,
            shown: true,
        };
        store
            .phishing_apply(&[
                PhishingWrite::Login {
                    uid: 501,
                    entry: LoginEntry {
                        domain: "example.com".into(),
                        first_ms: 1,
                        last_ms: 1,
                        count: 1,
                    },
                },
                PhishingWrite::Sender {
                    uid: 501,
                    entry: SenderEntry {
                        key: "example.net".into(),
                        first_ms: 1,
                        first_msg: 1,
                    },
                },
                PhishingWrite::Verdict {
                    uid: 501,
                    msg: 2,
                    entry: entry.clone(),
                },
            ])
            .unwrap();

        let thirty_days_ago = (Utc::now() - chrono::Duration::days(30)).timestamp() as u64;
        let mut old_key = Uuid::new_v7(Timestamp::from_unix(NoContext, thirty_days_ago, 0))
            .as_bytes()
            .to_vec();
        old_key.extend_from_slice(&501u32.to_be_bytes());
        let old_value = serde_json::to_vec(&StoredVerdict { msg: 1, entry }).unwrap();
        let write_txn = store.db().begin_write().unwrap();
        write_txn
            .open_table(PHISHING_VERDICTS_TABLE)
            .unwrap()
            .insert(
                old_key.as_slice(),
                store.encode(&old_value).unwrap().as_slice(),
            )
            .unwrap();
        write_txn.commit().unwrap();

        let rows = store.phishing_load().unwrap();
        assert_eq!((rows.logins.len(), rows.senders.len()), (1, 1));
        let before: Vec<_> = store
            .phishing_verdicts(501, 10)
            .unwrap()
            .iter()
            .map(|v| v.msg)
            .collect();
        assert_eq!(before, vec![2, 1]);

        let removed = RetentionPolicy::new(7).run_cleanup(&store).await.unwrap();

        assert_eq!(removed, 1);
        let after: Vec<_> = store
            .phishing_verdicts(501, 10)
            .unwrap()
            .iter()
            .map(|v| v.msg)
            .collect();
        assert_eq!(after, vec![2]);
        assert_eq!(store.phishing_load().unwrap(), rows);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn floor_key_orders_after_older_uuids() {
        let old = *Uuid::now_v7().as_bytes();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let floor = uuid_v7_floor_key(Utc::now());
        assert!(old.as_slice() < floor.as_slice());
    }
}
