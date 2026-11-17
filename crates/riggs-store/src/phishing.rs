//! Per-user phishing state: logins, mail senders and the verdict log.
//!
//! The daemon's phishing adapter keeps this state in memory and persists it from a
//! single batching task through `phishing_apply`, one transaction per batch.

use redb::ReadableTable;
use riggs_types::errors::RiggsError;
use riggs_types::phishing::{LoginEntry, VerdictEntry};
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

use crate::store::{decode, RiggsStore};
use crate::tables::{PHISHING_LOGINS_TABLE, PHISHING_SENDERS_TABLE, PHISHING_VERDICTS_TABLE};

#[derive(Debug, Clone, PartialEq)]
pub enum PhishingWrite {
    /// Insert the row, or replace the one with the same uid and domain.
    Login { uid: u32, entry: LoginEntry },
    /// Remove the row if there is one.
    ForgetLogin { uid: u32, domain: String },
    /// Insert the row unless the uid already has one with this key.
    Sender { uid: u32, entry: SenderEntry },
    /// Append a row to the verdict log.
    Verdict {
        uid: u32,
        msg: u64,
        entry: VerdictEntry,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct SenderEntry {
    pub key: String,
    pub first_ms: u64,
    pub first_msg: u64,
}

/// Every login and sender row of every uid, in key order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PhishingRows {
    pub logins: Vec<(u32, LoginEntry)>,
    pub senders: Vec<(u32, SenderEntry)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredVerdict {
    pub msg: u64,
    pub entry: VerdictEntry,
}

impl RiggsStore {
    pub fn phishing_load(&self) -> Result<PhishingRows, RiggsError> {
        let read_txn = self
            .db()
            .begin_read()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        let logins = read_txn
            .open_table(PHISHING_LOGINS_TABLE)
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        let senders = read_txn
            .open_table(PHISHING_SENDERS_TABLE)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let mut rows = PhishingRows::default();
        for row in logins
            .iter()
            .map_err(|e| RiggsError::Store(e.to_string()))?
        {
            let (key, value) = row.map_err(|e| RiggsError::Store(e.to_string()))?;
            let (uid, domain) = key.value();
            let (first_ms, last_ms, count) = value.value();
            rows.logins.push((
                uid,
                LoginEntry {
                    domain: domain.to_string(),
                    first_ms,
                    last_ms,
                    count,
                },
            ));
        }
        for row in senders
            .iter()
            .map_err(|e| RiggsError::Store(e.to_string()))?
        {
            let (key, value) = row.map_err(|e| RiggsError::Store(e.to_string()))?;
            let (uid, key) = key.value();
            let (first_ms, first_msg) = value.value();
            rows.senders.push((
                uid,
                SenderEntry {
                    key: key.to_string(),
                    first_ms,
                    first_msg,
                },
            ));
        }
        Ok(rows)
    }

    /// Apply the whole slice in ONE transaction: either every write lands or none does.
    pub fn phishing_apply(&self, writes: &[PhishingWrite]) -> Result<(), RiggsError> {
        if writes.is_empty() {
            return Ok(());
        }
        let write_txn = self
            .db()
            .begin_write()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        {
            let mut logins = write_txn
                .open_table(PHISHING_LOGINS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            let mut senders = write_txn
                .open_table(PHISHING_SENDERS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            let mut verdicts = write_txn
                .open_table(PHISHING_VERDICTS_TABLE)
                .map_err(|e| RiggsError::Store(e.to_string()))?;
            for write in writes {
                match write {
                    PhishingWrite::Login { uid, entry } => {
                        logins
                            .insert(
                                (*uid, entry.domain.as_str()),
                                (entry.first_ms, entry.last_ms, entry.count),
                            )
                            .map_err(|e| RiggsError::Store(e.to_string()))?;
                    }
                    PhishingWrite::ForgetLogin { uid, domain } => {
                        logins
                            .remove((*uid, domain.as_str()))
                            .map_err(|e| RiggsError::Store(e.to_string()))?;
                    }
                    PhishingWrite::Sender { uid, entry } => {
                        let key = (*uid, entry.key.as_str());
                        if senders
                            .get(key)
                            .map_err(|e| RiggsError::Store(e.to_string()))?
                            .is_none()
                        {
                            senders
                                .insert(key, (entry.first_ms, entry.first_msg))
                                .map_err(|e| RiggsError::Store(e.to_string()))?;
                        }
                    }
                    PhishingWrite::Verdict { uid, msg, entry } => {
                        // serde_json writes a non-finite float as null, which would never read back.
                        if !entry.score.is_finite() {
                            return Err(RiggsError::Store(
                                "phishing verdict score is not finite".into(),
                            ));
                        }
                        let mut key = Uuid::now_v7().as_bytes().to_vec();
                        key.extend_from_slice(&uid.to_be_bytes());
                        let json = serde_json::to_vec(&StoredVerdict {
                            msg: *msg,
                            entry: entry.clone(),
                        })
                        .map_err(|e| RiggsError::Store(e.to_string()))?;
                        verdicts
                            .insert(key.as_slice(), self.encode(&json)?.as_slice())
                            .map_err(|e| RiggsError::Store(e.to_string()))?;
                    }
                }
            }
        }
        write_txn
            .commit()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        debug!(count = writes.len(), "stored phishing batch");
        Ok(())
    }

    /// The uid's newest `limit` verdict rows, newest first. One row per `Verdict`
    /// write, so the same `msg` can appear more than once.
    pub fn phishing_verdicts(
        &self,
        uid: u32,
        limit: usize,
    ) -> Result<Vec<StoredVerdict>, RiggsError> {
        let read_txn = self
            .db()
            .begin_read()
            .map_err(|e| RiggsError::Store(e.to_string()))?;
        let table = read_txn
            .open_table(PHISHING_VERDICTS_TABLE)
            .map_err(|e| RiggsError::Store(e.to_string()))?;

        let mut verdicts = Vec::new();
        for row in table
            .iter()
            .map_err(|e| RiggsError::Store(e.to_string()))?
            .rev()
        {
            if verdicts.len() >= limit {
                break;
            }
            let (key, value) = row.map_err(|e| RiggsError::Store(e.to_string()))?;
            if key.value().ends_with(&uid.to_be_bytes()) {
                verdicts.push(
                    serde_json::from_slice(&decode(value.value()))
                        .map_err(|e| RiggsError::Store(e.to_string()))?,
                );
            }
        }
        Ok(verdicts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use riggs_types::phishing::{Level, ObservationKind};

    fn open() -> (RiggsStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("riggs-phishing-test-{}.db", Uuid::now_v7()));
        (RiggsStore::new(&path).unwrap(), path)
    }

    fn login(uid: u32, domain: &str, last_ms: u64, count: u32) -> PhishingWrite {
        PhishingWrite::Login {
            uid,
            entry: LoginEntry {
                domain: domain.into(),
                first_ms: 1,
                last_ms,
                count,
            },
        }
    }

    fn sender(uid: u32, key: &str, first_ms: u64, first_msg: u64) -> PhishingWrite {
        PhishingWrite::Sender {
            uid,
            entry: SenderEntry {
                key: key.into(),
                first_ms,
                first_msg,
            },
        }
    }

    fn verdict_entry(score: f32) -> VerdictEntry {
        VerdictEntry {
            time_ms: 1,
            kind: ObservationKind::Mail,
            domain: "example.com".into(),
            cues: vec!["example_cue".into()],
            score,
            level: Level::Caution,
            shown: true,
        }
    }

    fn verdict(uid: u32, msg: u64) -> PhishingWrite {
        PhishingWrite::Verdict {
            uid,
            msg,
            entry: verdict_entry(0.5),
        }
    }

    fn msgs(verdicts: &[StoredVerdict]) -> Vec<u64> {
        verdicts.iter().map(|v| v.msg).collect()
    }

    #[test]
    fn apply_round_trips_each_kind_of_write() {
        let (store, path) = open();
        store
            .phishing_apply(&[
                login(501, "example.com", 2, 1),
                login(501, "example.org", 3, 1),
                PhishingWrite::ForgetLogin {
                    uid: 501,
                    domain: "example.org".into(),
                },
                sender(501, "example.net", 4, 40),
                verdict(501, 1),
                verdict(501, 2),
            ])
            .unwrap();
        store.phishing_apply(&[verdict(501, 3)]).unwrap();

        let rows = store.phishing_load().unwrap();
        assert_eq!(
            rows.logins,
            vec![(
                501,
                LoginEntry {
                    domain: "example.com".into(),
                    first_ms: 1,
                    last_ms: 2,
                    count: 1,
                }
            )]
        );
        assert_eq!(
            rows.senders,
            vec![(
                501,
                SenderEntry {
                    key: "example.net".into(),
                    first_ms: 4,
                    first_msg: 40,
                }
            )]
        );
        let verdicts = store.phishing_verdicts(501, 10).unwrap();
        assert_eq!(msgs(&verdicts), vec![3, 2, 1]);
        assert_eq!(verdicts[0].entry, verdict_entry(0.5));
        assert_eq!(msgs(&store.phishing_verdicts(501, 2).unwrap()), vec![3, 2]);
        assert!(store.phishing_verdicts(501, 0).unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn login_replaces_sender_keeps_the_first_and_forget_removes_one_row() {
        let (store, path) = open();
        store
            .phishing_apply(&[
                login(501, "example.com", 2, 1),
                login(501, "example.org", 2, 1),
                login(502, "example.com", 2, 1),
                sender(501, "example.net", 10, 100),
                sender(501, "example.net", 15, 150),
            ])
            .unwrap();
        store
            .phishing_apply(&[
                login(501, "example.com", 5, 2),
                sender(501, "example.net", 20, 200),
                sender(501, "example.net", 30, 300),
            ])
            .unwrap();

        let rows = store.phishing_load().unwrap();
        let replaced = rows
            .logins
            .iter()
            .find(|(uid, entry)| *uid == 501 && entry.domain == "example.com")
            .unwrap();
        assert_eq!((replaced.1.last_ms, replaced.1.count), (5, 2));
        assert_eq!(rows.logins.len(), 3);
        assert_eq!(rows.senders.len(), 1);
        assert_eq!(
            (rows.senders[0].1.first_ms, rows.senders[0].1.first_msg),
            (10, 100)
        );

        store
            .phishing_apply(&[
                PhishingWrite::ForgetLogin {
                    uid: 501,
                    domain: "example.com".into(),
                },
                PhishingWrite::ForgetLogin {
                    uid: 501,
                    domain: "example.edu".into(),
                },
            ])
            .unwrap();
        let left: Vec<_> = store
            .phishing_load()
            .unwrap()
            .logins
            .into_iter()
            .map(|(uid, entry)| (uid, entry.domain))
            .collect();
        assert_eq!(
            left,
            vec![(501, "example.org".into()), (502, "example.com".into())]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rows_and_verdicts_stay_with_their_uid() {
        // 1 is a decimal prefix of 10; 1 and 256 share their leading big-endian bytes.
        let uids = [1u32, 10, 256];
        let (store, path) = open();
        let writes: Vec<_> = uids
            .iter()
            .flat_map(|&uid| {
                [
                    login(uid, "example.com", 2, uid),
                    sender(uid, "example.com", 3, u64::from(uid)),
                    verdict(uid, u64::from(uid)),
                ]
            })
            .collect();
        store.phishing_apply(&writes).unwrap();

        let rows = store.phishing_load().unwrap();
        let login_counts: Vec<_> = rows.logins.iter().map(|(uid, e)| (*uid, e.count)).collect();
        assert_eq!(login_counts, vec![(1, 1), (10, 10), (256, 256)]);
        let sender_msgs: Vec<_> = rows
            .senders
            .iter()
            .map(|(uid, e)| (*uid, e.first_msg))
            .collect();
        assert_eq!(sender_msgs, vec![(1, 1), (10, 10), (256, 256)]);
        for uid in uids {
            assert_eq!(
                msgs(&store.phishing_verdicts(uid, 10).unwrap()),
                vec![u64::from(uid)]
            );
        }
        assert!(store.phishing_verdicts(2, 10).unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_failing_write_leaves_nothing_of_its_batch() {
        let (store, path) = open();
        store
            .phishing_apply(&[login(501, "example.com", 2, 1)])
            .unwrap();
        let before = store.phishing_load().unwrap();

        let failing = store.phishing_apply(&[
            login(501, "example.org", 2, 1),
            PhishingWrite::ForgetLogin {
                uid: 501,
                domain: "example.com".into(),
            },
            sender(501, "example.net", 3, 30),
            verdict(501, 1),
            PhishingWrite::Verdict {
                uid: 501,
                msg: 2,
                entry: verdict_entry(f32::NAN),
            },
        ]);

        assert!(failing.is_err());
        assert_eq!(store.phishing_load().unwrap(), before);
        assert!(store.phishing_verdicts(501, 10).unwrap().is_empty());
        store.phishing_apply(&[verdict(501, 3)]).unwrap();
        assert_eq!(msgs(&store.phishing_verdicts(501, 10).unwrap()), vec![3]);
        let _ = std::fs::remove_file(&path);
    }
}
