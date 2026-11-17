use redb::TableDefinition;

pub const EVENTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("events");
pub const VERDICTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("verdicts");
pub const QUARANTINE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("quarantine");
pub const CONFIG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("config");
pub const RESPONSE_LOG_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("response_log");
/// (uid, registrable domain) -> (first_ms, last_ms, count)
pub const PHISHING_LOGINS_TABLE: TableDefinition<(u32, &str), (u64, u64, u32)> =
    TableDefinition::new("phishing_logins");
/// (uid, sender key) -> (first_ms, first_msg)
pub const PHISHING_SENDERS_TABLE: TableDefinition<(u32, &str), (u64, u64)> =
    TableDefinition::new("phishing_senders");
/// UUIDv7 (16 bytes) ++ uid big-endian (4 bytes) -> encoded `StoredVerdict` JSON.
/// The UUIDv7 prefix lets retention prune it like the other time-keyed tables.
pub const PHISHING_VERDICTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("phishing_verdicts");
