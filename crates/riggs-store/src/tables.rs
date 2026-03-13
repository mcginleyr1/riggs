use redb::TableDefinition;

pub const EVENTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("events");
pub const VERDICTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("verdicts");
pub const QUARANTINE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("quarantine");
pub const CONFIG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("config");
pub const RESPONSE_LOG_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("response_log");
