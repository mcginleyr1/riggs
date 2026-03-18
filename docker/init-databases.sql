-- Databases created on first postgres startup.
-- Meta DB is the main Ecto repo; tenant DBs are created dynamically
-- by the ShardManager, but we pre-create the dev demo tenant here.

CREATE DATABASE murtaugh_meta;
CREATE DATABASE murtaugh_tenant_demo;

-- Enable TimescaleDB extension in both databases.
-- This must happen as the superuser before Ecto migrations run.
\c murtaugh_meta
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

\c murtaugh_tenant_demo
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Return to default db
\c postgres
