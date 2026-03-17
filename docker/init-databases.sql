-- Databases created on first postgres startup.
-- Meta DB is the main Ecto repo; tenant DBs are created dynamically
-- by the ShardManager, but we pre-create the dev demo tenant here.

CREATE DATABASE murtaugh_meta;
CREATE DATABASE murtaugh_tenant_demo;
