CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
