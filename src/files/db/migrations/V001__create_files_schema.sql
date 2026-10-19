-- V001__create_files_schema.sql
-- SecureCloud Files Service PostgreSQL 17 Relational Schema Baseline
-- M5: Secure Files (Card FILES-002)

CREATE TABLE IF NOT EXISTS files (
    file_id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL,
    owner_device_id UUID NOT NULL,
    conversation_id UUID NULL,
    encrypted_size BIGINT NOT NULL CHECK (encrypted_size >= 0),
    content_type VARCHAR(255) NULL,
    encryption_algorithm VARCHAR(64) NOT NULL DEFAULT 'XChaCha20-Poly1305',
    status VARCHAR(32) NOT NULL DEFAULT 'CREATED'
        CHECK (status IN ('CREATED', 'UPLOADING', 'FINALIZING', 'AVAILABLE', 'EXPIRED', 'DELETED', 'FAILED')),
    retention_until TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_versions (
    version_id UUID PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    version_number INT NOT NULL DEFAULT 1 CHECK (version_number > 0),
    encrypted_size BIGINT NOT NULL CHECK (encrypted_size >= 0),
    minio_object_key VARCHAR(512) NOT NULL,
    checksum_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT uq_file_version UNIQUE(file_id, version_number)
);

CREATE TABLE IF NOT EXISTS encrypted_file_metadata (
    file_id UUID PRIMARY KEY REFERENCES files(file_id) ON DELETE CASCADE,
    encrypted_filename BYTEA NOT NULL,
    encrypted_mime_type BYTEA NULL,
    metadata_nonce BYTEA NOT NULL,
    metadata_tag BYTEA NOT NULL,
    client_encryption_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_transfers (
    transfer_id UUID PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    transfer_type VARCHAR(16) NOT NULL CHECK (transfer_type IN ('UPLOAD', 'DOWNLOAD')),
    initiator_user_id UUID NOT NULL,
    initiator_device_id UUID NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'CREATED'
        CHECK (status IN ('CREATED', 'TRANSFERRING', 'FINALIZING', 'COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED')),
    total_chunks INT NOT NULL CHECK (total_chunks >= 0),
    accepted_chunks INT NOT NULL DEFAULT 0 CHECK (accepted_chunks >= 0),
    total_bytes BIGINT NOT NULL CHECK (total_bytes >= 0),
    transferred_bytes BIGINT NOT NULL DEFAULT 0 CHECK (transferred_bytes >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS file_chunks (
    chunk_id UUID PRIMARY KEY,
    transfer_id UUID NOT NULL REFERENCES file_transfers(transfer_id) ON DELETE CASCADE,
    chunk_index INT NOT NULL CHECK (chunk_index >= 0),
    byte_offset BIGINT NOT NULL CHECK (byte_offset >= 0),
    chunk_size INT NOT NULL CHECK (chunk_size > 0),
    chunk_hash_sha256 VARCHAR(64) NOT NULL,
    minio_chunk_key VARCHAR(512) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'RECEIVED' CHECK (status IN ('RECEIVED', 'COMMITTED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_transfer_chunk UNIQUE(transfer_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS file_access (
    access_id UUID PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    grantee_user_id UUID NOT NULL,
    grantee_device_id UUID NULL,
    permission VARCHAR(32) NOT NULL DEFAULT 'READ' CHECK (permission IN ('READ', 'WRITE', 'ADMIN')),
    granted_by UUID NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ NULL,
    CONSTRAINT uq_file_grantee UNIQUE(file_id, grantee_user_id)
);

CREATE TABLE IF NOT EXISTS files_outbox (
    event_id UUID PRIMARY KEY,
    aggregate_type VARCHAR(32) NOT NULL DEFAULT 'FILE',
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload_json JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED')),
    retry_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ NULL
);

-- Optimized B-Tree and partial indexes
CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_user_id, status);
CREATE INDEX IF NOT EXISTS idx_files_conversation ON files(conversation_id) WHERE conversation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_files_retention ON files(retention_until) WHERE status != 'DELETED';
CREATE INDEX IF NOT EXISTS idx_file_transfers_file ON file_transfers(file_id, status);
CREATE INDEX IF NOT EXISTS idx_file_chunks_transfer ON file_chunks(transfer_id, chunk_index);
CREATE INDEX IF NOT EXISTS idx_files_outbox_pending ON files_outbox(created_at) WHERE status = 'PENDING';
