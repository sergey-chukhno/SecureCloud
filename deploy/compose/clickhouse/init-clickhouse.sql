-- Bootstrap initialization script for ClickHouse 24.8
-- Provisions securecloud_audit database and unprivileged audit_user service account.

CREATE DATABASE IF NOT EXISTS securecloud_audit;
CREATE USER IF NOT EXISTS audit_user IDENTIFIED WITH sha256_password BY 'audit_dev_db_secret';
GRANT ALL ON securecloud_audit.* TO audit_user;
