#!/bin/sh
set -e

# Shell initialization script for MinIO S3 Object Storage
# Provisions securecloud-files-encrypted bucket and files_minio_user service account.

MINIO_ROOT="${MINIO_ROOT_USER:-minioadmin}"
MINIO_PASS="${MINIO_ROOT_PASSWORD:-minioadmin_dev_secret}"
BUCKET_NAME="${FILES_MINIO_BUCKET:-securecloud-files-encrypted}"
FILES_USER="${FILES_MINIO_USER:-files_minio_user}"
FILES_PASS="${FILES_MINIO_PASSWORD:-files_dev_minio_secret}"

echo "[SecureCloud MinIO Init] Waiting for MinIO S3 endpoint at http://minio:9000..."

# Retry loop waiting for MinIO to respond
until mc alias set local http://minio:9000 "$MINIO_ROOT" "$MINIO_PASS" >/dev/null 2>&1; do
    echo "[SecureCloud MinIO Init] Waiting for MinIO service..."
    sleep 1
done

echo "[SecureCloud MinIO Init] MinIO endpoint reachable. Creating bucket '$BUCKET_NAME'..."
mc mb --ignore-existing "local/$BUCKET_NAME"

echo "[SecureCloud MinIO Init] Creating service account '$FILES_USER'..."
mc admin user add local "$FILES_USER" "$FILES_PASS" || true

echo "[SecureCloud MinIO Init] Attaching readwrite policy to '$FILES_USER'..."
mc admin policy attach local readwrite --user "$FILES_USER" || mc admin policy set local readwrite user="$FILES_USER" || true

echo "[SecureCloud MinIO Init] MinIO initialization complete."
