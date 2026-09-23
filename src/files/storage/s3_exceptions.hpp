#pragma once

#include <stdexcept>
#include <string>

namespace securecloud::files::storage {

/// Base exception for all MinIO S3 storage client operations
class S3ClientException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// Thrown when the target S3 bucket is not found (HTTP 404 on bucket endpoint)
class S3BucketNotFoundException : public S3ClientException {
    using S3ClientException::S3ClientException;
};

/// Thrown when S3 credentials or SigV4 signature is rejected (HTTP 403 Forbidden)
class S3AuthenticationException : public S3ClientException {
    using S3ClientException::S3ClientException;
};

/// Thrown when a specific object key is not found in the bucket
class S3ObjectNotFoundException : public S3ClientException {
    using S3ClientException::S3ClientException;
};

/// Thrown when TCP network connection or HTTP transport to S3 endpoint fails
class S3ConnectionException : public S3ClientException {
    using S3ClientException::S3ClientException;
};

} // namespace securecloud::files::storage
