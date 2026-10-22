# Walkthrough: FILES-003-T04 — Storage Resilience, Retries & HTTP Connection Pooling

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-003-T04`  
**Card**: `FILES-003` (Establish MinIO Object Storage Integration)  
**Branch**: `feature/files-003-Establish-MinIO-object-storage-integration`

`FILES-003-T04` provides enterprise-grade network resilience and socket resource optimization for `S3Client`:
1. **HTTP Keep-Alive Connection Pooling**: Eliminates per-request TCP handshake latency by reusing sockets for consecutive requests to the same host/port.
2. **Transient Error Exponential Backoff with Jitter**: Automatically recovers from transient MinIO restarts, rate limiting, and network glitches (HTTP 500, 502, 503, 504, and socket drop/status 0).
3. **Fail-Fast for Permanent Errors**: Immediately throws on client errors (400, 401, 403, 404) without wasting retries.

---

## 2. Key Components Delivered

### 2.1 S3RetryPolicy (`src/files/storage/s3_client.hpp`, `src/files/storage/s3_client.cpp`)
Configurable retry parameters:
```cpp
struct S3RetryPolicy {
    uint32_t max_retries{3};
    std::chrono::milliseconds initial_backoff{50};
    std::chrono::milliseconds max_backoff{500};
    double jitter_factor{0.2};

    [[nodiscard]] bool is_retryable(int status_code) const noexcept;
    [[nodiscard]] std::chrono::milliseconds calculate_backoff(uint32_t attempt) const noexcept;
};
```
Backoff calculation uses full exponential backoff capped at `max_backoff` with uniform randomized jitter:
$$\text{delay} = \min(\text{initial\_backoff} \times 2^{\text{attempt}-1}, \text{max\_backoff}) \times (1 \pm \text{jitter})$$

### 2.2 DefaultHttpTransport Keep-Alive Socket Reuse (`src/files/storage/s3_client.cpp`)
- Reuses `cached_sock_` if valid and target `(host, port)` matches.
- Issues `Connection: keep-alive` in request headers.
- Inspects response `Content-Length` and reads exactly the declared body payload, preserving socket byte synchronization.
- Re-establishes socket connection automatically if peer closed an idle connection.
- Closes socket cleanly on destructor or when peer sends `Connection: close`.

### 2.3 S3Client::execute_with_retry
Routes all 11 client operations (`ping_bucket`, `object_exists`, `put_object`, `get_object`, `head_object`, `delete_object`, `create_multipart_upload`, `upload_part`, `complete_multipart_upload`, `abort_multipart_upload`, `list_objects`) through retry wrapper.

---

## 3. Verification & Acceptance Criteria
- Unit tested via `SequentialMockHttpTransport` in `tests/unit/files/s3_client_test.cpp`:
  - `RetryPolicyTransientRecovery`: 503 followed by 200 succeeds on attempt 2.
  - `RetryPolicyExhaustion`: 503 x 4 throws `S3ServerException` after retry budget.
  - `NonRetryableErrorFailsImmediately`: 404 throws immediately on attempt 1.
  - `RetryPolicyBackoffCalculation`: Confirmed exponential doubling and status code classification.
