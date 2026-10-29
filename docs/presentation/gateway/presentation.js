/**
 * SecureCloud Gateway Architecture Presentation Engine
 * Comprehensive interactive presentation logic & data models.
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- State & DOM References ---
    const slides = Array.from(document.querySelectorAll('.slide'));
    const totalSlides = slides.length;
    let currentSlideIndex = 0;

    const progressBar = document.getElementById('progress-bar');
    const slideCounter = document.getElementById('slide-counter');
    const slideDotsContainer = document.getElementById('slide-dots');
    const btnPrev = document.getElementById('btn-prev');
    const btnNext = document.getElementById('btn-next');
    const btnFullscreen = document.getElementById('btn-fullscreen');
    const btnToc = document.getElementById('btn-toc');
    const btnCloseToc = document.getElementById('btn-close-toc');
    const tocModal = document.getElementById('toc-modal');
    const tocList = document.getElementById('toc-list');

    // --- Subsystem Data Model (Slide 3) ---
    const subsystemData = {
        transport: {
            title: "Transport & Network Gatekeeper Subsystem",
            path: "src/gateway/http/server/ & src/gateway/tls/",
            description: "Terminates public network traffic at the external perimeter with strict cryptographic hardening and automatic cleartext redirection.",
            classes: [
                {
                    name: "HttpsServer (httplib::SSLServer)",
                    desc: "Wraps multi-threaded SSL server with RAII lifecycle. Binds to 0.0.0.0:8443, enforcing TLS 1.3 only with AEAD ciphers."
                },
                {
                    name: "TlsHandler (OpenSSL SSL_CTX)",
                    desc: "Configures SSL context: disables SSLv2–TLS 1.2, rejects non-AEAD suites, disables session tickets & compression to eliminate CRIME/BREACH."
                },
                {
                    name: "HttpRedirectServer",
                    desc: "Dedicated listener on port 8080. Intercepts cleartext HTTP and returns HTTP 308 Permanent Redirect with strict HSTS preload."
                },
                {
                    name: "GatewayTlsConfig",
                    desc: "Type-safe TLS configuration model validating certificate paths, private keys, and minimum TLS version at startup."
                }
            ],
            meta: "Security Invariant 1: All external traffic must terminate on TLS 1.3 with AEAD ciphers. Cleartext HTTP never traverses past the redirector."
        },
        perimeter: {
            title: "Perimeter Security & Identity Subsystem",
            path: "src/gateway/http/auth/",
            description: "Validates caller credentials, sanitizes untrusted input, and constructs immutable verified execution contexts before downstream traversal.",
            classes: [
                {
                    name: "HeaderSanitizer",
                    desc: "Zero-allocation in-place mutator stripping spoofed headers (x-user-id, x-device-id, x-auth-level, x-scopes) before middleware execution."
                },
                {
                    name: "BearerTokenExtractor",
                    desc: "RFC 6750 parser extracting Bearer tokens from Authorization headers with strict whitespace and grammar validation."
                },
                {
                    name: "AuthServiceTokenValidator",
                    desc: "Validates sessions via mTLS gRPC against Auth microservice. Features thread-safe 2s bounded LRU cache with eviction."
                },
                {
                    name: "GatewaySecurityPolicy & ScopeMatcher",
                    desc: "Declarative security matrix evaluating route access rules, required OAuth2 scopes (with wildcard support), and MFA assurance."
                }
            ],
            meta: "Security Invariant 3 & 5: Auth Service remains the sole authentication authority. The Gateway fails closed on any token or auth failure."
        },
        resilience: {
            title: "Resilience & Flow-Control Subsystem",
            path: "src/gateway/http/resilience/",
            description: "Protects platform resources from denial-of-service, slow satellite consumers, noisy-neighbor starvation, and cascading outages.",
            classes: [
                {
                    name: "BulkheadManager",
                    desc: "Partitions server concurrency into isolated atomic pools: Auth (100), Messaging (200), Files (50), and Emergency (10 reserved slots)."
                },
                {
                    name: "CircuitBreaker (Nygard FSM)",
                    desc: "Tracks downstream failure rates (UNAVAILABLE, DEADLINE_EXCEEDED). Transitions CLOSED ➔ OPEN ➔ HALF_OPEN to fast-fail in < 1 ms."
                },
                {
                    name: "DeadlineManager",
                    desc: "Ingests client X-Request-Timeout headers, clamps budgets strictly to [50ms, 10000ms], and establishes gRPC call deadlines."
                },
                {
                    name: "RetryPolicy & DrainManager",
                    desc: "Safe exponential backoff with full jitter for idempotent reads. Coordinates graceful drain phase with HTTP 503 Retry-After: 5."
                }
            ],
            meta: "Resilience Invariant: Saturated file transfers never starve rapid authentication or health checks. Outages fail fast without socket exhaustion."
        },
        routing: {
            title: "Routing & Protocol Proxy Subsystem",
            path: "src/gateway/http/routing/ & src/gateway/http/proxy/",
            description: "Dispatches HTTP URIs to strongly typed gRPC stubs while managing in-flight request cancellation guards.",
            classes: [
                {
                    name: "Router & GatewayRouteRegistrar",
                    desc: "O(1) exact-match hash table and parameterized regex path matcher for dynamic endpoints (/api/v1/files/:file_id/chunks/:index)."
                },
                {
                    name: "AuthProxyHandler",
                    desc: "Translates REST/JSON auth calls (/api/v1/auth/login, /me, /device/register) into typed gRPC calls against Auth microservice."
                },
                {
                    name: "FilesProxyHandler",
                    desc: "Translates chunk upload and download requests into gRPC streaming calls against Files microservice."
                },
                {
                    name: "ActiveCallGuard",
                    desc: "Registers in-flight gRPC contexts by request_id. If client disconnects TCP, immediately cancels downstream gRPC storage I/O."
                }
            ],
            meta: "Client Cancellation Invariant: Dropped client connections immediately terminate downstream gRPC calls, preventing wasted database and disk I/O."
        },
        grpc: {
            title: "Downstream gRPC & Channel Management Subsystem",
            path: "src/gateway/grpc/",
            description: "Manages persistent HTTP/2 connections, connection pooling, keepalives, and mutual TLS across internal cluster microservices.",
            classes: [
                {
                    name: "GrpcChannelManager",
                    desc: "Thread-safe channel lifecycle manager. Configures mTLS credentials with cluster root CA, gateway client cert, and private key."
                },
                {
                    name: "SAN Verification Engine",
                    desc: "Overrides SSL target names to strictly match service identities (DNS:auth, DNS:files, DNS:messaging, DNS:audit)."
                },
                {
                    name: "HTTP/2 Keepalive Tuning",
                    desc: "Configures 30s keepalive pings and 10s timeouts (PERMIT_WITHOUT_CALLS=1) to detect dead mesh links instantaneously."
                },
                {
                    name: "ClientCallContext",
                    desc: "RAII wrapper injecting correlation metadata (x-request-id, x-client-service: gateway) and enforcing deadline propagation."
                }
            ],
            meta: "East-West Mesh Security: Internal microservices reject any traffic not originating from a valid mTLS-authenticated peer with approved SAN."
        },
        streaming: {
            title: "Streaming & Cryptographic Integrity Subsystem",
            path: "src/gateway/http/streaming/",
            description: "Executes bounded memory chunk streaming and single-pass cryptographic integrity validation for multi-gigabyte file transfers.",
            classes: [
                {
                    name: "StreamingBuffer",
                    desc: "Bounded FIFO deque buffer (default 8 MiB ceiling, 2 chunks) with dual condition variables (cv_readable_, cv_writable_) for backpressure."
                },
                {
                    name: "Activity Watchdog",
                    desc: "Monitors monotonic read/write timestamps. Triggers StreamStatus::Timeout if no I/O occurs within 30s on stalled satellite links."
                },
                {
                    name: "StreamingSha256Validator",
                    desc: "Single-pass incremental SHA-256 calculation using OpenSSL EVP_MD_CTX. Digests chunk bytes in-flight without re-buffering."
                },
                {
                    name: "Constant-Time Verification",
                    desc: "Uses CRYPTO_memcmp(computed, expected, 32) to prevent side-channel timing attacks leaking hash prefixes."
                }
            ],
            meta: "Bounded Memory Invariant (ADR-010): Gateway memory never exceeds 8 MiB per concurrent streaming transfer, regardless of file size."
        },
        observability: {
            title: "Observability, Diagnostics & Health Subsystem",
            path: "src/gateway/health/ & src/gateway/http/errors/",
            description: "Emits structured diagnostics, enforces secret-free logging invariants, maps RFC 7807 problem details, and serves health probes.",
            classes: [
                {
                    name: "RequestIdMiddleware",
                    desc: "Propagates or generates UUIDv7 correlation IDs, binding HTTP headers, access logs, and downstream gRPC metadata."
                },
                {
                    name: "LoggingMiddleware (Secret-Free)",
                    desc: "Structured JSON logger capturing method, URI, latency, IP, and status. Strictly omits request bodies, tokens, and credentials."
                },
                {
                    name: "ErrorMapper (RFC 7807)",
                    desc: "Standardizes error payloads into application/problem+json. Masks internal database/storage errors behind safe error codes."
                },
                {
                    name: "GatewayHealthEvaluator",
                    desc: "Probes downstream mTLS gRPC connectivity to Auth service, powering /health/live and /health/ready container probes."
                }
            ],
            meta: "Secret-Free Logging Invariant: Zero passwords, bearer tokens, encryption keys, or plaintext payloads ever enter application log streams."
        }
    };

    // --- Pipeline Steps Data Model (Slide 4) ---
    const pipelineSteps = [
        {
            num: 1,
            title: "TLS 1.3 Transport Termination",
            component: "HttpsServer (:8443) & TlsHandler",
            flow: "OS kernel accepts TCP handshake. OpenSSL establishes strict TLS 1.3 session with AEAD cipher (TLS_AES_256_GCM_SHA384).",
            budget: "Latency impact: ~1-2 ms on local/metro, ~80-120 ms over satellite link.",
            reject: "Fails closed at socket level on cleartext or TLS < 1.3 handshakes."
        },
        {
            num: 2,
            title: "UUIDv7 Correlation Ingestion",
            component: "RequestIdMiddleware",
            flow: "Checks for existing X-Request-ID. If absent or invalid, generates a cryptographically unique, time-ordered UUIDv7 and binds it to context.",
            budget: "Latency impact: < 0.05 ms (in-memory UUIDv7 generation).",
            reject: "Malformed IDs replaced with fresh valid UUIDv7; never fails."
        },
        {
            num: 3,
            title: "Transport Resource Bounds Verification",
            component: "ResourceLimiterMiddleware",
            flow: "Validates header size <= 16 KiB and body size <= 10 MiB. Atomically increments active connections guard (max 1024).",
            budget: "Latency impact: < 0.1 ms (atomic integer & header size check).",
            reject: "HTTP 431 Request Header Fields Too Large / HTTP 413 Payload Too Large / HTTP 503 Concurrency Max."
        },
        {
            num: 4,
            title: "Perimeter Sanitization & Token Verification",
            component: "HeaderSanitizer & AuthenticationMiddleware",
            flow: "Strips spoofed X-User-Id headers. Extracts Bearer token. Checks 2s LRU cache; on miss, validates session via mTLS gRPC against Auth microservice.",
            budget: "Latency impact: ~0.1 ms (cache hit) / ~3-5 ms (mTLS gRPC validation miss).",
            reject: "HTTP 401 UNAUTHENTICATED / TOKEN_EXPIRED / SESSION_REVOKED. HTTP 503 if Auth unreachable."
        },
        {
            num: 5,
            title: "Token-Bucket Rate Limiting",
            component: "RateLimiterMiddleware",
            flow: "Retrieves token bucket associated with verified user_id (or client IP). Consumes token if available; updates leak rate.",
            budget: "Latency impact: < 0.1 ms (thread-safe hash table with mutex).",
            reject: "HTTP 429 TOO_MANY_REQUESTS with Retry-After header."
        },
        {
            num: 6,
            title: "Workload Bulkhead & Circuit Breaker Check",
            component: "BulkheadManager & CircuitBreaker",
            flow: "Acquires concurrency lease for workload (Auth: 100, Msg: 200, Files: 50). Verifies downstream circuit breaker is not OPEN.",
            budget: "Latency impact: < 0.05 ms (atomic counter & FSM state check).",
            reject: "HTTP 503 BULKHEAD_LIMIT_EXCEEDED or HTTP 503 CIRCUIT_BREAKER_OPEN (< 1 ms fast-fail)."
        },
        {
            num: 7,
            title: "Deadline Clamping & Downstream mTLS gRPC",
            component: "DeadlineManager, GrpcChannelManager, ActiveCallGuard",
            flow: "Clamps client deadline to [50ms, 10s]. Dispatches typed protobuf RPC over persistent HTTP/2 channel. Cancels RPC if client drops socket.",
            budget: "Latency impact: Downstream service execution (~5-50 ms).",
            reject: "Downstream errors mapped via ErrorMapper. Safe reads retried up to 3 times on transient UNAVAILABLE."
        },
        {
            num: 8,
            title: "RFC 7807 Response & RAII Resource Release",
            component: "ErrorMapper, LoggingMiddleware, RAII Guards",
            flow: "Serializes JSON response with X-Request-ID. Emits secret-free access log. Decrements active connections and releases bulkhead lease.",
            budget: "Latency impact: < 0.2 ms (JSON serialization & socket flush).",
            reject: "HTTP 200 OK on success, or RFC 7807 Problem Details on mapped application errors."
        }
    ];

    // --- Render Slide Dots ---
    slides.forEach((slide, idx) => {
        const dot = document.createElement('div');
        dot.classList.add('slide-dot');
        if (idx === 0) dot.classList.add('active');
        dot.title = `Slide ${idx + 1}: ${slide.dataset.title}`;
        dot.addEventListener('click', () => goToSlide(idx));
        slideDotsContainer.appendChild(dot);

        // Add to TOC
        const tocItem = document.createElement('li');
        tocItem.classList.add('toc-item');
        const formattedNum = (idx + 1) < 10 ? `0${idx + 1}` : `${idx + 1}`;
        tocItem.innerHTML = `
            <span class="toc-num">${formattedNum}</span>
            <span class="toc-title">${slide.dataset.title}</span>
        `;
        tocItem.addEventListener('click', () => {
            goToSlide(idx);
            closeToc();
        });
        tocList.appendChild(tocItem);
    });

    const slideDots = Array.from(document.querySelectorAll('.slide-dot'));

    // --- Navigation Logic ---
    function goToSlide(index) {
        if (index < 0 || index >= totalSlides) return;

        slides[currentSlideIndex].classList.remove('active');
        slideDots[currentSlideIndex].classList.remove('active');

        currentSlideIndex = index;

        slides[currentSlideIndex].classList.add('active');
        slides[currentSlideIndex].scrollTop = 0;
        slideDots[currentSlideIndex].classList.add('active');

        // Update Counter & Progress Bar
        slideCounter.textContent = `Slide ${currentSlideIndex + 1} of ${totalSlides}`;
        const progressPercent = ((currentSlideIndex + 1) / totalSlides) * 100;
        progressBar.style.width = `${progressPercent}%`;

        // Update Prev / Next Buttons state
        btnPrev.disabled = currentSlideIndex === 0;
        btnNext.disabled = currentSlideIndex === totalSlides - 1;
    }

    btnPrev.addEventListener('click', () => goToSlide(currentSlideIndex - 1));
    btnNext.addEventListener('click', () => goToSlide(currentSlideIndex + 1));

    // --- Keyboard Navigation ---
    document.addEventListener('keydown', (e) => {
        if (tocModal.classList.contains('active')) {
            if (e.key === 'Escape') closeToc();
            return;
        }

        switch (e.key) {
            case 'ArrowRight':
            case 'PageDown':
            case ' ':
                e.preventDefault();
                goToSlide(currentSlideIndex + 1);
                break;
            case 'ArrowLeft':
            case 'PageUp':
                e.preventDefault();
                goToSlide(currentSlideIndex - 1);
                break;
            case 'Home':
                e.preventDefault();
                goToSlide(0);
                break;
            case 'End':
                e.preventDefault();
                goToSlide(totalSlides - 1);
                break;
            case 'f':
            case 'F':
                toggleFullscreen();
                break;
            case 'm':
            case 'M':
                toggleToc();
                break;
            default:
                if (e.key >= '1' && e.key <= '9') {
                    goToSlide(parseInt(e.key) - 1);
                }
        }
    });

    // --- Fullscreen Toggle ---
    function toggleFullscreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(err => console.error(err));
        } else {
            if (document.exitFullscreen) {
                document.exitFullscreen();
            }
        }
    }
    btnFullscreen.addEventListener('click', toggleFullscreen);

    // --- TOC Modal ---
    function openToc() { tocModal.classList.add('active'); }
    function closeToc() { tocModal.classList.remove('active'); }
    function toggleToc() { tocModal.classList.toggle('active'); }
    btnToc.addEventListener('click', openToc);
    btnCloseToc.addEventListener('click', closeToc);
    tocModal.addEventListener('click', (e) => {
        if (e.target === tocModal) closeToc();
    });

    // --- Slide 3: Gateway Subsystem Explorer ---
    const gatewaySubsystemTabs = document.querySelectorAll('.subsystem-tabs .sub-tab:not(.auth-sub-tab)');
    const gatewaySubsystemDetail = document.getElementById('subsystem-detail');

    function renderGatewaySubsystem(key) {
        const sub = subsystemData[key];
        if (!sub || !gatewaySubsystemDetail) return;

        gatewaySubsystemDetail.innerHTML = `
            <div class="detail-title-group">
                <h3>${sub.title}</h3>
                <div class="detail-source-path">${sub.path}</div>
            </div>
            <p style="color: var(--text-secondary); font-size: 0.92rem; line-height: 1.5;">${sub.description}</p>
            <div class="detail-classes-grid">
                ${sub.classes.map(c => `
                    <div class="class-card">
                        <h4>${c.name}</h4>
                        <p>${c.desc}</p>
                    </div>
                `).join('')}
            </div>
            <div class="detail-meta-box">
                <strong>Architectural Invariant:</strong> ${sub.meta}
            </div>
        `;
    }

    gatewaySubsystemTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            gatewaySubsystemTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            renderGatewaySubsystem(tab.dataset.sub);
        });
    });

    // Initial render for gateway subsystem (transport)
    renderGatewaySubsystem('transport');

    // --- Slide 4: Interactive Gateway Request Pipeline ---
    const gatewayPipelineNodes = document.querySelectorAll('.pipeline-track .pipeline-node:not(.auth-pipeline-node)');
    const gatewayPipelineCard = document.getElementById('pipeline-step-card');

    function renderGatewayPipelineStep(stepNum) {
        const step = pipelineSteps.find(s => s.num === stepNum);
        if (!step || !gatewayPipelineCard) return;

        gatewayPipelineCard.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.8rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.75rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <span class="badge badge-blue">STEP 0${step.num} OF 08</span>
                    <h3 style="font-family: var(--font-heading); font-size: 1.3rem; color: #fff;">${step.title}</h3>
                </div>
                <span style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--accent-emerald);">${step.component}</span>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
                <div>
                    <h5 style="color: var(--accent-blue); font-size: 0.82rem; font-family: var(--font-mono); margin-bottom: 0.4rem; text-transform: uppercase;">In-Flight Execution Flow</h5>
                    <p style="color: #cbd5e1; font-size: 0.88rem; line-height: 1.5;">${step.flow}</p>
                </div>
                <div>
                    <div style="margin-bottom: 0.75rem;">
                        <h5 style="color: var(--accent-amber); font-size: 0.82rem; font-family: var(--font-mono); margin-bottom: 0.3rem; text-transform: uppercase;">Latency & Budget</h5>
                        <p style="color: var(--text-secondary); font-size: 0.84rem;">${step.budget}</p>
                    </div>
                    <div>
                        <h5 style="color: var(--accent-red); font-size: 0.82rem; font-family: var(--font-mono); margin-bottom: 0.3rem; text-transform: uppercase;">Fail-Closed Security Rejection</h5>
                        <p style="color: var(--text-secondary); font-size: 0.84rem;">${step.reject}</p>
                    </div>
                </div>
            </div>
        `;
    }

    gatewayPipelineNodes.forEach(node => {
        node.addEventListener('click', () => {
            gatewayPipelineNodes.forEach(n => n.classList.remove('active'));
            node.classList.add('active');
            renderGatewayPipelineStep(parseInt(node.dataset.step));
        });
    });

    // Initial render for gateway pipeline step 1
    renderGatewayPipelineStep(1);

    // =========================================================================
    // AUTH SERVICE INTERACTIVE DATA & CONTROLLERS (SLIDES 9 & 10)
    // =========================================================================

    const authSubsystemData = {
        auth_facade: {
            title: "gRPC Protocol & Service Facade Subsystem",
            path: "src/auth/service/ & proto/securecloud/auth/v1/",
            description: "Terminates internal mutual TLS mesh traffic, manages gRPC ServerContext, orchestrates asynchronous threadpool task dispatch, and exposes the public signing key.",
            classes: [
                {
                    name: "AuthServiceImpl",
                    desc: "Central gRPC handler implementing LoginWithPassword, RefreshToken, VerifyMfaTotp, RegisterDevice, and GetPrekeyBundle."
                },
                {
                    name: "GrpcServerContext & SAN Validator",
                    desc: "Validates caller peer certificate SAN (DNS:gateway, DNS:messaging). Rejects unauthorized services with PERMISSION_DENIED."
                },
                {
                    name: "AuthServerConfig",
                    desc: "Type-safe configuration loader enforcing PostgreSQL port 5433, mTLS certificate paths, and Argon2id execution parameters."
                },
                {
                    name: "AuthHealthService",
                    desc: "Implements standard gRPC Health Checking Protocol (v1). Evaluates PostgreSQL connection pool health before reporting SERVING."
                }
            ],
            meta: "ADR-001 & ADR-005: Auth listens strictly on internal mTLS port 50051. Public clients cannot connect directly."
        },
        auth_crypto: {
            title: "Credential Verification & Cryptographic Engine",
            path: "src/auth/credential/ & src/auth/crypto/",
            description: "Implements memory-hard password verification, asymmetric Ed25519 digital signature generation, and constant-time verifier comparisons.",
            classes: [
                {
                    name: "CredentialVerifier (Argon2id)",
                    desc: "Hybrid memory-hard password hashing (t=3, m=64MB, p=4). Evaluates verifiers in dedicated worker threads to prevent gRPC starvation."
                },
                {
                    name: "Ed25519Signer (Twisted Edwards)",
                    desc: "Operates on -x^2 + y^2 = 1 - (121665/121666)x^2 y^2 over F(2^255-19). Signs access token envelopes with 64-byte deterministic signatures."
                },
                {
                    name: "ConstantTimeComparator",
                    desc: "Wraps CRYPTO_memcmp to compare password verifiers, token hashes, and recovery codes in constant time, defeating timing attacks."
                },
                {
                    name: "TokenEnvelopeSerializer",
                    desc: "Compact base64url serialization: base64url(header) . base64url(claims) . base64url(signature). Validated without secret keys."
                }
            ],
            meta: "ADR-004 & ADR-005: Memory-hard hashing prevents GPU offline attacks. Ed25519 private key never leaves the Auth enclave."
        },
        auth_session: {
            title: "Session & Token Rotation Lifecycle Subsystem",
            path: "src/auth/session/",
            description: "Manages session persistence, issues short-lived access tokens, rotates single-use refresh tokens, and executes cascading invalidation on theft.",
            classes: [
                {
                    name: "SessionManager",
                    desc: "Creates, retrieves, and invalidates session entities. Binds user UUID, device UUID, creation timestamp, and expiration TTL."
                },
                {
                    name: "TokenManager & Rotator",
                    desc: "Issues single-use 256-bit refresh tokens. Hashes tokens with SHA-256 before database insertion; raw token is returned once."
                },
                {
                    name: "ReplayAttackDetector",
                    desc: "If an already-consumed refresh token is presented, detects token theft and triggers instant cascading revocation of all user sessions."
                },
                {
                    name: "TokenEnvelopeValidator",
                    desc: "Parses and verifies Ed25519 signatures, expiration timestamps, issuer identity, and token scopes."
                }
            ],
            meta: "ADR-006: Rotating refresh tokens guarantee that stolen credentials result in automatic session family invalidation upon first replay."
        },
        auth_mfa: {
            title: "Multi-Factor Authentication & Enclave Subsystem",
            path: "src/auth/mfa/",
            description: "Implements RFC 6238 TOTP verification, AES-256-GCM envelope encryption for seeds, clock skew tolerance, and single-use recovery codes.",
            classes: [
                {
                    name: "TotpEngine (RFC 6238)",
                    desc: "Computes HMAC-SHA1 over 30-second time steps. Supports +/-1 step drift tolerance with replay prevention cache."
                },
                {
                    name: "EnvelopeEncryptionEngine",
                    desc: "Encrypts raw TOTP secret seeds with AES-256-GCM using hardware-protected master key and 96-bit random IV before database write."
                },
                {
                    name: "RecoveryCodeManager",
                    desc: "Generates 16-character high-entropy recovery codes. Stores strictly as Argon2id hashes; marks codes as consumed upon redemption."
                },
                {
                    name: "MfaChallengeTracker",
                    desc: "Issues short-lived (5-min) ephemeral mfa_tokens upon valid password verification, requiring TOTP resolution before final token grant."
                }
            ],
            meta: "Security Invariant: TOTP seeds are never stored in plaintext. Recovery codes are memory-hard hashed and permanently consumable."
        },
        auth_device: {
            title: "Device Trust & Cross-Device Pairing Subsystem",
            path: "src/auth/device/",
            description: "Tracks physical hardware identity, manages device trust states, coordinates cross-device pairing code exchanges, and enforces device revocation.",
            classes: [
                {
                    name: "DeviceManager",
                    desc: "Maintains registered device records, platform metadata, public key bindings, trust states (ACTIVE, PENDING, REVOKED)."
                },
                {
                    name: "PairingCodeExchange",
                    desc: "Generates 6-digit cryptographic pairing codes with 10-minute expiration. Authenticated primary devices approve pending new hardware."
                },
                {
                    name: "DeviceRevocationGuard",
                    desc: "Instantly terminates all active sessions associated with a revoked device and marks prekeys as ineligible for new handshakes."
                },
                {
                    name: "DeviceFingerprintValidator",
                    desc: "Verifies device UUIDv7 and hardware identity attributes, preventing device impersonation across network shifts."
                }
            ],
            meta: "Hardware Trust Invariant: Every session is cryptographically bound to a physical device UUID; revoking a device purges all its sessions."
        },
        auth_prekeys: {
            title: "Signal X3DH & PQXDH Prekey Inventory Subsystem",
            path: "src/auth/prekey/",
            description: "Acts as the authoritative public key directory for Signal protocol handshakes. Manages signed prekeys, one-time prekeys, and atomic consumption.",
            classes: [
                {
                    name: "PrekeyManager",
                    desc: "Assembles complete cryptographic prekey bundles: Identity Key (IK), Signed Prekey (SPK), SPK Signature, and One-Time Prekey (OPK)."
                },
                {
                    name: "PrekeyValidator",
                    desc: "Validates Ed25519 signatures on signed prekeys during upload, ensuring clients cannot upload tampered public keys."
                },
                {
                    name: "AtomicPrekeyClaimer",
                    desc: "Executes SELECT ... FOR UPDATE SKIP LOCKED on the one-time prekeys table, atomically claiming an OPK without multi-thread contention."
                },
                {
                    name: "PrekeyInventoryMonitor",
                    desc: "Monitors device OPK counts. When available keys drop below threshold (e.g. < 25), dispatches replenishment prompts to client."
                }
            ],
            meta: "ADR-008 & ADR-009: Prekey directory stores only public keys; private keys remain on device. Atomic claims eliminate race collisions."
        },
        auth_db: {
            title: "PostgreSQL 17 Persistence & Connection Subsystem",
            path: "src/auth/database/",
            description: "Provides ACID relational persistence with strict port 5433 enforcement, connection pooling, and automated schema migration management.",
            classes: [
                {
                    name: "PostgresConnectionPool (Port 5433)",
                    desc: "Thread-safe RAII connection pool wrapping libpqxx. Fails closed immediately if configured with port 5432 or 5434."
                },
                {
                    name: "MigrationRunner (V1 through V4)",
                    desc: "Applies transactional schema migrations on daemon startup: users, credentials, sessions, devices, MFA, and prekeys."
                },
                {
                    name: "SkipLockedExecutor",
                    desc: "Specialized query runner for high-concurrency atomic prekey acquisition without serialization deadlocks."
                },
                {
                    name: "DatabaseHealthProbe",
                    desc: "Executes SELECT 1 on pooled connections every 10 seconds to detect database outages and update service readiness."
                }
            ],
            meta: "ADR-003: Strict port isolation prevents Auth from ever communicating with non-Auth database instances."
        }
    };

    const authPipelineSteps = [
        {
            num: 1,
            title: "Primary Authentication Flow",
            component: "LoginWithPassword RPC",
            flow: "Client submits email/username + password. Auth fetches verifier from PostgreSQL 5433, computes Argon2id in worker thread, compares verifiers in constant time, and signs Ed25519 token.",
            budget: "Latency impact: ~50-70 ms (dominated by memory-hard Argon2id calculation).",
            reject: "HTTP 401 / UNAUTHENTICATED on invalid password or account lockout."
        },
        {
            num: 2,
            title: "Single-Use Token Rotation Flow",
            component: "RefreshToken RPC",
            flow: "Client presents rotating refresh token. Auth hashes token (SHA-256), validates against active sessions, marks old token consumed, issues fresh token pair, and commits atomically.",
            budget: "Latency impact: ~3-5 ms (single indexed PostgreSQL transaction).",
            reject: "If token was previously consumed, triggers Token Reuse Cascade: invalidates entire session tree immediately."
        },
        {
            num: 3,
            title: "MFA TOTP Challenge Flow",
            component: "VerifyMfaTotp RPC",
            flow: "Client presents 6-digit TOTP code and ephemeral mfa_token. Auth decrypts AES-256-GCM seed with master key, verifies time step (+/-1 window), caches code to prevent replay, and issues full session.",
            budget: "Latency impact: ~2-4 ms (AES-256-GCM decryption + HMAC-SHA1).",
            reject: "HTTP 401 on incorrect code or expired/replayed TOTP window."
        },
        {
            num: 4,
            title: "Device Pairing Code Exchange",
            component: "InitiatePairing & ConfirmPairing",
            flow: "New hardware requests pairing code (6-digit numeric, 10-min TTL). User confirms on existing active device. Auth cryptographically binds new device UUID to user account.",
            budget: "Latency impact: ~2-3 ms per handshake phase.",
            reject: "HTTP 404 / EXPIRED on timeout; rejected if confirmed by unauthorized device."
        },
        {
            num: 5,
            title: "Signal X3DH Prekey Bundle Claim",
            component: "GetPrekeyBundle RPC",
            flow: "Sender requests prekey bundle for recipient device. Auth fetches Identity Key + Signed Prekey, and claims One-Time Prekey atomically using SELECT ... FOR UPDATE SKIP LOCKED.",
            budget: "Latency impact: ~2-4 ms (zero lock contention via SKIP LOCKED).",
            reject: "Returns bundle without OPK if one-time prekeys are exhausted; triggers replenishment alert."
        }
    ];

    // --- Slide 9: Auth Subsystem Explorer Handlers ---
    const authSubsystemTabs = document.querySelectorAll('.auth-sub-tab');
    const authSubsystemDetail = document.getElementById('auth-subsystem-detail');

    function renderAuthSubsystem(key) {
        const sub = authSubsystemData[key];
        if (!sub || !authSubsystemDetail) return;

        authSubsystemDetail.innerHTML = `
            <div class="detail-title-group">
                <h3>${sub.title}</h3>
                <div class="detail-source-path">${sub.path}</div>
            </div>
            <p style="color: var(--text-secondary); font-size: 0.92rem; line-height: 1.5;">${sub.description}</p>
            <div class="detail-classes-grid">
                ${sub.classes.map(c => `
                    <div class="class-card">
                        <h4>${c.name}</h4>
                        <p>${c.desc}</p>
                    </div>
                `).join('')}
            </div>
            <div class="detail-meta-box">
                <strong>Architectural Invariant:</strong> ${sub.meta}
            </div>
        `;
    }

    authSubsystemTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            authSubsystemTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            renderAuthSubsystem(tab.dataset.sub);
        });
    });

    // Initial render for Auth subsystem
    renderAuthSubsystem('auth_facade');

    // --- Slide 10: Auth Interactive Pipeline Handlers ---
    const authPipelineNodes = document.querySelectorAll('.auth-pipeline-node');
    const authPipelineCard = document.getElementById('auth-pipeline-step-card');

    function renderAuthPipelineStep(stepNum) {
        const step = authPipelineSteps.find(s => s.num === stepNum);
        if (!step || !authPipelineCard) return;

        authPipelineCard.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.8rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.75rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <span class="badge badge-purple">FLOW 0${step.num} OF 05</span>
                    <h3 style="font-family: var(--font-heading); font-size: 1.3rem; color: #fff;">${step.title}</h3>
                </div>
                <span style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--accent-blue);">${step.component}</span>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
                <div>
                    <h5 style="color: var(--accent-blue); font-size: 0.82rem; font-family: var(--font-mono); margin-bottom: 0.4rem; text-transform: uppercase;">Cryptographic State Transition</h5>
                    <p style="color: #cbd5e1; font-size: 0.88rem; line-height: 1.5;">${step.flow}</p>
                </div>
                <div>
                    <div style="margin-bottom: 0.75rem;">
                        <h5 style="color: var(--accent-amber); font-size: 0.82rem; font-family: var(--font-mono); margin-bottom: 0.3rem; text-transform: uppercase;">Timing & Complexity Budget</h5>
                        <p style="color: var(--text-secondary); font-size: 0.84rem;">${step.budget}</p>
                    </div>
                    <div>
                        <h5 style="color: var(--accent-red); font-size: 0.82rem; font-family: var(--font-mono); margin-bottom: 0.3rem; text-transform: uppercase;">Rejection & Security Cascade</h5>
                        <p style="color: var(--text-secondary); font-size: 0.84rem;">${step.reject}</p>
                    </div>
                </div>
            </div>
        `;
    }

    authPipelineNodes.forEach(node => {
        node.addEventListener('click', () => {
            authPipelineNodes.forEach(n => n.classList.remove('active'));
            node.classList.add('active');
            renderAuthPipelineStep(parseInt(node.dataset.step));
        });
    });

    // Initial render for Auth pipeline step 1
    renderAuthPipelineStep(1);

    // =========================================================================
    // MESSAGING SERVICE INTERACTIVE DATA & CONTROLLERS (SLIDES 16 & 18)
    // =========================================================================

    const messagingSubsystemData = {
        msg_facade: {
            title: "gRPC Protocol Facade & Anti-Impersonation Gateway",
            path: "src/messaging/service/ & proto/securecloud/messaging/v1/",
            description: "Terminates internal mutual TLS mesh traffic, validates caller identity against gRPC security context, enforces zero-knowledge payload invariants, and provides fast validation.",
            classes: [
                {
                    name: "MessagingServiceImpl",
                    desc: "Central gRPC handler implementing SendMessage, AcknowledgeDelivery, MarkMessageRead, SyncMessages, and StreamIncomingMessages."
                },
                {
                    name: "MessagingCallerContext",
                    desc: "Binds verified x-user-id and x-device-id from Gateway mTLS headers. Detects and rejects caller impersonation in < 0.05 ms."
                },
                {
                    name: "SubmissionValidator & ProtocolVersionPolicy",
                    desc: "Verifies Signal PQXDH envelope headers, recipient device completeness, and executes anti-plaintext heuristic checks."
                },
                {
                    name: "ZeroPlaintextGuard",
                    desc: "Enforces ADR-008: Audits memory buffers ensuring zero unencrypted text, identity keys, or ratchet states ever cross daemon boundaries."
                }
            ],
            meta: "ADR-008 & INV-M01: Messaging is a blind courier. Payloads are opaque ciphertext; server has mathematically zero decryption keys."
        },
        msg_sequencing: {
            title: "Monotonic Sequencer & Idempotency Engine",
            path: "src/messaging/service/ & src/messaging/domain/",
            description: "Allocates gapless monotonic sequence numbers per conversation-month partition and enforces lock-striped idempotency deduplication.",
            classes: [
                {
                    name: "ConversationSequenceAllocator",
                    desc: "Atomic sequence allocator generating monotonically increasing 64-bit integers per (conversation_id, YYYY-MM) bucket."
                },
                {
                    name: "InMemorySequenceAllocator",
                    desc: "High-performance sequence allocator achieving 82 µs P50 latency with thread-safe atomic counters and durable checkpointing."
                },
                {
                    name: "MessageSubmissionIdempotencyGuard",
                    desc: "Lock-striped LRU idempotency cache. Duplicate client tokens yield cached sequence without duplicate database row insertion."
                },
                {
                    name: "SubmissionFingerprint",
                    desc: "Cryptographic hash of (conversation_id, sender_device_id, client_token) ensuring tamper-evident replay prevention."
                }
            ],
            meta: "ADR-007: Sequence numbers are strictly monotonic per conversation month. Gaps and backward regressions are mathematically impossible."
        },
        msg_storage: {
            title: "ScyllaDB Monthly Partition Repository Subsystem",
            path: "src/messaging/repository/ & src/messaging/domain/message_bucket.cpp",
            description: "Delivers Cassandra-native, high-throughput persistence partitioned into monthly buckets ((conversation_id, YYYY-MM), seq ASC) with zero ALLOW FILTERING.",
            classes: [
                {
                    name: "ScyllaMessageRepository",
                    desc: "Persists immutable message envelopes into messages_by_conversation with bounded partition sizing (max 100k msgs / ~50 MB per bucket)."
                },
                {
                    name: "ScyllaDeliveryStateRepository",
                    desc: "Tracks per-recipient-device delivery states (Queued, Delivering, Delivered, Expired) indexed by ((device_id, bucket), time ASC)."
                },
                {
                    name: "ScyllaConversationRepository & Membership",
                    desc: "Resolves active conversation rosters and participant device mappings with sub-millisecond local partition lookups."
                },
                {
                    name: "CQL Zero-Filter Auditor",
                    desc: "100% of prepared queries target primary partition keys and secondary indexed message_id; zero full-table scans exist."
                }
            ],
            meta: "ADR-005 & ADR-007: Direct ScyllaDB port 9042 access is exclusive to Messaging. Monthly partitioning prevents hot-partition tombstone degradation."
        },
        msg_delivery: {
            title: "Bounded Delivery Scheduler & Fair Priority Queue",
            path: "src/messaging/delivery/",
            description: "Coordinates 3-tier prioritized delivery dispatching across active devices using Fair Deficit Round-Robin and drop-to-durable backpressure.",
            classes: [
                {
                    name: "BoundedDeliveryScheduler",
                    desc: "Manages 3-tier priority queues: Emergency (Priority 0 bypass) > Delivery (Priority 1 DRR) > Sync (Priority 2 yield). Bounded to 1000 tasks/dev."
                },
                {
                    name: "DeliveryWorker Pool",
                    desc: "Multi-threaded worker pool executing non-blocking network dispatches with 5s timeout protection and exponential backoff retries."
                },
                {
                    name: "DurableDeliveryRecoveryService",
                    desc: "On service cold start, scans pending deliveries and reconstructs in-memory scheduler state in 4.33 ms (SLA <= 500 ms)."
                },
                {
                    name: "OutboxDeliveryConsumer",
                    desc: "Transactional dual-write processor ensuring zero message loss between conversation persistence and delivery queueing."
                }
            ],
            meta: "ADR-010: Bounded queues prevent out-of-memory crashes. Saturated memory queues safely drop excess tasks to durable ScyllaDB outbox."
        },
        msg_connection: {
            title: "Device Connection Registry & Fast-Track Push",
            path: "src/messaging/delivery/ & src/messaging/service/",
            description: "Maintains real-time device connection sessions, provides sub-2ms direct gRPC bi-directional streaming push, and manages channel leases.",
            classes: [
                {
                    name: "DeviceConnectionRegistry",
                    desc: "Thread-safe lease registry binding physical device UUIDs to active gRPC streaming channels. Zero-allocation lookup optimization."
                },
                {
                    name: "RealtimeDeliveryAccelerator",
                    desc: "Bypasses scheduler queues upon device connect: directly pushes pending envelopes over active socket in 1.24 ms (P50 = 24.9 µs)."
                },
                {
                    name: "ConnectionLifecycleManager",
                    desc: "Tracks heartbeats and lease expiries. Runs automated background reaper sweeping 50 stale channels in 0.052 ms."
                },
                {
                    name: "PresenceCoordinator",
                    desc: "Computes mutual conversation presence status while shielding stranger queries with synthetic OFFLINE states (zero privacy leaks)."
                }
            ],
            meta: "Fast-Track Invariant: Online recipient devices receive messages via memory fast-track without waiting for batch scheduler polling."
        },
        msg_status: {
            title: "Delivery & Read Acknowledgment Tracker Subsystem",
            path: "src/messaging/service/ & src/messaging/domain/",
            description: "Implements decoupled, orthogonal state transitions enforcing the Non-Conflation Axiom (DeliveredAt != ReadAt) and monotonic cursor sync.",
            classes: [
                {
                    name: "DeliveryService",
                    desc: "Processes affirmative device ACKs, transitions transport state to Delivered, and emits audit notifications."
                },
                {
                    name: "ReadReceiptService",
                    desc: "Orthogonal user-action tracker recording explicit read receipts without altering underlying transport delivery states."
                },
                {
                    name: "DeliveryStateTransitionGuard",
                    desc: "Monotonic state machine validator preventing backward state regressions (e.g. Delivered cannot revert to Queued)."
                },
                {
                    name: "MessageSyncService & SyncCursorManager",
                    desc: "Coordinates historical catch-up queries using monotonic sequence watermarks; processes 100-msg batches in 846 µs."
                }
            ],
            meta: "Non-Conflation Axiom: Delivery is a network event; Read is a user action. The two states are strictly orthogonal and decoupled."
        }
    };

    // --- Slide 16: Messaging Subsystem Explorer Handlers ---
    const msgSubsystemTabs = document.querySelectorAll('.msg-sub-tab');
    const msgSubsystemDetail = document.getElementById('msg-subsystem-detail');

    function renderMsgSubsystem(key) {
        const sub = messagingSubsystemData[key];
        if (!sub || !msgSubsystemDetail) return;

        msgSubsystemDetail.innerHTML = `
            <div class="detail-title-group">
                <h3>${sub.title}</h3>
                <div class="detail-source-path">${sub.path}</div>
            </div>
            <p style="color: var(--text-secondary); font-size: 0.92rem; line-height: 1.5;">${sub.description}</p>
            <div class="detail-classes-grid">
                ${sub.classes.map(c => `
                    <div class="class-card">
                        <h4>${c.name}</h4>
                        <p>${c.desc}</p>
                    </div>
                `).join('')}
            </div>
            <div class="detail-meta-box" style="border-left-color: var(--accent-emerald);">
                <strong>Architectural Invariant:</strong> ${sub.meta}
            </div>
        `;

        // Highlight matching node in animated SVG if present
        document.querySelectorAll('.svg-subsystem-node').forEach(node => {
            if (node.dataset.sub === key) {
                node.classList.add('active-svg-subsystem');
            } else {
                node.classList.remove('active-svg-subsystem');
            }
        });
    }

    msgSubsystemTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            msgSubsystemTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            renderMsgSubsystem(tab.dataset.sub);
        });
    });

    // Initial render for Messaging subsystem
    renderMsgSubsystem('msg_facade');

    // Initial navigation state
    goToSlide(0);
});
