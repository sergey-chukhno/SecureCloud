#!/usr/bin/env python3
"""
SecureCloud Backend Services Performance & Load Benchmark Harness (Docker Compose)

Runs 6 empirical benchmark groups against a live, clean Docker Compose stack:
  1. Gateway TLS 1.3 Baseline & Concurrency Scaling (/health/live, /health/ready, fresh TLS)
  2. Auth Service (PostgreSQL): Login (Argon2id), JWT validation (/users/me), Refresh, Crypto Directory
  3. Messaging Service (ScyllaDB): Durable submit (256B & 4KiB), Catch-up sync, Delivery ACKs
  4. Files Service (PostgreSQL + MinIO): Chunked encrypted upload & download (64KiB, 1MiB, 5MiB)
  5. Audit Service (ClickHouse): Async outbox/spool ingestion drain & investigation query latency
  6. Container Resource Footprint (docker stats): Idle, Peak Load, and Post-Load CPU & RAM

Zero external Python dependencies (Python 3.9+ stdlib only).
"""

import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
import platform
import ssl
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COMPOSE_FILE = os.path.join(REPO_ROOT, "deploy", "compose", "docker-compose.yml")
CA_CERT_PATH = os.path.join(REPO_ROOT, "deploy", "dev-pki", "ca", "ca.crt")

ALICE_EMAIL = os.environ.get("DEMO_ALICE_EMAIL", "alice@securecloud.local")
ALICE_PASSWORD = os.environ.get("DEMO_ALICE_PASSWORD", "AliceDemo#2026")
BOB_EMAIL = os.environ.get("DEMO_BOB_EMAIL", "bob@securecloud.local")
BOB_PASSWORD = os.environ.get("DEMO_BOB_PASSWORD", "BobDemo#2026")

GATEWAY_HOST = os.environ.get("SECURECLOUD_GATEWAY_HOST", "127.0.0.1")
GATEWAY_PORT = int(os.environ.get("GATEWAY_HTTPS_HOST_PORT", "8443"))

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "127.0.0.1")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_HTTP_HOST_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("AUDIT_DB_USER", "audit_user")
CLICKHOUSE_PASSWORD = os.environ.get("AUDIT_DB_PASSWORD", "audit_dev_db_secret")
CLICKHOUSE_DB = os.environ.get("AUDIT_DB_NAME", "securecloud_audit")


def percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int((pct / 100.0) * len(sorted_vals)))
    return sorted_vals[idx]


def summarize_latencies(latencies_ms: List[float], total_wall_s: float, errors: int, total_reqs: int) -> Dict[str, Any]:
    s = sorted(latencies_ms)
    ok = len(s)
    return {
        "total_requests": total_reqs,
        "succeeded": ok,
        "errors": errors,
        "error_rate_pct": round((errors / total_reqs) * 100.0, 3) if total_reqs > 0 else 0.0,
        "wall_seconds": round(total_wall_s, 3),
        "throughput_rps": round(ok / total_wall_s, 2) if total_wall_s > 0 else 0.0,
        "mean_ms": round(statistics.fmean(s), 3) if s else 0.0,
        "p50_ms": round(percentile(s, 50.0), 3) if s else 0.0,
        "p95_ms": round(percentile(s, 95.0), 3) if s else 0.0,
        "p99_ms": round(percentile(s, 99.0), 3) if s else 0.0,
        "max_ms": round(s[-1], 3) if s else 0.0,
        "min_ms": round(s[0], 3) if s else 0.0,
    }


_CURL_BRIDGE_C = r"""
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* data;
    size_t len;
    size_t cap;
} Buf;

static size_t write_cb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t n = size * nmemb;
    Buf* b = (Buf*)userdata;
    if (b->len + n + 1 > b->cap) {
        size_t new_cap = (b->cap == 0) ? 4096 : b->cap * 2;
        while (new_cap < b->len + n + 1) new_cap *= 2;
        char* p = (char*)realloc(b->data, new_cap);
        if (!p) return 0;
        b->data = p;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

void sc_curl_global_init(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

void* sc_curl_new(void) {
    return (void*)curl_easy_init();
}

void sc_curl_free(void* h) {
    if (h) curl_easy_cleanup((CURL*)h);
}

int sc_curl_request(
    void* h,
    const char* method,
    const char* url,
    const char* ca_cert,
    const char* const* headers,
    int header_count,
    const char* body,
    size_t body_len,
    int keep_alive,
    long timeout_sec,
    long* out_status,
    char** out_body,
    size_t* out_body_len
) {
    CURL* curl = (CURL*)h;
    curl_easy_reset(curl);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_sec);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (!keep_alive) {
        curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
        curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
    }

    struct curl_slist* slist = NULL;
    slist = curl_slist_append(slist, "Expect:");
    for (int i = 0; i < header_count; ++i) {
        slist = curl_slist_append(slist, headers[i]);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
    } else if (strcmp(method, "GET") != 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        if (body && body_len > 0) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
        }
    }

    Buf resp = {NULL, 0, 0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(slist);

    if (rc != CURLE_OK) {
        free(resp.data);
        *out_status = 0;
        *out_body = NULL;
        *out_body_len = 0;
        return (int)rc;
    }

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    *out_status = code;
    *out_body = resp.data;
    *out_body_len = resp.len;
    return 0;
}

void sc_curl_free_buf(char* p) {
    free(p);
}
"""

_CURL_LIB = None


def _load_curl_bridge():
    global _CURL_LIB
    if _CURL_LIB is not None:
        return _CURL_LIB
    import ctypes

    c_path = "/tmp/sc_bench_curl_bridge.c"
    so_path = "/tmp/sc_bench_curl_bridge.dylib"
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(_CURL_BRIDGE_C)
    subprocess.check_call(["clang", "-O2", "-shared", "-fPIC", c_path, "-lcurl", "-o", so_path])
    lib = ctypes.CDLL(so_path)
    lib.sc_curl_global_init.argtypes = []
    lib.sc_curl_global_init.restype = None
    lib.sc_curl_new.argtypes = []
    lib.sc_curl_new.restype = ctypes.c_void_p
    lib.sc_curl_free.argtypes = [ctypes.c_void_p]
    lib.sc_curl_free.restype = None
    lib.sc_curl_free_buf.argtypes = [ctypes.c_void_p]
    lib.sc_curl_free_buf.restype = None
    lib.sc_curl_request.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_long,
        ctypes.POINTER(ctypes.c_long),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.sc_curl_request.restype = ctypes.c_int
    lib.sc_curl_global_init()
    _CURL_LIB = lib
    return lib


def make_ssl_context(ca_cert: str) -> Any:
    ctx = ssl.create_default_context(cafile=ca_cert)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = True
        return ctx
    except ValueError:
        # Stock macOS Python links LibreSSL 2.8.3 (no TLS 1.3). Use native libcurl TLS 1.3 bridge.
        _load_curl_bridge()
        return {"mode": "libcurl", "ca_cert": ca_cert}


class KeepAliveClient:
    """Thread-local persistent HTTPS/1.1 connection over TLS 1.3."""

    def __init__(self, host: str, port: int, ssl_ctx: Any, timeout: float = 30.0):
        self.host = host
        self.port = port
        self.ssl_ctx = ssl_ctx
        self.timeout = timeout
        self._conn: Optional[http.client.HTTPSConnection] = None
        self._curl_handle = None
        if isinstance(ssl_ctx, dict) and ssl_ctx.get("mode") == "libcurl":
            self._curl_handle = _load_curl_bridge().sc_curl_new()

    def _ensure_conn(self) -> http.client.HTTPSConnection:
        if self._conn is None:
            self._conn = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=self.ssl_ctx
            )
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
        if self._curl_handle is not None:
            try:
                _load_curl_bridge().sc_curl_free(self._curl_handle)
            except Exception:
                pass
            self._curl_handle = None

    def request(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        keep_alive: bool = True,
    ) -> Tuple[int, bytes, Dict[str, str]]:
        if self._curl_handle is not None:
            import ctypes

            lib = _load_curl_bridge()
            url = f"https://{self.host}:{self.port}{path}".encode("utf-8")
            ca = self.ssl_ctx["ca_cert"].encode("utf-8")
            hdr_list = [f"{k}: {v}".encode("utf-8") for k, v in (headers or {}).items()]
            c_hdrs = (ctypes.c_char_p * len(hdr_list))(*hdr_list) if hdr_list else None
            c_status = ctypes.c_long(0)
            c_out_ptr = ctypes.c_void_p(0)
            c_out_len = ctypes.c_size_t(0)
            b_bytes = body if body is not None else b""
            rc = lib.sc_curl_request(
                self._curl_handle,
                method.encode("ascii"),
                url,
                ca,
                c_hdrs,
                len(hdr_list),
                b_bytes if body is not None else None,
                len(b_bytes),
                1 if keep_alive else 0,
                int(self.timeout),
                ctypes.byref(c_status),
                ctypes.byref(c_out_ptr),
                ctypes.byref(c_out_len),
            )
            if rc != 0:
                raise RuntimeError(f"libcurl error code {rc}")
            data = ctypes.string_at(c_out_ptr.value, c_out_len.value) if c_out_ptr.value and c_out_len.value > 0 else b""
            if c_out_ptr.value:
                lib.sc_curl_free_buf(c_out_ptr)
            return int(c_status.value), data, {}

        hdrs = dict(headers or {})
        hdrs["Connection"] = "keep-alive" if keep_alive else "close"
        if body is not None and "Content-Length" not in hdrs:
            hdrs["Content-Length"] = str(len(body))

        for attempt in range(2):
            conn = self._ensure_conn()
            try:
                conn.request(method, path, body=body, headers=hdrs)
                resp = conn.getresponse()
                data = resp.read()
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                status = resp.status
                if not keep_alive or resp_headers.get("connection", "").lower() == "close":
                    self.close()
                return status, data, resp_headers
            except (http.client.RemoteDisconnected, http.client.CannotSendRequest, ConnectionResetError, BrokenPipeError):
                self.close()
                if attempt == 1:
                    raise
        raise RuntimeError("Unreachable")


def run_concurrent_load(
    workers: int,
    total_requests: int,
    ssl_ctx: ssl.SSLContext,
    req_builder,
    keep_alive: bool = True,
    expected_statuses: Tuple[int, ...] = (200, 201, 202),
) -> Dict[str, Any]:
    latencies: List[float] = []
    errors = 0
    error_samples: List[str] = []
    lock = threading.Lock()

    per_worker = [total_requests // workers + (1 if i < (total_requests % workers) else 0) for i in range(workers)]

    def worker_fn(worker_idx: int, count: int) -> None:
        nonlocal errors
        client = KeepAliveClient(GATEWAY_HOST, GATEWAY_PORT, ssl_ctx)
        local_lats: List[float] = []
        local_errs = 0
        local_samples: List[str] = []
        try:
            for seq in range(count):
                method, path, body, headers = req_builder(worker_idx, seq)
                t0 = time.perf_counter()
                try:
                    status, data, _ = client.request(method, path, body=body, headers=headers, keep_alive=keep_alive)
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    if status in expected_statuses:
                        local_lats.append(elapsed_ms)
                    else:
                        local_errs += 1
                        if len(local_samples) < 3:
                            local_samples.append(f"HTTP {status}: {data[:160].decode('utf-8', 'replace')}")
                except Exception as exc:
                    local_errs += 1
                    if len(local_samples) < 3:
                        local_samples.append(repr(exc))
        finally:
            client.close()
        with lock:
            latencies.extend(local_lats)
            errors += local_errs
            if len(error_samples) < 5:
                error_samples.extend(local_samples[: 5 - len(error_samples)])

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(worker_fn, i, c) for i, c in enumerate(per_worker) if c > 0]
        for f in futs:
            f.result()
    wall_s = time.perf_counter() - t_start

    res = summarize_latencies(latencies, wall_s, errors, total_requests)
    if error_samples:
        res["error_samples"] = error_samples
    return res


def clickhouse_query(sql: str) -> Tuple[str, float]:
    url_path = "/?database=" + urllib.parse.quote(CLICKHOUSE_DB)
    auth_raw = f"{CLICKHOUSE_USER}:{CLICKHOUSE_PASSWORD}".encode("utf-8")
    headers = {
        "Authorization": "Basic " + base64.b64encode(auth_raw).decode("ascii"),
        "Content-Type": "text/plain; charset=utf-8",
    }
    t0 = time.perf_counter()
    conn = http.client.HTTPConnection(CLICKHOUSE_HOST, CLICKHOUSE_PORT, timeout=15.0)
    try:
        conn.request("POST", url_path, body=sql.encode("utf-8"), headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if resp.status != 200:
            raise RuntimeError(f"ClickHouse HTTP {resp.status}: {body[:200]}")
        return body.strip(), elapsed_ms
    finally:
        conn.close()


def capture_docker_stats() -> Dict[str, Dict[str, Any]]:
    cmd = [
        "docker",
        "stats",
        "--no-stream",
        "--format",
        "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.PIDs}}",
    ]
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    stats: Dict[str, Dict[str, Any]] = {}
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        name, cpu_s, mem_usage, mem_pct, net_io, pids = parts[:6]
        if not name.startswith("securecloud-"):
            continue
        short_name = name.replace("securecloud-", "").rsplit("-", 1)[0]
        cpu_val = float(cpu_s.strip().rstrip("%") or "0")
        mem_used_raw = mem_usage.split("/")[0].strip()
        mem_mib = _parse_size_mib(mem_used_raw)
        stats[short_name] = {
            "container": name,
            "cpu_pct": round(cpu_val, 2),
            "mem_used_mib": round(mem_mib, 2),
            "mem_usage_raw": mem_usage.strip(),
            "mem_pct": mem_pct.strip(),
            "net_io": net_io.strip(),
            "pids": int(pids.strip() or "0"),
        }
    return stats


def _parse_size_mib(val: str) -> float:
    val = val.strip()
    if val.endswith("GiB"):
        return float(val[:-3]) * 1024.0
    if val.endswith("MiB"):
        return float(val[:-3])
    if val.endswith("KiB"):
        return float(val[:-3]) / 1024.0
    if val.endswith("GB"):
        return float(val[:-2]) * 953.674
    if val.endswith("MB"):
        return float(val[:-2]) * 0.953674
    if val.endswith("kB"):
        return float(val[:-2]) / 1048.576
    if val.endswith("B"):
        return float(val[:-1]) / (1024.0 * 1024.0)
    return 0.0


def collect_environment_metadata() -> Dict[str, Any]:
    def sh(cmd: List[str]) -> str:
        try:
            return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            return "unknown"

    mem_bytes = sh(["sysctl", "-n", "hw.memsize"])
    mem_gib = round(int(mem_bytes) / (1024**3), 1) if mem_bytes.isdigit() else 0.0
    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cpu_model": sh(["sysctl", "-n", "machdep.cpu.brand_string"]),
        "logical_cores": sh(["sysctl", "-n", "hw.ncpu"]),
        "host_ram_gib": mem_gib,
        "os": f"{platform.system()} {platform.mac_ver()[0]} ({platform.machine()})",
        "docker_version": sh(["docker", "--version"]),
        "docker_compose_version": sh(["docker", "compose", "version"]),
        "docker_cpus": sh(["docker", "info", "--format", "{{.NCPU}}"]),
        "docker_mem_bytes": sh(["docker", "info", "--format", "{{.MemTotal}}"]),
        "python_version": platform.python_version(),
        "openssl_version": ssl.OPENSSL_VERSION,
        "gateway_endpoint": f"https://{GATEWAY_HOST}:{GATEWAY_PORT}",
    }


def login_user(client: KeepAliveClient, email: str, password: str) -> Dict[str, Any]:
    body = json.dumps({"identifier": email, "credential": password}).encode("utf-8")
    status, data, _ = client.request(
        "POST", "/api/v1/auth/login", body=body, headers={"Content-Type": "application/json"}
    )
    if status != 200:
        raise RuntimeError(f"Login failed for {email}: HTTP {status} {data.decode('utf-8', 'replace')}")
    return json.loads(data.decode("utf-8"))


def _generate_signed_device_bundle() -> Tuple[str, str, str]:
    """Generate a real Ed25519 identity keypair and sign a 32-byte X25519 signed prekey via OpenSSL."""
    import tempfile

    openssl_bin = "/opt/homebrew/opt/openssl@3/bin/openssl"
    if not os.path.exists(openssl_bin):
        openssl_bin = "openssl"
    with tempfile.TemporaryDirectory() as td:
        priv_pem = os.path.join(td, "ik.pem")
        pub_der = os.path.join(td, "ik.der")
        spk_bin = os.path.join(td, "spk.bin")
        sig_bin = os.path.join(td, "sig.bin")
        subprocess.check_call([openssl_bin, "genpkey", "-algorithm", "ED25519", "-out", priv_pem], stderr=subprocess.DEVNULL)
        subprocess.check_call([openssl_bin, "pkey", "-in", priv_pem, "-pubout", "-outform", "DER", "-out", pub_der], stderr=subprocess.DEVNULL)
        with open(pub_der, "rb") as f:
            ik_pub = f.read()[-32:]  # Ed25519 SubjectPublicKeyInfo DER ends with raw 32-byte public key
        spk_bytes = os.urandom(32)
        with open(spk_bin, "wb") as f:
            f.write(spk_bytes)
        subprocess.check_call([openssl_bin, "pkeyutl", "-sign", "-inkey", priv_pem, "-rawin", "-in", spk_bin, "-out", sig_bin], stderr=subprocess.DEVNULL)
        with open(sig_bin, "rb") as f:
            sig_bytes = f.read()
        return ik_pub.hex(), spk_bytes.hex(), sig_bytes.hex()


def register_device(client: KeepAliveClient, token: str, user_id: str) -> str:
    ik_hex, spk_hex, sig_hex = _generate_signed_device_bundle()
    payload = {
        "user_id": user_id,
        "identity_key": ik_hex,
        "signed_prekey": spk_hex,
        "signed_prekey_signature": sig_hex,
        "one_time_prekeys": [os.urandom(32).hex() for _ in range(10)],
    }
    status, data, _ = client.request(
        "POST",
        "/api/v1/devices",
        body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    if status not in (200, 201):
        raise RuntimeError(f"Device registration failed: HTTP {status} {data.decode('utf-8', 'replace')}")
    return json.loads(data.decode("utf-8"))["device_id"]


def create_direct_conversation(client: KeepAliveClient, token: str, peer_user_id: str) -> str:
    payload = {"type": "direct", "participant_user_ids": [peer_user_id]}
    status, data, _ = client.request(
        "POST",
        "/api/v1/conversations",
        body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    if status not in (200, 201):
        raise RuntimeError(f"Create conversation failed: HTTP {status} {data.decode('utf-8', 'replace')}")
    j = json.loads(data.decode("utf-8"))
    conv = j.get("conversation", j)
    return conv["conversation_id"]


def benchmark_group_1_gateway(ssl_ctx: ssl.SSLContext) -> Dict[str, Any]:
    print("\n=== Group 1: Gateway TLS 1.3 Baseline & Concurrency Scaling ===", flush=True)
    results: Dict[str, Any] = {}

    def live_builder(_w: int, _s: int):
        return "GET", "/health/live", None, {}

    def ready_builder(_w: int, _s: int):
        return "GET", "/health/ready", None, {}

    for workers, count in [(1, 200), (10, 500), (25, 500), (50, 500)]:
        r = run_concurrent_load(workers, count, ssl_ctx, live_builder, keep_alive=True)
        results[f"health_live_keepalive_c{workers}"] = r
        print(
            f"  /health/live (keep-alive, c={workers:2d}, n={count}): "
            f"{r['throughput_rps']:7.1f} req/s | p50={r['p50_ms']:.2f}ms p95={r['p95_ms']:.2f}ms p99={r['p99_ms']:.2f}ms | err={r['errors']}",
            flush=True,
        )

    r_ready = run_concurrent_load(10, 200, ssl_ctx, ready_builder, keep_alive=True)
    results["health_ready_keepalive_c10"] = r_ready
    print(
        f"  /health/ready (keep-alive, c=10, n=200): "
        f"{r_ready['throughput_rps']:7.1f} req/s | p50={r_ready['p50_ms']:.2f}ms p95={r_ready['p95_ms']:.2f}ms p99={r_ready['p99_ms']:.2f}ms | err={r_ready['errors']}",
        flush=True,
    )

    for workers, count in [(1, 60), (10, 150)]:
        r_tls = run_concurrent_load(workers, count, ssl_ctx, live_builder, keep_alive=False)
        results[f"health_live_fresh_tls13_c{workers}"] = r_tls
        print(
            f"  /health/live (fresh TLS1.3, c={workers:2d}, n={count}): "
            f"{r_tls['throughput_rps']:7.1f} req/s | p50={r_tls['p50_ms']:.2f}ms p95={r_tls['p95_ms']:.2f}ms p99={r_tls['p99_ms']:.2f}ms | err={r_tls['errors']}",
            flush=True,
        )

    return results


def benchmark_group_2_auth(
    ssl_ctx: Any, alice_token: str, alice_refresh: str, alice_device_id_from_login: str, bob_user_id: str
) -> Tuple[Dict[str, Any], str]:
    print("\n=== Group 2: Auth Service (PostgreSQL) ===", flush=True)
    results: Dict[str, Any] = {}

    login_body = json.dumps({"identifier": ALICE_EMAIL, "credential": ALICE_PASSWORD}).encode("utf-8")

    def login_builder(_w: int, _s: int):
        return "POST", "/api/v1/auth/login", login_body, {"Content-Type": "application/json"}

    for workers, count in [(1, 10), (5, 25)]:
        r = run_concurrent_load(workers, count, ssl_ctx, login_builder, keep_alive=True)
        results[f"auth_login_argon2id_c{workers}"] = r
        print(
            f"  POST /api/v1/auth/login (Argon2id, c={workers:2d}, n={count}): "
            f"{r['throughput_rps']:6.1f} req/s | p50={r['p50_ms']:.2f}ms p95={r['p95_ms']:.2f}ms p99={r['p99_ms']:.2f}ms | err={r['errors']}",
            flush=True,
        )

    auth_hdr = {"Authorization": f"Bearer {alice_token}"}

    def devices_builder(_w: int, _s: int):
        return "GET", "/api/v1/devices", None, auth_hdr

    for workers, count in [(1, 150), (10, 400)]:
        r = run_concurrent_load(workers, count, ssl_ctx, devices_builder, keep_alive=True)
        results[f"auth_devices_jwt_c{workers}"] = r
        print(
            f"  GET  /api/v1/devices (JWT + Auth PG, c={workers:2d}, n={count}): "
            f"{r['throughput_rps']:6.1f} req/s | p50={r['p50_ms']:.2f}ms p95={r['p95_ms']:.2f}ms p99={r['p99_ms']:.2f}ms | err={r['errors']}",
            flush=True,
        )

    # Sequential rotating refresh token test
    refresh_lats: List[float] = []
    refresh_errs = 0
    cur_refresh = alice_refresh
    cur_access = alice_token
    client = KeepAliveClient(GATEWAY_HOST, GATEWAY_PORT, ssl_ctx)
    t0_wall = time.perf_counter()
    try:
        for _ in range(30):
            body = json.dumps({"refresh_token": cur_refresh, "device_id": alice_device_id_from_login}).encode("utf-8")
            t0 = time.perf_counter()
            st, data, _ = client.request(
                "POST", "/api/v1/auth/refresh", body=body, headers={"Content-Type": "application/json"}
            )
            elapsed = (time.perf_counter() - t0) * 1000.0
            if st == 200:
                j = json.loads(data.decode("utf-8"))
                cur_refresh = j.get("refresh_token", cur_refresh)
                cur_access = j.get("access_token", cur_access)
                refresh_lats.append(elapsed)
            else:
                refresh_errs += 1
    finally:
        client.close()
    r_ref = summarize_latencies(refresh_lats, time.perf_counter() - t0_wall, refresh_errs, 30)
    results["auth_refresh_rotating_c1"] = r_ref
    print(
        f"  POST /api/v1/auth/refresh (rotating, c= 1, n=30): "
        f"{r_ref['throughput_rps']:6.1f} req/s | p50={r_ref['p50_ms']:.2f}ms p95={r_ref['p95_ms']:.2f}ms max={r_ref['max_ms']:.2f}ms | err={r_ref['errors']}",
        flush=True,
    )

    dir_hdr = {"Authorization": f"Bearer {cur_access}"}
    dir_path = f"/api/v1/users/{urllib.parse.quote(bob_user_id)}/devices/crypto-directory"

    def dir_builder(_w: int, _s: int):
        return "GET", dir_path, None, dir_hdr

    for workers, count in [(1, 100), (10, 300)]:
        r = run_concurrent_load(workers, count, ssl_ctx, dir_builder, keep_alive=True)
        results[f"auth_crypto_directory_c{workers}"] = r
        print(
            f"  GET  /api/v1/users/.../crypto-directory (c={workers:2d}, n={count}): "
            f"{r['throughput_rps']:6.1f} req/s | p50={r['p50_ms']:.2f}ms p95={r['p95_ms']:.2f}ms p99={r['p99_ms']:.2f}ms | err={r['errors']}",
            flush=True,
        )

    return results, cur_access


def benchmark_group_3_messaging(
    ssl_ctx: ssl.SSLContext,
    alice_token: str,
    bob_token: str,
    bob_user_id: str,
    bob_device_id: str,
    conversation_id: str,
    peak_stats_holder: Dict[str, Any],
) -> Dict[str, Any]:
    print("\n=== Group 3: Messaging Service (ScyllaDB) ===", flush=True)
    results: Dict[str, Any] = {}

    eph_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    iv_b64 = base64.b64encode(os.urandom(12)).decode("ascii")
    tag_b64 = base64.b64encode(os.urandom(16)).decode("ascii")
    ct_256_b64 = base64.b64encode(os.urandom(256)).decode("ascii")
    ct_4k_b64 = base64.b64encode(os.urandom(4096)).decode("ascii")

    sent_message_ids: List[str] = []
    sent_lock = threading.Lock()

    def run_send_bench(workers: int, count: int, ct_b64: str, label: str, capture_peak: bool = False) -> Dict[str, Any]:
        latencies: List[float] = []
        errors = 0
        error_samples: List[str] = []
        lock = threading.Lock()
        per_worker = [count // workers + (1 if i < (count % workers) else 0) for i in range(workers)]
        stop_sampler = threading.Event()

        def sampler_fn():
            time.sleep(0.4)
            if not stop_sampler.is_set():
                try:
                    peak_stats_holder["messaging_peak"] = capture_docker_stats()
                except Exception:
                    pass

        sampler_thread = None
        if capture_peak:
            sampler_thread = threading.Thread(target=sampler_fn, daemon=True)
            sampler_thread.start()

        def worker_fn(w_idx: int, n_reqs: int) -> None:
            nonlocal errors
            client = KeepAliveClient(GATEWAY_HOST, GATEWAY_PORT, ssl_ctx)
            local_lats: List[float] = []
            local_errs = 0
            local_ids: List[str] = []
            local_samples: List[str] = []
            try:
                for seq in range(n_reqs):
                    idemp = f"bench-{label}-{w_idx}-{seq}-{uuid.uuid4().hex[:8]}"
                    payload = {
                        "conversation_id": conversation_id,
                        "client_idempotency_token": idemp,
                        "idempotency_token": idemp,
                        "priority": "normal",
                        "delivery_targets": [
                            {
                                "recipient_user_id": bob_user_id,
                                "recipient_device_id": bob_device_id,
                                "encrypted_payload": {
                                    "ciphertext_blob": ct_b64,
                                    "ephemeral_public_key": eph_b64,
                                    "initialization_vector": iv_b64,
                                    "auth_tag": tag_b64,
                                    "algorithm": "AES-256-GCM",
                                },
                            }
                        ],
                    }
                    body = json.dumps(payload).encode("utf-8")
                    hdrs = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {alice_token}",
                        "X-Idempotency-Token": idemp,
                    }
                    t0 = time.perf_counter()
                    try:
                        st, data, _ = client.request("POST", "/api/v1/messages", body=body, headers=hdrs)
                        elapsed = (time.perf_counter() - t0) * 1000.0
                        if st in (200, 201, 202):
                            local_lats.append(elapsed)
                            if len(local_ids) < 25:
                                try:
                                    mid = json.loads(data.decode("utf-8")).get("message_id")
                                    if mid:
                                        local_ids.append(mid)
                                except Exception:
                                    pass
                        else:
                            local_errs += 1
                            if len(local_samples) < 3:
                                local_samples.append(f"HTTP {st}: {data[:160].decode('utf-8', 'replace')}")
                    except Exception as exc:
                        local_errs += 1
                        if len(local_samples) < 3:
                            local_samples.append(repr(exc))
            finally:
                client.close()

            with lock:
                latencies.extend(local_lats)
                errors += local_errs
                if len(error_samples) < 5:
                    error_samples.extend(local_samples[: 5 - len(error_samples)])
            with sent_lock:
                if len(sent_message_ids) < 120:
                    sent_message_ids.extend(local_ids[: 120 - len(sent_message_ids)])

        t_start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(worker_fn, i, c) for i, c in enumerate(per_worker) if c > 0]
            for f in futs:
                f.result()
        wall_s = time.perf_counter() - t_start
        stop_sampler.set()
        if sampler_thread is not None:
            sampler_thread.join(timeout=5.0)

        res = summarize_latencies(latencies, wall_s, errors, count)
        if error_samples:
            res["error_samples"] = error_samples
        return res

    for workers, count in [(1, 100), (10, 400), (25, 500)]:
        r = run_send_bench(workers, count, ct_256_b64, f"256b_c{workers}", capture_peak=(workers == 25))
        results[f"msg_submit_256b_c{workers}"] = r
        print(
            f"  POST /api/v1/messages (256B, c={workers:2d}, n={count}): "
            f"{r['throughput_rps']:6.1f} msg/s | p50={r['p50_ms']:.2f}ms p95={r['p95_ms']:.2f}ms p99={r['p99_ms']:.2f}ms | err={r['errors']}",
            flush=True,
        )

    r_4k = run_send_bench(10, 300, ct_4k_b64, "4kib_c10")
    results["msg_submit_4kib_c10"] = r_4k
    print(
        f"  POST /api/v1/messages (4KiB, c=10, n=300): "
        f"{r_4k['throughput_rps']:6.1f} msg/s | p50={r_4k['p50_ms']:.2f}ms p95={r_4k['p95_ms']:.2f}ms p99={r_4k['p99_ms']:.2f}ms | err={r_4k['errors']}",
        flush=True,
    )

    # Catch-up sync (Bob reading conversation messages)
    sync_path = (
        f"/api/v1/conversations/{urllib.parse.quote(conversation_id)}/messages"
        f"?device_id={urllib.parse.quote(bob_device_id)}&limit=50"
    )
    bob_hdr = {"Authorization": f"Bearer {bob_token}"}

    def sync_builder(_w: int, _s: int):
        return "GET", sync_path, None, bob_hdr

    for workers, count in [(1, 50), (10, 200)]:
        r = run_concurrent_load(workers, count, ssl_ctx, sync_builder, keep_alive=True)
        results[f"msg_sync_limit50_c{workers}"] = r
        print(
            f"  GET  /api/v1/conversations/.../messages (limit=50, c={workers:2d}, n={count}): "
            f"{r['throughput_rps']:6.1f} req/s | p50={r['p50_ms']:.2f}ms p95={r['p95_ms']:.2f}ms p99={r['p99_ms']:.2f}ms | err={r['errors']}",
            flush=True,
        )

    # Delivery ACKs by Bob on 100 real messages
    ack_ids = sent_message_ids[:100]
    ack_count = len(ack_ids)
    ack_idx_lock = threading.Lock()
    ack_pos = [0]

    def ack_builder(_w: int, _s: int):
        with ack_idx_lock:
            idx = ack_pos[0]
            ack_pos[0] += 1
        mid = ack_ids[idx % ack_count]
        payload = {
            "recipient_device_id": bob_device_id,
            "device_id": bob_device_id,
            "delivered_at_unix_ms": int(time.time() * 1000),
        }
        return (
            "POST",
            f"/api/v1/messages/{urllib.parse.quote(mid)}/ack",
            json.dumps(payload).encode("utf-8"),
            {"Content-Type": "application/json", "Authorization": f"Bearer {bob_token}"},
        )

    if ack_count > 0:
        r_ack = run_concurrent_load(10, ack_count, ssl_ctx, ack_builder, keep_alive=True)
        results["msg_delivery_ack_c10"] = r_ack
        print(
            f"  POST /api/v1/messages/.../ack (c=10, n={ack_count}): "
            f"{r_ack['throughput_rps']:6.1f} ack/s | p50={r_ack['p50_ms']:.2f}ms p95={r_ack['p95_ms']:.2f}ms p99={r_ack['p99_ms']:.2f}ms | err={r_ack['errors']}",
            flush=True,
        )

    return results


def benchmark_group_4_files(
    ssl_ctx: ssl.SSLContext,
    alice_token: str,
    alice_user_id: str,
    alice_device_id: str,
    conversation_id: str,
    peak_stats_holder: Dict[str, Any],
) -> Dict[str, Any]:
    print("\n=== Group 4: Files Service (PostgreSQL + MinIO) ===", flush=True)
    results: Dict[str, Any] = {}
    client = KeepAliveClient(GATEWAY_HOST, GATEWAY_PORT, ssl_ctx, timeout=60.0)
    auth_hdr = {"Authorization": f"Bearer {alice_token}"}

    workloads = [
        ("64kib", 64 * 1024, 64 * 1024, 10),
        ("1mib", 1024 * 1024, 1024 * 1024, 5),
        ("5mib", 5 * 1024 * 1024, 4 * 1024 * 1024, 3),
    ]

    try:
        for label, total_bytes, chunk_size, iters in workloads:
            upload_ms_list: List[float] = []
            download_ms_list: List[float] = []
            total_ms_list: List[float] = []
            errors = 0
            integrity_ok = 0
            error_samples: List[str] = []

            for i in range(iters):
                raw_blob = os.urandom(total_bytes)
                full_sha = hashlib.sha256(raw_blob).hexdigest()
                chunks = [raw_blob[off : off + chunk_size] for off in range(0, total_bytes, chunk_size)]
                file_id = str(uuid.uuid4())

                try:
                    t_up0 = time.perf_counter()
                    # 1. init
                    init_payload = {
                        "file_id": file_id,
                        "owner_user_id": alice_user_id,
                        "owner_device_id": alice_device_id,
                        "conversation_id": conversation_id,
                        "encrypted_size_bytes": total_bytes,
                        "expected_chunk_count": len(chunks),
                        "encryption_version": "v1",
                        "client_crypto_metadata": json.dumps({"alg": "AES-256-GCM", "v": 1, "chunk_size": chunk_size}),
                    }
                    st, data, _ = client.request(
                        "POST",
                        "/api/v1/files/upload/init",
                        body=json.dumps(init_payload).encode("utf-8"),
                        headers={**auth_hdr, "Content-Type": "application/json"},
                    )
                    if st not in (200, 201):
                        raise RuntimeError(f"init HTTP {st}: {data[:160].decode('utf-8', 'replace')}")
                    upload_id = json.loads(data.decode("utf-8"))["upload_id"]

                    # 2. chunks
                    for idx, chunk_bytes in enumerate(chunks):
                        c_sha = hashlib.sha256(chunk_bytes).hexdigest()
                        st, data, _ = client.request(
                            "POST",
                            "/api/v1/files/upload/chunk",
                            body=chunk_bytes,
                            headers={
                                **auth_hdr,
                                "Content-Type": "application/octet-stream",
                                "Upload-Id": upload_id,
                                "Chunk-Index": str(idx),
                                "X-Ciphertext-SHA256": c_sha,
                            },
                        )
                        if st not in (200, 201):
                            raise RuntimeError(f"chunk {idx} HTTP {st}: {data[:160].decode('utf-8', 'replace')}")

                    # 3. finalize
                    fin_payload = {
                        "upload_id": upload_id,
                        "file_id": file_id,
                        "expected_ciphertext_sha256": full_sha,
                    }
                    st, data, _ = client.request(
                        "POST",
                        "/api/v1/files/upload/finalize",
                        body=json.dumps(fin_payload).encode("utf-8"),
                        headers={**auth_hdr, "Content-Type": "application/json"},
                    )
                    if st not in (200, 201):
                        raise RuntimeError(f"finalize HTTP {st}: {data[:160].decode('utf-8', 'replace')}")
                    up_ms = (time.perf_counter() - t_up0) * 1000.0

                    if label == "5mib" and i == 1:
                        try:
                            peak_stats_holder["files_peak"] = capture_docker_stats()
                        except Exception:
                            pass

                    # 4. download all chunks + verify SHA-256
                    t_dn0 = time.perf_counter()
                    downloaded = bytearray()
                    for idx in range(len(chunks)):
                        st, data, _ = client.request(
                            "GET", f"/api/v1/files/{urllib.parse.quote(file_id)}/chunks/{idx}", headers=auth_hdr
                        )
                        if st != 200:
                            raise RuntimeError(f"download chunk {idx} HTTP {st}: {data[:160].decode('utf-8', 'replace')}")
                        downloaded.extend(data)
                    dn_ms = (time.perf_counter() - t_dn0) * 1000.0

                    if hashlib.sha256(downloaded).hexdigest() == full_sha:
                        integrity_ok += 1
                    else:
                        raise RuntimeError("SHA-256 mismatch on downloaded blob")

                    upload_ms_list.append(up_ms)
                    download_ms_list.append(dn_ms)
                    total_ms_list.append(up_ms + dn_ms)
                except Exception as exc:
                    errors += 1
                    if len(error_samples) < 3:
                        error_samples.append(str(exc))

            mib = total_bytes / (1024.0 * 1024.0)
            up_mean = statistics.fmean(upload_ms_list) if upload_ms_list else 0.0
            dn_mean = statistics.fmean(download_ms_list) if download_ms_list else 0.0
            up_mib_s = (mib / (up_mean / 1000.0)) if up_mean > 0 else 0.0
            dn_mib_s = (mib / (dn_mean / 1000.0)) if dn_mean > 0 else 0.0

            entry = {
                "payload_bytes": total_bytes,
                "chunk_size_bytes": chunk_size,
                "chunk_count": (total_bytes + chunk_size - 1) // chunk_size,
                "iterations": iters,
                "succeeded": len(upload_ms_list),
                "errors": errors,
                "sha256_verified": integrity_ok,
                "upload_mean_ms": round(up_mean, 2),
                "upload_p50_ms": round(percentile(sorted(upload_ms_list), 50.0), 2),
                "upload_max_ms": round(max(upload_ms_list), 2) if upload_ms_list else 0.0,
                "upload_throughput_mib_s": round(up_mib_s, 2),
                "download_mean_ms": round(dn_mean, 2),
                "download_p50_ms": round(percentile(sorted(download_ms_list), 50.0), 2),
                "download_max_ms": round(max(download_ms_list), 2) if download_ms_list else 0.0,
                "download_throughput_mib_s": round(dn_mib_s, 2),
                "roundtrip_mean_ms": round(statistics.fmean(total_ms_list), 2) if total_ms_list else 0.0,
            }
            if error_samples:
                entry["error_samples"] = error_samples
            results[f"files_{label}"] = entry
            print(
                f"  Files {label:5s} ({entry['chunk_count']} chunks, n={iters}): "
                f"UP {up_mean:6.1f}ms ({up_mib_s:5.2f} MiB/s) | DN {dn_mean:6.1f}ms ({dn_mib_s:5.2f} MiB/s) | "
                f"SHA256 {integrity_ok}/{iters} | err={errors}",
                flush=True,
            )
    finally:
        client.close()

    return results


def benchmark_group_5_audit(initial_count: int, bench_start_ts: float) -> Dict[str, Any]:
    print("\n=== Group 5: Audit Service (ClickHouse Async Ingestion & Query Latency) ===", flush=True)
    results: Dict[str, Any] = {}

    # Poll ClickHouse until count stabilizes (all outboxes & gateway spool drained)
    t_drain0 = time.perf_counter()
    prev_cnt = -1
    stable_ticks = 0
    final_cnt = initial_count
    for _ in range(20):
        out, _ = clickhouse_query("SELECT count() FROM audit_events")
        final_cnt = int(out.strip() or "0")
        if final_cnt == prev_cnt and final_cnt > initial_count:
            stable_ticks += 1
            if stable_ticks >= 3:
                break
        else:
            stable_ticks = 0
        prev_cnt = final_cnt
        time.sleep(0.5)
    drain_wait_s = time.perf_counter() - t_drain0
    total_elapsed_s = time.perf_counter() - bench_start_ts
    new_events = final_cnt - initial_count

    # Breakdown by producer_service
    prod_raw, _ = clickhouse_query(
        "SELECT producer_service, count() FROM audit_events GROUP BY producer_service ORDER BY count() DESC FORMAT TabSeparated"
    )
    by_producer: Dict[str, int] = {}
    for line in prod_raw.splitlines():
        if "\t" in line:
            p, c = line.split("\t", 1)
            by_producer[p.strip()] = int(c.strip())

    # Grab a real correlation_id for point-lookup query benchmark
    sample_corr, _ = clickhouse_query(
        "SELECT toString(correlation_id) FROM audit_events WHERE correlation_id IS NOT NULL AND toString(correlation_id) != '00000000-0000-0000-0000-000000000000' LIMIT 1"
    )
    sample_corr = sample_corr.strip()

    # Timed investigation queries (30 iterations each)
    query_specs = [
        ("query_recent_by_producer", "SELECT event_id, event_type, occurred_at FROM audit_events WHERE producer_service = 'messaging' ORDER BY occurred_at DESC LIMIT 50 FORMAT TabSeparated"),
        ("query_time_window_agg", "SELECT producer_service, event_type, count() FROM audit_events WHERE occurred_at >= now() - INTERVAL 1 HOUR GROUP BY producer_service, event_type FORMAT TabSeparated"),
    ]
    if sample_corr:
        safe_corr = sample_corr.replace("'", "")
        query_specs.append(
            ("query_by_correlation_id", f"SELECT event_id, producer_service, event_type, occurred_at FROM audit_events WHERE correlation_id = '{safe_corr}' LIMIT 50 FORMAT TabSeparated")
        )

    query_results: Dict[str, Any] = {}
    for q_name, sql in query_specs:
        lats: List[float] = []
        errs = 0
        t0_w = time.perf_counter()
        for _ in range(30):
            try:
                _, ms = clickhouse_query(sql)
                lats.append(ms)
            except Exception:
                errs += 1
        qr = summarize_latencies(lats, time.perf_counter() - t0_w, errs, 30)
        query_results[q_name] = qr
        print(
            f"  ClickHouse {q_name:26s} (n=30): "
            f"p50={qr['p50_ms']:.2f}ms p95={qr['p95_ms']:.2f}ms max={qr['max_ms']:.2f}ms | err={qr['errors']}",
            flush=True,
        )

    results["initial_events"] = initial_count
    results["final_events"] = final_cnt
    results["new_events_ingested"] = new_events
    results["drain_stabilization_s"] = round(drain_wait_s, 2)
    results["effective_ingestion_rate_eps"] = round(new_events / total_elapsed_s, 2) if total_elapsed_s > 0 else 0.0
    results["events_by_producer"] = by_producer
    results["queries"] = query_results
    print(
        f"  Audit ingested: +{new_events} events (total={final_cnt}) | drain wait={drain_wait_s:.2f}s | producers={by_producer}",
        flush=True,
    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureCloud Backend Docker Compose Benchmark Harness")
    parser.add_argument("--json-out", default="/tmp/backend_bench_results.json", help="Path to write JSON results")
    args = parser.parse_args()

    if not os.path.exists(CA_CERT_PATH):
        print(f"ERROR: CA cert not found at {CA_CERT_PATH}", file=sys.stderr)
        return 1

    ssl_ctx = make_ssl_context(CA_CERT_PATH)
    report: Dict[str, Any] = {"environment": collect_environment_metadata()}

    print("=== Capturing Idle Baseline Container Stats ===", flush=True)
    idle_stats = capture_docker_stats()
    initial_audit_str, _ = clickhouse_query("SELECT count() FROM audit_events")
    initial_audit_count = int(initial_audit_str.strip() or "0")
    print(f"  Initial ClickHouse audit_events: {initial_audit_count}", flush=True)

    # Setup Alice & Bob sessions + devices + conversation
    print("=== Bootstrapping Benchmark Users, Devices & Conversation ===", flush=True)
    setup_client = KeepAliveClient(GATEWAY_HOST, GATEWAY_PORT, ssl_ctx)
    try:
        alice_sess = login_user(setup_client, ALICE_EMAIL, ALICE_PASSWORD)
        bob_sess = login_user(setup_client, BOB_EMAIL, BOB_PASSWORD)
        alice_token = alice_sess["access_token"]
        alice_refresh = alice_sess["refresh_token"]
        alice_user_id = alice_sess["user_id"]
        alice_login_device_id = alice_sess.get("device_id", "")
        bob_token = bob_sess["access_token"]
        bob_user_id = bob_sess["user_id"]

        alice_device_id = register_device(setup_client, alice_token, alice_user_id)
        bob_device_id = register_device(setup_client, bob_token, bob_user_id)
        conversation_id = create_direct_conversation(setup_client, alice_token, bob_user_id)
        print(
            f"  Ready: alice_dev={alice_device_id[:8]}.. bob_dev={bob_device_id[:8]}.. conv={conversation_id[:8]}..",
            flush=True,
        )
    finally:
        setup_client.close()

    bench_start_ts = time.perf_counter()
    peak_stats_holder: Dict[str, Any] = {}

    report["group1_gateway"] = benchmark_group_1_gateway(ssl_ctx)
    report["group2_auth"], alice_token = benchmark_group_2_auth(
        ssl_ctx, alice_token, alice_refresh, alice_login_device_id, bob_user_id
    )
    report["group3_messaging"] = benchmark_group_3_messaging(
        ssl_ctx, alice_token, bob_token, bob_user_id, bob_device_id, conversation_id, peak_stats_holder
    )
    report["group4_files"] = benchmark_group_4_files(
        ssl_ctx, alice_token, alice_user_id, alice_device_id, conversation_id, peak_stats_holder
    )
    report["group5_audit"] = benchmark_group_5_audit(initial_audit_count, bench_start_ts)

    print("\n=== Group 6: Container Resource Footprint ===", flush=True)
    post_stats = capture_docker_stats()
    report["group6_resources"] = {
        "idle": idle_stats,
        "messaging_peak": peak_stats_holder.get("messaging_peak", {}),
        "files_peak": peak_stats_holder.get("files_peak", {}),
        "post_load": post_stats,
    }
    for svc in ["gateway", "auth", "messaging", "files", "audit", "postgres", "scylladb", "minio", "clickhouse"]:
        idle_m = idle_stats.get(svc, {}).get("mem_used_mib", 0.0)
        peak_m = max(
            peak_stats_holder.get("messaging_peak", {}).get(svc, {}).get("mem_used_mib", 0.0),
            peak_stats_holder.get("files_peak", {}).get(svc, {}).get("mem_used_mib", 0.0),
        )
        post_m = post_stats.get(svc, {}).get("mem_used_mib", 0.0)
        peak_c = max(
            peak_stats_holder.get("messaging_peak", {}).get(svc, {}).get("cpu_pct", 0.0),
            peak_stats_holder.get("files_peak", {}).get(svc, {}).get("cpu_pct", 0.0),
        )
        print(
            f"  {svc:11s} | Idle: {idle_m:7.1f} MiB | Peak: {peak_m:7.1f} MiB ({peak_c:5.1f}% CPU) | Post: {post_m:7.1f} MiB",
            flush=True,
        )

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved full JSON benchmark results to {args.json_out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
