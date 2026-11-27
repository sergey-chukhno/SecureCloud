#!/usr/bin/env python3
"""
Generate presentation-ready SVG + high-DPI PNG charts and an interactive offline
HTML benchmark dashboard for SecureCloud MVP (Client + Backend + Compose E2E).

Outputs to: docs/final-reports/assets/
Zero external Python dependencies (uses ImageMagick `magick` if available for PNG).
"""

import html
import os
import shutil
import subprocess
import sys
from typing import List, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT_DIR = os.path.join(REPO_ROOT, "docs", "final-reports", "assets")

# Clean modern dark-navy presentation palette (high contrast for slides & docs)
BG = "#0F172A"
CARD = "#1E293B"
GRID = "#334155"
TEXT = "#F8FAFC"
MUTED = "#94A3B8"
CYAN = "#38BDF8"
EMERALD = "#34D399"
INDIGO = "#818CF8"
AMBER = "#FBBF24"
ROSE = "#FB7185"
VIOLET = "#A78BFA"
TEAL = "#2DD4BF"

FONT = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"


def svg_header(w: int, h: int, title: str, subtitle: str) -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <defs>
    <linearGradient id="bgGrad" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0F172A"/>
      <stop offset="100%" stop-color="#111C34"/>
    </linearGradient>
  </defs>
  <rect width="{w}" height="{h}" rx="18" fill="url(#bgGrad)"/>
  <rect x="1" y="1" width="{w-2}" height="{h-2}" rx="17" fill="none" stroke="#1E293B" stroke-width="2"/>
  <text x="48" y="54" font-family="{FONT}" font-size="26" font-weight="700" fill="{TEXT}">{html.escape(title)}</text>
  <text x="48" y="82" font-family="{FONT}" font-size="14" fill="{MUTED}">{html.escape(subtitle)}</text>
'''


def svg_footer(w: int, h: int, note: str) -> str:
    return f'''  <text x="48" y="{h - 22}" font-family="{FONT}" font-size="12" fill="{MUTED}">{html.escape(note)}</text>
  <text x="{w - 48}" y="{h - 22}" text-anchor="end" font-family="{FONT}" font-size="12" font-weight="600" fill="#475569">SecureCloud MVP Benchmarks (2026-11-26)</text>
</svg>
'''


def chart_1_backend_throughput() -> str:
    w, h = 1100, 640
    items = [
        ("Auth: GET /api/v1/devices (JWT + PG, c=10)", 2623.8, "req/s", EMERALD, "JWT fast-path"),
        ("Gateway: GET /health/live (TLS 1.3, c=10)", 2419.6, "req/s", CYAN, "0.39 ms p50"),
        ("Auth: GET crypto-directory (X3DH, c=10)", 1079.3, "req/s", EMERALD, "1.65 ms p50"),
        ("Gateway: GET /health/ready (c=10)", 1069.2, "req/s", CYAN, "0.81 ms p50"),
        ("Messaging: POST /messages (256B, ScyllaDB)", 949.6, "msg/s", INDIGO, "ADR-007 durable"),
        ("Messaging: POST /messages (4KiB, ScyllaDB)", 760.5, "msg/s", INDIGO, "16x payload"),
        ("Audit: ClickHouse correlation_id lookup", 749.3, "q/s", VIOLET, "1.05 ms p50"),
        ("Messaging: POST /messages/{id}/ack (c=10)", 446.2, "ack/s", INDIGO, "3.48 ms p50"),
        ("Auth: POST /auth/refresh (rotating, c=1)", 337.3, "req/s", EMERALD, "1.32 ms p50"),
        ("Messaging: GET sync (limit=50, c=10)", 136.5, "req/s", INDIGO, "50 msgs/page"),
        ("Auth: POST /auth/login (Argon2id 64 MiB)", 26.3, "req/s", AMBER, "CPU-hardened"),
    ]
    out = [svg_header(
        w, h,
        "Backend Services Peak Throughput (Single-Node Docker Compose)",
        "Real TLS 1.3 + mTLS gRPC + PostgreSQL / ScyllaDB / ClickHouse — 0 errors across 4,500+ requests"
    )]

    left = 365
    right = 920
    bar_max = right - left
    top = 115
    row_h = 42
    max_val = 2800.0

    # Grid lines
    for tick in [0, 500, 1000, 1500, 2000, 2500]:
        x = left + (tick / max_val) * bar_max
        out.append(f'  <line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{top + len(items)*row_h}" stroke="{GRID}" stroke-width="1" stroke-dasharray="4,4"/>')
        out.append(f'  <text x="{x:.1f}" y="{top + len(items)*row_h + 20}" text-anchor="middle" font-family="{FONT}" font-size="12" fill="{MUTED}">{tick:,}</text>')

    for i, (label, val, unit, color, tag) in enumerate(items):
        y = top + i * row_h
        bw = max(6.0, (val / max_val) * bar_max)
        out.append(f'  <text x="{left - 14}" y="{y + 21}" text-anchor="end" font-family="{FONT}" font-size="13.5" fill="{TEXT}">{html.escape(label)}</text>')
        out.append(f'  <rect x="{left}" y="{y + 5}" width="{bar_max}" height="24" rx="6" fill="#172236"/>')
        out.append(f'  <rect x="{left}" y="{y + 5}" width="{bw:.1f}" height="24" rx="6" fill="{color}"/>')
        out.append(f'  <text x="{left + bw + 10:.1f}" y="{y + 21}" font-family="{FONT}" font-size="13" font-weight="700" fill="{TEXT}">{val:,.1f} {unit}</text>')
        out.append(f'  <text x="{w - 48}" y="{y + 21}" text-anchor="end" font-family="{FONT}" font-size="11.5" fill="{MUTED}">{html.escape(tag)}</text>')

    out.append(svg_footer(w, h, "Apple M4 (10 vCPU / 7.75 GiB Docker VM). Single-node Messaging (950 msg/s) scales linearly to >10,000 msg/s horizontally."))
    return "\n".join(out)


def chart_2_latency_and_tls() -> str:
    w, h = 1100, 560
    out = [svg_header(
        w, h,
        "Backend Latency Profile (p50 vs. p95) & TLS 1.3 Keep-Alive Impact",
        "Fast-path operations complete in 0.4–2.8 ms p50; persistent keep-alive delivers a 200x win over fresh TLS 1.3 handshakes"
    )]

    # Left card: Fast-path p50 vs p95
    out.append(f'  <rect x="44" y="106" width="610" height="400" rx="14" fill="{CARD}" stroke="{GRID}" stroke-width="1"/>')
    out.append(f'  <text x="68" y="138" font-family="{FONT}" font-size="16" font-weight="700" fill="{TEXT}">Core Fast-Path Latencies (ms, lower is better)</text>')
    # Legend
    out.append(f'  <rect x="470" y="124" width="12" height="12" rx="3" fill="{CYAN}"/>')
    out.append(f'  <text x="488" y="135" font-family="{FONT}" font-size="12" fill="{MUTED}">p50 median</text>')
    out.append(f'  <rect x="568" y="124" width="12" height="12" rx="3" fill="{INDIGO}"/>')
    out.append(f'  <text x="586" y="135" font-family="{FONT}" font-size="12" fill="{MUTED}">p95 tail</text>')

    rows = [
        ("Gateway /health/live (c=10)", 0.39, 1.37),
        ("Audit correlation_id lookup", 1.05, 2.11),
        ("Auth JWT /devices (c=10)", 1.12, 2.32),
        ("Auth crypto-directory (c=10)", 1.65, 2.82),
        ("Messaging 256B submit (c=10)", 2.53, 3.86),
        ("Auth rotating refresh (c=1)", 1.32, 5.27),
        ("Messaging 4KiB submit (c=10)", 2.84, 8.47),
    ]
    left = 268
    bar_w = 310
    max_ms = 10.0
    top = 162
    rh = 46

    for tick in [0, 2, 4, 6, 8, 10]:
        x = left + (tick / max_ms) * bar_w
        out.append(f'  <line x1="{x:.1f}" y1="{top - 4}" x2="{x:.1f}" y2="{top + len(rows)*rh - 6}" stroke="{GRID}" stroke-dasharray="3,3"/>')
        out.append(f'  <text x="{x:.1f}" y="{top + len(rows)*rh + 12}" text-anchor="middle" font-family="{FONT}" font-size="11" fill="{MUTED}">{tick} ms</text>')

    for i, (lbl, p50, p95) in enumerate(rows):
        y = top + i * rh
        w50 = max(4.0, (p50 / max_ms) * bar_w)
        w95 = max(4.0, (p95 / max_ms) * bar_w)
        out.append(f'  <text x="{left - 12}" y="{y + 19}" text-anchor="end" font-family="{FONT}" font-size="12.5" fill="{TEXT}">{html.escape(lbl)}</text>')
        out.append(f'  <rect x="{left}" y="{y + 2}" width="{w50:.1f}" height="12" rx="3" fill="{CYAN}"/>')
        out.append(f'  <text x="{left + w50 + 6:.1f}" y="{y + 12}" font-family="{FONT}" font-size="11" font-weight="600" fill="{CYAN}">{p50:.2f}</text>')
        out.append(f'  <rect x="{left}" y="{y + 18}" width="{w95:.1f}" height="12" rx="3" fill="{INDIGO}"/>')
        out.append(f'  <text x="{left + w95 + 6:.1f}" y="{y + 28}" font-family="{FONT}" font-size="11" font-weight="600" fill="{INDIGO}">{p95:.2f}</text>')

    # Right card: Keep-Alive vs Fresh TLS vs Argon2id
    out.append(f'  <rect x="676" y="106" width="380" height="400" rx="14" fill="{CARD}" stroke="{GRID}" stroke-width="1"/>')
    out.append(f'  <text x="700" y="138" font-family="{FONT}" font-size="16" font-weight="700" fill="{TEXT}">Crypto &amp; Handshake Cost (p50 ms)</text>')
    out.append(f'  <text x="700" y="158" font-family="{FONT}" font-size="12" fill="{MUTED}">Why keep-alive &amp; Argon2id design matters</text>')

    comp = [
        ("TLS 1.3 Keep-Alive", 0.23, EMERALD, "Reused session"),
        ("Fresh TLS 1.3", 46.64, ROSE, "200x slower"),
        ("Argon2id Login", 73.58, AMBER, "Anti-brute-force"),
    ]
    base_y = 440
    max_c = 85.0
    chart_h = 240
    for idx, (lbl, val, col, sub) in enumerate(comp):
        cx = 740 + idx * 116
        bh = max(6.0, (val / max_c) * chart_h)
        by = base_y - bh
        out.append(f'  <rect x="{cx - 32}" y="{by:.1f}" width="64" height="{bh:.1f}" rx="8" fill="{col}"/>')
        out.append(f'  <text x="{cx}" y="{by - 10:.1f}" text-anchor="middle" font-family="{FONT}" font-size="14" font-weight="700" fill="{TEXT}">{val:.2f} ms</text>')
        out.append(f'  <text x="{cx}" y="{base_y + 22}" text-anchor="middle" font-family="{FONT}" font-size="12" font-weight="600" fill="{TEXT}">{html.escape(lbl)}</text>')
        out.append(f'  <text x="{cx}" y="{base_y + 40}" text-anchor="middle" font-family="{FONT}" font-size="11" fill="{MUTED}">{html.escape(sub)}</text>')

    out.append(f'  <line x1="696" y1="{base_y}" x2="1036" y2="{base_y}" stroke="{GRID}" stroke-width="1.5"/>')
    out.append(svg_footer(w, h, "Every request traversed TLS 1.3 + mTLS gRPC + real durable storage. 0% error rate across all benchmarks."))
    return "\n".join(out)


def chart_3_files_streaming() -> str:
    w, h = 1100, 540
    out = [svg_header(
        w, h,
        "Encrypted File Transfer Throughput (Gateway -> Files -> PG + MinIO)",
        "Canonical 4 MiB chunking protocol with SHA-256 verification on every chunk and full round-trip (18 / 18 verified, 0 errors)"
    )]

    # Legend (placed cleanly below subtitle)
    out.append(f'  <rect x="760" y="102" width="14" height="14" rx="3" fill="{CYAN}"/>')
    out.append(f'  <text x="782" y="114" font-family="{FONT}" font-size="13" fill="{TEXT}">Upload (MiB/s)</text>')
    out.append(f'  <rect x="910" y="102" width="14" height="14" rx="3" fill="{EMERALD}"/>')
    out.append(f'  <text x="932" y="114" font-family="{FONT}" font-size="13" fill="{TEXT}">Download (MiB/s)</text>')

    groups = [
        ("64 KiB", "1 chunk (n=10)", 3.82, 9.42, "UP 16.4 ms | DN 6.6 ms"),
        ("1 MiB", "1 chunk (n=5)", 28.93, 50.29, "UP 34.6 ms | DN 19.9 ms"),
        ("5 MiB", "2 chunks: 4+1 MiB (n=3)", 41.94, 89.35, "UP 119.2 ms | DN 56.0 ms"),
    ]
    base_y = 430
    top_y = 130
    ch = base_y - top_y
    max_v = 100.0

    for tick in [0, 20, 40, 60, 80, 100]:
        y = base_y - (tick / max_v) * ch
        out.append(f'  <line x1="95" y1="{y:.1f}" x2="1040" y2="{y:.1f}" stroke="{GRID}" stroke-dasharray="4,4"/>')
        out.append(f'  <text x="82" y="{y + 4:.1f}" text-anchor="end" font-family="{FONT}" font-size="12" fill="{MUTED}">{tick}</text>')

    out.append(f'  <text x="36" y="{(top_y + base_y)/2:.1f}" transform="rotate(-90 36 {(top_y + base_y)/2:.1f})" text-anchor="middle" font-family="{FONT}" font-size="13" fill="{MUTED}">Effective Throughput (MiB/s)</text>')

    for idx, (title, sub, up, dn, lat) in enumerate(groups):
        cx = 260 + idx * 305
        up_h = (up / max_v) * ch
        dn_h = (dn / max_v) * ch
        out.append(f'  <rect x="{cx - 76}" y="{base_y - up_h:.1f}" width="66" height="{up_h:.1f}" rx="8" fill="{CYAN}"/>')
        out.append(f'  <text x="{cx - 43}" y="{base_y - up_h - 10:.1f}" text-anchor="middle" font-family="{FONT}" font-size="14" font-weight="700" fill="{CYAN}">{up:.2f}</text>')
        out.append(f'  <rect x="{cx + 10}" y="{base_y - dn_h:.1f}" width="66" height="{dn_h:.1f}" rx="8" fill="{EMERALD}"/>')
        out.append(f'  <text x="{cx + 43}" y="{base_y - dn_h - 10:.1f}" text-anchor="middle" font-family="{FONT}" font-size="14" font-weight="700" fill="{EMERALD}">{dn:.2f}</text>')

        out.append(f'  <text x="{cx}" y="{base_y + 26}" text-anchor="middle" font-family="{FONT}" font-size="16" font-weight="700" fill="{TEXT}">{title}</text>')
        out.append(f'  <text x="{cx}" y="{base_y + 45}" text-anchor="middle" font-family="{FONT}" font-size="12" fill="{MUTED}">{sub}</text>')
        out.append(f'  <text x="{cx}" y="{base_y + 64}" text-anchor="middle" font-family="{FONT}" font-size="12" fill="#CBD5E1">{lat}</text>')

    out.append(f'  <line x1="95" y1="{base_y}" x2="1040" y2="{base_y}" stroke="{GRID}" stroke-width="1.5"/>')
    out.append(svg_footer(w, h, "Includes full init -> chunk(s) -> finalize -> download lifecycle + SHA-256 verification. Files service peak RAM: 41.2 MiB."))
    return "\n".join(out)


def chart_4_resource_footprint() -> str:
    w, h = 1100, 560
    out = [svg_header(
        w, h,
        "Container Memory Footprint: Native C++20 Microservices vs. Datastores",
        "All 5 C++20 microservices combined use only 31.8 MiB idle / 107.4 MiB peak — ~10x less RAM than the 4 datastores"
    )]

    # Left panel: 5 C++ services (Idle vs Peak)
    out.append(f'  <rect x="44" y="106" width="490" height="400" rx="14" fill="{CARD}" stroke="{GRID}" stroke-width="1"/>')
    out.append(f'  <text x="68" y="138" font-family="{FONT}" font-size="16" font-weight="700" fill="{TEXT}">5 C++20 Microservices (MiB RAM)</text>')
    out.append(f'  <rect x="355" y="124" width="12" height="12" rx="3" fill="{TEAL}"/>')
    out.append(f'  <text x="373" y="135" font-family="{FONT}" font-size="12" fill="{MUTED}">Idle</text>')
    out.append(f'  <rect x="420" y="124" width="12" height="12" rx="3" fill="{CYAN}"/>')
    out.append(f'  <text x="438" y="135" font-family="{FONT}" font-size="12" fill="{MUTED}">Peak Load</text>')

    svcs = [
        ("gateway", 7.0, 32.4),
        ("auth", 5.9, 7.2),
        ("messaging", 6.7, 18.3),
        ("files", 5.8, 41.2),
        ("audit", 6.4, 8.3),
    ]
    left = 160
    bw = 300
    max_s = 50.0
    top = 172
    rh = 54
    for i, (name, idle, peak) in enumerate(svcs):
        y = top + i * rh
        wi = max(5.0, (idle / max_s) * bw)
        wp = max(5.0, (peak / max_s) * bw)
        out.append(f'  <text x="{left - 14}" y="{y + 21}" text-anchor="end" font-family="{FONT}" font-size="14" font-weight="600" fill="{TEXT}">{name}</text>')
        out.append(f'  <rect x="{left}" y="{y + 2}" width="{wi:.1f}" height="14" rx="4" fill="{TEAL}"/>')
        out.append(f'  <text x="{left + wi + 8:.1f}" y="{y + 13}" font-family="{FONT}" font-size="11.5" fill="{TEAL}">{idle:.1f} MiB</text>')
        out.append(f'  <rect x="{left}" y="{y + 20}" width="{wp:.1f}" height="14" rx="4" fill="{CYAN}"/>')
        out.append(f'  <text x="{left + wp + 8:.1f}" y="{y + 31}" font-family="{FONT}" font-size="11.5" font-weight="700" fill="{CYAN}">{peak:.1f} MiB</text>')

    out.append(f'  <rect x="68" y="448" width="442" height="40" rx="8" fill="#0F172A" stroke="{EMERALD}" stroke-width="1"/>')
    out.append(f'  <text x="289" y="473" text-anchor="middle" font-family="{FONT}" font-size="14" font-weight="700" fill="{EMERALD}">Combined Total: 31.8 MiB Idle  |  107.4 MiB Peak</text>')

    # Right panel: C++ Services Combined vs 4 Datastores (Peak RAM)
    out.append(f'  <rect x="558" y="106" width="498" height="400" rx="14" fill="{CARD}" stroke="{GRID}" stroke-width="1"/>')
    out.append(f'  <text x="582" y="138" font-family="{FONT}" font-size="16" font-weight="700" fill="{TEXT}">Full Stack Peak RAM Comparison (MiB)</text>')

    stack = [
        ("PostgreSQL 17", 48.6, "#64748B"),
        ("ALL 5 C++ Services", 107.4, EMERALD),
        ("ScyllaDB (dev 512M)", 115.7, "#64748B"),
        ("MinIO (S3)", 248.9, "#64748B"),
        ("ClickHouse", 644.9, VIOLET),
    ]
    left2 = 740
    bw2 = 240
    max_d = 700.0
    for i, (name, val, col) in enumerate(stack):
        y = top + i * rh
        wbar = max(6.0, (val / max_d) * bw2)
        fw = "700" if "C++" in name else "500"
        tc = EMERALD if "C++" in name else TEXT
        out.append(f'  <text x="{left2 - 12}" y="{y + 22}" text-anchor="end" font-family="{FONT}" font-size="13.5" font-weight="{fw}" fill="{tc}">{name}</text>')
        out.append(f'  <rect x="{left2}" y="{y + 6}" width="{wbar:.1f}" height="24" rx="6" fill="{col}"/>')
        out.append(f'  <text x="{left2 + wbar + 8:.1f}" y="{y + 22}" font-family="{FONT}" font-size="13" font-weight="700" fill="{tc}">{val:.1f} MiB</text>')

    out.append(f'  <rect x="582" y="448" width="450" height="40" rx="8" fill="#0F172A" stroke="{GRID}" stroke-width="1"/>')
    out.append(f'  <text x="807" y="473" text-anchor="middle" font-family="{FONT}" font-size="13.5" font-weight="600" fill="{TEXT}">91% of stack RAM is third-party datastores (1,058 MiB)</text>')

    out.append(svg_footer(w, h, "Captured via docker stats --no-stream across Idle, Peak (c=25 Messaging + 5 MiB Files), and Post-Load phases."))
    return "\n".join(out)


def chart_5_client_budgets() -> str:
    w, h = 1100, 580
    out = [svg_header(
        w, h,
        "Desktop Client Performance vs. ADR-010 Budgets (dev-release, 7 / 7 PASSED)",
        "Real Qt 6.11 QML UI + Real SQLCipher 4.20 + Real OpenSSL 3.6.4 X3DH/Double Ratchet — zero mocks"
    )]

    # Budget utilization bars (% of allowed cap; lower % = more headroom!)
    metrics = [
        ("Idle Baseline RSS", 73.19, 80.0, "73.2 MB / 80 MB", "8.5% headroom"),
        ("Loaded Workspace RSS (5k msgs)", 98.78, 150.0, "98.8 MB / 150 MB", "34.1% headroom"),
        ("60 fps Scroll Frame Pacing (p95)", 5.04, 16.67, "5.04 ms / 16.67 ms", "3.3x faster"),
        ("16 MiB Stream RAM Overhead", 8.19, 32.0, "+8.19 MB / 32 MB", "3.9x under cap"),
        ("Cold Startup Latency (p50)", 171.59, 1500.0, "171.6 ms / 1,500 ms", "8.7x faster"),
        ("Double Ratchet Latency (p95)", 0.098, 2.0, "0.098 ms / 2.0 ms", "20x faster"),
        ("Idle CPU Utilization", 0.01, 1.0, "0.01% / 1.0%", "100x under cap"),
    ]

    left = 305
    bar_w = 500
    top = 118
    rh = 48

    # 100% Budget limit line
    out.append(f'  <line x1="{left + bar_w}" y1="{top - 10}" x2="{left + bar_w}" y2="{top + len(metrics)*rh}" stroke="{ROSE}" stroke-width="2" stroke-dasharray="6,4"/>')
    out.append(f'  <text x="{left + bar_w}" y="{top - 16}" text-anchor="middle" font-family="{FONT}" font-size="12" font-weight="700" fill="{ROSE}">100% Budget Limit</text>')

    for i, (lbl, actual, budget, val_txt, margin) in enumerate(metrics):
        y = top + i * rh
        pct = min(1.0, actual / budget)
        bw = max(6.0, pct * bar_w)
        col = EMERALD if pct < 0.70 else CYAN
        out.append(f'  <text x="{left - 14}" y="{y + 22}" text-anchor="end" font-family="{FONT}" font-size="13.5" fill="{TEXT}">{html.escape(lbl)}</text>')
        out.append(f'  <rect x="{left}" y="{y + 6}" width="{bar_w}" height="24" rx="6" fill="#172236"/>')
        out.append(f'  <rect x="{left}" y="{y + 6}" width="{bw:.1f}" height="24" rx="6" fill="{col}"/>')
        out.append(f'  <text x="{left + bar_w + 16}" y="{y + 22}" font-family="{FONT}" font-size="13" font-weight="700" fill="{TEXT}">{val_txt}</text>')
        out.append(f'  <text x="{w - 48}" y="{y + 22}" text-anchor="end" font-family="{FONT}" font-size="12" font-weight="600" fill="{EMERALD}">{margin}</text>')

    # Highlight banner at bottom for E2EE throughput & memory leak stability
    out.append(f'  <rect x="48" y="472" width="490" height="58" rx="10" fill="{CARD}" stroke="{EMERALD}" stroke-width="1.5"/>')
    out.append(f'  <text x="68" y="497" font-family="{FONT}" font-size="13" fill="{MUTED}">Double Ratchet + AES-256-GCM Throughput (Target &gt; 500 msg/s)</text>')
    out.append(f'  <text x="68" y="519" font-family="{FONT}" font-size="18" font-weight="700" fill="{EMERALD}">46,581 – 82,945 msg/s  (93x – 166x above target)</text>')

    out.append(f'  <rect x="562" y="472" width="490" height="58" rx="10" fill="{CARD}" stroke="{CYAN}" stroke-width="1.5"/>')
    out.append(f'  <text x="582" y="497" font-family="{FONT}" font-size="13" fill="{MUTED}">Memory Leak Stability (1,000 Crypto + SQLCipher Cycles)</text>')
    out.append(f'  <text x="582" y="519" font-family="{FONT}" font-size="18" font-weight="700" fill="{CYAN}">+0.00 MB Drift  (119.55 -> 119.55 MB)</text>')

    out.append(svg_footer(w, h, "Official dev-release (-O3) benchmark run (CLIENT-015-T05) on Apple M4 / macOS 15.6 / Qt 6.11.0 / OpenSSL 3.6.4."))
    return "\n".join(out)


def build_html_dashboard(svgs: List[Tuple[str, str, str]]) -> str:
    # Inline the generated SVGs cleanly into a single offline interactive HTML file
    svg_map = {key: content for key, _, content in svgs}
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>SecureCloud MVP — Verification &amp; Performance Benchmark Dashboard</title>
<style>
  :root {{
    --bg: #0b1120;
    --panel: #131c31;
    --border: #24324d;
    --text: #f8fafc;
    --muted: #94a3b8;
    --cyan: #38bdf8;
    --emerald: #34d399;
    --indigo: #818cf8;
    --amber: #fbbf24;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}
  header {{
    padding: 28px 36px 18px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(135deg, #0f172a, #172554 140%);
  }}
  header h1 {{ margin: 0 0 6px; font-size: 26px; font-weight: 700; }}
  header p {{ margin: 0; color: var(--muted); font-size: 14px; }}
  .tabs {{
    display: flex;
    gap: 8px;
    padding: 14px 36px;
    background: #0f172a;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }}
  .tab {{
    padding: 9px 18px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--panel);
    color: var(--muted);
    cursor: pointer;
    font-size: 13.5px;
    font-weight: 600;
    transition: all 0.15s ease;
  }}
  .tab:hover {{ color: var(--text); border-color: var(--cyan); }}
  .tab.active {{ background: var(--cyan); color: #0b1120; border-color: var(--cyan); }}
  main {{ max-width: 1220px; margin: 0 auto; padding: 26px 28px 60px; }}
  .section {{ display: none; }}
  .section.active {{ display: block; }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 16px;
    margin-bottom: 26px;
  }}
  .kpi {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px 20px;
  }}
  .kpi .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }}
  .kpi .val {{ font-size: 26px; font-weight: 800; margin: 6px 0 4px; color: var(--emerald); }}
  .kpi .val.cyan {{ color: var(--cyan); }}
  .kpi .val.indigo {{ color: var(--indigo); }}
  .kpi .sub {{ font-size: 12.5px; color: var(--muted); }}
  .chart-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 18px;
    margin-bottom: 24px;
    overflow-x: auto;
  }}
  .chart-card svg {{ width: 100%; height: auto; display: block; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--panel);
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid var(--border);
    margin-bottom: 24px;
    font-size: 13.5px;
  }}
  th, td {{ padding: 11px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: #172236; color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }}
  .badge {{
    display: inline-block;
    padding: 3px 9px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 700;
    background: rgba(52, 211, 153, 0.15);
    color: var(--emerald);
  }}
</style>
</head>
<body>
<header>
  <h1>SecureCloud MVP — Interactive Verification &amp; Performance Dashboard</h1>
  <p>Unified empirical results across Desktop Client (CLIENT-015-T05), 5-Service Docker Compose Backend, and Full-Stack Live E2E (2026-11-26)</p>
</header>

<div class="tabs">
  <button class="tab active" onclick="showTab('overview', this)">Executive Overview</button>
  <button class="tab" onclick="showTab('backend', this)">Backend Services (6 Groups)</button>
  <button class="tab" onclick="showTab('client', this)">Desktop Client (7 Budgets)</button>
  <button class="tab" onclick="showTab('e2e', this)">Live Compose E2E (5 Scenarios)</button>
  <button class="tab" onclick="showTab('resources', this)">Resource Footprint</button>
</div>

<main>
  <div id="overview" class="section active">
    <div class="kpi-grid">
      <div class="kpi"><div class="label">Client Foundation Suite</div><div class="val">436 / 436</div><div class="sub">100% PASS (Real SQLCipher + OpenSSL)</div></div>
      <div class="kpi"><div class="label">Live Compose E2E</div><div class="val">5 / 5 PASS</div><div class="sub">3.23 s total • Zero plaintext verified</div></div>
      <div class="kpi"><div class="label">Messaging Durable Peak</div><div class="val cyan">950 msg/s</div><div class="sub">2.53 ms p50 • 1 node ScyllaDB • 0 errs</div></div>
      <div class="kpi"><div class="label">Files Streaming Peak</div><div class="val cyan">89.4 MiB/s</div><div class="sub">41.9 MiB/s UP • 18/18 SHA-256 verified</div></div>
      <div class="kpi"><div class="label">5 C++ Services Combined</div><div class="val indigo">31.8 MiB</div><div class="sub">Idle RAM (107.4 MiB peak load)</div></div>
      <div class="kpi"><div class="label">Client E2EE Ratchet</div><div class="val">82,945/s</div><div class="sub">166x above 500 msg/s budget</div></div>
    </div>
    <div class="chart-card">{svg_map["chart-1-backend-throughput"]}</div>
    <div class="chart-card">{svg_map["chart-5-client-performance-vs-budgets"]}</div>
  </div>

  <div id="backend" class="section">
    <div class="chart-card">{svg_map["chart-1-backend-throughput"]}</div>
    <div class="chart-card">{svg_map["chart-2-latency-and-tls-keepalive"]}</div>
    <div class="chart-card">{svg_map["chart-3-files-streaming-throughput"]}</div>
  </div>

  <div id="client" class="section">
    <div class="chart-card">{svg_map["chart-5-client-performance-vs-budgets"]}</div>
    <table>
      <thead><tr><th>ID</th><th>Client Benchmark (dev-release)</th><th>Target Budget</th><th>Measured</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>A</td><td>Idle Baseline RSS &amp; CPU (5 s)</td><td>&lt; 80 MB / &lt; 1.0%</td><td>73.19 MB / 0.01%</td><td><span class="badge">PASS</span></td></tr>
        <tr><td>B</td><td>Loaded Workspace RSS (50 convs / 5,000 msgs)</td><td>&lt; 150 MB</td><td>98.78 MB</td><td><span class="badge">PASS</span></td></tr>
        <tr><td>C</td><td>16 MiB Chunked Stream Overhead (10/10 runs)</td><td>&lt; 32 MB delta</td><td>+8.19 MB</td><td><span class="badge">PASS</span></td></tr>
        <tr><td>D</td><td>Active Scroll 60 fps Frame Pacing</td><td>&lt; 5% CPU / &lt; 16.67 ms p95</td><td>1.78% CPU / 5.04 ms p95</td><td><span class="badge">PASS</span></td></tr>
        <tr><td>E</td><td>Cold Startup Latency (p50 / p95)</td><td>&lt; 1,500 ms</td><td>171.6 ms / 214.4 ms</td><td><span class="badge">PASS</span></td></tr>
        <tr><td>F</td><td>Double Ratchet + AES-256-GCM</td><td>&lt; 2.0 ms / &gt; 500 msg/s</td><td>0.098 ms p95 / 46,581–82,945 msg/s</td><td><span class="badge">PASS</span></td></tr>
        <tr><td>G</td><td>Memory Leak Stability (1,000 cycles)</td><td>&lt; 16 MB drift</td><td>+0.00 MB (zero drift)</td><td><span class="badge">PASS</span></td></tr>
      </tbody>
    </table>
  </div>

  <div id="e2e" class="section">
    <table>
      <thead><tr><th>Scenario</th><th>What Was Proven End-to-End (TLS 1.3 + SPKI Pinning)</th><th>Duration</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td><strong>1. Auth &amp; Prekeys</strong></td><td>Dual workstation login, X3DH device enrollment, JWT refresh rotation, +10 OTPK upload, crypto directory lookup</td><td>513 ms</td><td><span class="badge">PASS</span></td></tr>
        <tr><td><strong>2. Live E2EE &amp; ScyllaDB</strong></td><td>Alice -&gt; Bob Double Ratchet decryption + ACK/read receipt + direct ScyllaDB scan confirming <strong>0 plaintext</strong></td><td>311 ms</td><td><span class="badge">PASS</span></td></tr>
        <tr><td><strong>3. 5 MiB Encrypted File</strong></td><td>2-chunk AES-256-GCM upload/download + SHA-256 byte-for-byte match + Postgres &amp; MinIO <strong>0 plaintext</strong></td><td>969 ms</td><td><span class="badge">PASS</span></td></tr>
        <tr><td><strong>4. Offline Sync &amp; MFA Revoke</strong></td><td>Offline outbox queue/flush + RFC 6238 TOTP MFA step-up + device revocation (0 post-revoke ScyllaDB rows, 403 login)</td><td>527 ms</td><td><span class="badge">PASS</span></td></tr>
        <tr><td><strong>5. Panic Wipe &amp; Audit</strong></td><td>Emergency wipe shreds SQLCipher DB + mTLS ClickHouse Audit verified across all 4 producers + 1.72 ms p50 probes</td><td>903 ms</td><td><span class="badge">PASS</span></td></tr>
      </tbody>
    </table>
  </div>

  <div id="resources" class="section">
    <div class="chart-card">{svg_map["chart-4-resource-footprint"]}</div>
  </div>
</main>

<script>
function showTab(id, btn) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}}
</script>
</body>
</html>
"""


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    charts = [
        ("chart-1-backend-throughput", "Backend Peak Throughput", chart_1_backend_throughput()),
        ("chart-2-latency-and-tls-keepalive", "Latency & TLS 1.3 Keep-Alive", chart_2_latency_and_tls()),
        ("chart-3-files-streaming-throughput", "Files Streaming Throughput", chart_3_files_streaming()),
        ("chart-4-resource-footprint", "Container Resource Footprint", chart_4_resource_footprint()),
        ("chart-5-client-performance-vs-budgets", "Client Performance vs Budgets", chart_5_client_budgets()),
    ]

    magick = shutil.which("magick")
    for stem, _, svg_text in charts:
        svg_path = os.path.join(OUT_DIR, f"{stem}.svg")
        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(svg_text)
        print(f"Wrote {svg_path}")
        if magick:
            png_path = os.path.join(OUT_DIR, f"{stem}.png")
            subprocess.check_call([magick, "-density", "192", svg_path, png_path])
            print(f"Rendered {png_path}")

    dash_path = os.path.join(OUT_DIR, "mvp-benchmark-dashboard.html")
    with open(dash_path, "w", encoding="utf-8") as f:
        f.write(build_html_dashboard(charts))
    print(f"Wrote {dash_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
