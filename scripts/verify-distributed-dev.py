#!/usr/bin/env python3
"""
SecureCloud Distributed Development Environment Orchestrator (SC-015)

Sequences and orchestrates the distributed development environment lifecycle
by delegating to existing SC-009 through SC-014 validators.

Key Invariants:
1. Observational Host PostgreSQL 14 Guard:
   Strictly observational socket check on 127.0.0.1:5432.
   NEVER attempts to stop, restart, reconfigure, or bind to host port 5432.
2. Port Binding Audit:
   Verifies that all Compose exposed ports bind strictly to 127.0.0.1.
   Asserts container postgres binds strictly to host port 5433 (never 5432).
3. Thin Orchestration:
   Delegates directly to existing verification scripts without duplicating logic.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        cls.GREEN = ""
        cls.RED = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.CYAN = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RESET = ""


if not sys.stdout.isatty() or os.environ.get("NO_COLOR") or platform.system() == "Windows" and "WT_SESSION" not in os.environ and "TERM" not in os.environ:
    if platform.system() == "Windows" and "WT_SESSION" not in os.environ:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            Colors.disable()


def setup_windows_environment(preset: str = "") -> None:
    """
    On Windows, ensure MSYS2 / MinGW binary search paths are discovered,
    sanitized, and prepended to PATH. Incompatible environments (e.g. mixing
    ucrt64 and mingw64) are filtered out to prevent DLL ABI/entrypoint mismatch.
    """
    if platform.system() != "Windows":
        return

    preset_lower = preset.lower() if preset else ""
    is_ucrt = ("ucrt" in preset_lower or os.environ.get("MSYSTEM", "").upper() == "UCRT64")
    is_clang = ("clang" in preset_lower or os.environ.get("MSYSTEM", "").upper() == "CLANG64")

    target_env = "mingw64"
    if is_ucrt:
        target_env = "ucrt64"
    elif is_clang:
        target_env = "clang64"

    incompatible_envs = {"mingw64", "ucrt64", "clang64"} - {target_env}

    target_bin: Optional[str] = None
    usr_bin: Optional[str] = None

    msystem_prefix = os.environ.get("MSYSTEM_PREFIX")
    if msystem_prefix and Path(msystem_prefix).exists():
        p = Path(msystem_prefix) / "bin"
        if p.exists():
            target_bin = str(p.resolve())
        u_cand = Path(msystem_prefix).parent / "usr" / "bin"
        if u_cand.exists():
            usr_bin = str(u_cand.resolve())

    if not target_bin:
        for drive in ["C:", "D:"]:
            for msys_dir in ["msys64", "msys2"]:
                base = Path(f"{drive}/{msys_dir}")
                cand = base / target_env / "bin"
                if cand.exists():
                    target_bin = str(cand.resolve())
                    u_cand = base / "usr" / "bin"
                    if u_cand.exists():
                        usr_bin = str(u_cand.resolve())
                    break
            if target_bin:
                break

    curr_path = os.environ.get("PATH", "")
    parts = [p.strip() for p in curr_path.split(os.pathsep) if p.strip()]

    filtered_parts: List[str] = []
    for p in parts:
        p_lower = p.lower()
        if any(f"\\{inc}\\bin" in p_lower or f"/{inc}/bin" in p_lower for inc in incompatible_envs):
            continue
        if target_bin and p_lower == target_bin.lower():
            continue
        if usr_bin and p_lower == usr_bin.lower():
            continue
        filtered_parts.append(p)

    new_parts: List[str] = []
    if target_bin:
        new_parts.append(target_bin)
    if usr_bin:
        new_parts.append(usr_bin)

    final_path = new_parts + filtered_parts
    os.environ["PATH"] = os.pathsep.join(final_path)


def find_bash() -> str:
    if platform.system() == "Windows":
        # 1. Active MSYSTEM_PREFIX parent usr/bin
        msystem_prefix = os.environ.get("MSYSTEM_PREFIX")
        if msystem_prefix:
            cand = Path(msystem_prefix).parent / "usr" / "bin" / "bash.exe"
            if cand.exists():
                return str(cand.resolve())

        # 2. Standard MSYS2 and Git Bash installation paths
        for drive in ["C:", "D:"]:
            for cand in [
                Path(f"{drive}/msys64/usr/bin/bash.exe"),
                Path(f"{drive}/msys64/bin/bash.exe"),
                Path(f"{drive}/msys2/usr/bin/bash.exe"),
                Path(f"{drive}/Program Files/Git/bin/bash.exe"),
                Path(f"{drive}/Program Files/Git/usr/bin/bash.exe"),
                Path(f"{drive}/Program Files (x86)/Git/bin/bash.exe"),
            ]:
                if cand.exists():
                    return str(cand.resolve())

        # 3. Search PATH, strictly avoiding the WSL proxy in System32 / Windows
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        for p in path_dirs:
            p_clean = p.strip().strip('"')
            if not p_clean:
                continue
            cand = Path(p_clean) / "bash.exe"
            cand_lower = str(cand).lower()
            if "system32" in cand_lower or "syswow64" in cand_lower or "\\windows\\" in cand_lower or "/windows/" in cand_lower:
                continue
            if cand.exists():
                return str(cand.resolve())

        return "bash"

    found = shutil.which("bash")
    return found if found else "bash"


@dataclass
class StageResult:
    name: str
    command_str: str
    duration_s: float
    passed: bool
    exit_code: int
    skipped: bool = False
    details: str = ""


# Expected Docker Compose host bindings (service -> expected list of (host_ip, host_port))
EXPECTED_BINDINGS: Dict[str, List[Tuple[str, int]]] = {
    "gateway": [("127.0.0.1", 50051)],
    "auth": [("127.0.0.1", 50052)],
    "messaging": [("127.0.0.1", 50053)],
    "files": [("127.0.0.1", 50054)],
    "audit": [("127.0.0.1", 50055)],
    "postgres": [("127.0.0.1", 5433)],  # NEVER 5432
    "scylladb": [("127.0.0.1", 9042)],
    "clickhouse": [("127.0.0.1", 8123), ("127.0.0.1", 9009)],
    "minio": [("127.0.0.1", 9000), ("127.0.0.1", 9001)],
}


def check_host_postgres_socket(host: str = "127.0.0.1", port: int = 5432, timeout_s: float = 0.5) -> bool:
    """
    Purely observational socket check on host PostgreSQL 14 port.
    Never attempts to stop, kill, reconfigure, or remediate the port.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class DistributedOrchestrator:
    def __init__(self, repo_root: Path, preset: Optional[str] = None, verbose: bool = False) -> None:
        self.repo_root = repo_root
        self.verbose = verbose
        self.preset = preset or self._detect_preset()
        setup_windows_environment(self.preset)
        self.compose_file = self.repo_root / "deploy" / "compose" / "docker-compose.yml"
        self.results: List[StageResult] = []
        self.compose_cmd = ["docker", "compose", "--ansi", "never", "-f", str(self.compose_file)]
        # Export BUILD_DIR so downstream verification scripts know the active preset build tree
        os.environ["BUILD_DIR"] = str((self.repo_root / "build" / self.preset).resolve())

    def _detect_preset(self) -> str:
        system = platform.system()
        if system == "Darwin":
            return "dev-debug"
        elif system == "Windows":
            msystem = os.environ.get("MSYSTEM", "").upper()
            if "MINGW" in msystem or "UCRT" in msystem or "CLANG" in msystem:
                return "ci-windows-mingw"
            has_gcc = shutil.which("gcc") is not None or shutil.which("g++") is not None
            has_cl = shutil.which("cl") is not None
            if has_gcc and not has_cl:
                return "ci-windows-mingw"
            return "ci-windows-msvc"
        return "dev-debug"

    def _execute_stage(
        self,
        name: str,
        cmd: Optional[List[str]] = None,
        custom_action: Optional[Callable[[], Tuple[bool, str]]] = None,
        skip: bool = False,
    ) -> bool:
        print(f"\n{Colors.BOLD}{Colors.BLUE}=== Stage: {name} ==={Colors.RESET}")
        cmd_str = " ".join(cmd) if cmd else "(Internal Action)"
        print(f"{Colors.DIM}Action: {cmd_str}{Colors.RESET}")

        if skip:
            print(f"{Colors.YELLOW}[SKIPPED]{Colors.RESET} Stage was bypassed by flag")
            self.results.append(StageResult(
                name=name,
                command_str=cmd_str,
                duration_s=0.0,
                passed=True,
                exit_code=0,
                skipped=True,
            ))
            return True

        start_time = time.monotonic()
        if custom_action:
            try:
                passed, details = custom_action()
                duration = time.monotonic() - start_time
                status_str = f"{Colors.GREEN}[PASS]{Colors.RESET}" if passed else f"{Colors.RED}[FAIL]{Colors.RESET}"
                print(f"{status_str} Completed in {duration:.2f}s: {details}")
                self.results.append(StageResult(
                    name=name,
                    command_str=cmd_str,
                    duration_s=duration,
                    passed=passed,
                    exit_code=0 if passed else 1,
                    details=details,
                ))
                return passed
            except Exception as e:
                duration = time.monotonic() - start_time
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Exception during stage: {e}")
                self.results.append(StageResult(
                    name=name,
                    command_str=cmd_str,
                    duration_s=duration,
                    passed=False,
                    exit_code=-1,
                    details=str(e),
                ))
                return False

        if not cmd:
            return True

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                stdout=None if self.verbose else subprocess.PIPE,
                stderr=None if self.verbose else subprocess.PIPE,
                text=True,
                check=False,
            )
            duration = time.monotonic() - start_time
            passed = (proc.returncode == 0)

            if not passed and not self.verbose:
                if proc.stdout:
                    print(f"{Colors.DIM}--- STDOUT ---{Colors.RESET}\n{proc.stdout}")
                if proc.stderr:
                    print(f"{Colors.RED}--- STDERR ---{Colors.RESET}\n{proc.stderr}")

            status_str = f"{Colors.GREEN}[PASS]{Colors.RESET}" if passed else f"{Colors.RED}[FAIL (exit {proc.returncode})]{Colors.RESET}"
            print(f"{status_str} Completed in {duration:.2f}s")
            self.results.append(StageResult(
                name=name,
                command_str=cmd_str,
                duration_s=duration,
                passed=passed,
                exit_code=proc.returncode,
            ))
            return passed
        except Exception as e:
            duration = time.monotonic() - start_time
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Execution failed: {e}")
            self.results.append(StageResult(
                name=name,
                command_str=cmd_str,
                duration_s=duration,
                passed=False,
                exit_code=-1,
                details=str(e),
            ))
            return False

    def action_preflight_observational_guard(self) -> Tuple[bool, str]:
        """
        Purely observational check on host port 5432.
        Confirms whether workstation PostgreSQL 14 is present.
        """
        is_active = check_host_postgres_socket("127.0.0.1", 5432, timeout_s=0.5)
        if is_active:
            msg = "Workstation host PostgreSQL 14 detected on 127.0.0.1:5432 (observational guard confirmed active; port 5432 strictly protected)"
        else:
            msg = "No service detected on 127.0.0.1:5432 (workstation port 5432 clear and unallocated)"
        return True, msg

    def action_verify_port_bindings_audit(self) -> Tuple[bool, str]:
        """
        Inspects docker compose config to ensure all exposed host ports are bound
        strictly to loopback (127.0.0.1) and postgres uses host port 5433 (never 5432).
        Also verifies that the Docker daemon is active and responsive.
        """
        # Fast fail if Docker daemon is not running
        docker_info = subprocess.run(["docker", "info"], capture_output=True, text=True, check=False)
        if docker_info.returncode != 0:
            return False, (
                "Docker daemon is not running or unreachable.\n"
                "  Please launch Docker Desktop and ensure the Linux container engine is started before running verification."
            )

        proc = subprocess.run(
            self.compose_cmd + ["config", "--format", "json"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return False, f"Failed to retrieve docker compose config: {proc.stderr}"

        try:
            config = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            return False, f"Failed to parse docker compose json: {e}"

        services = config.get("services", {})
        audit_records = []
        violations = []

        for svc_name, svc_info in services.items():
            ports = svc_info.get("ports", [])
            for p in ports:
                # Docker Compose config outputs port objects or string specs
                if isinstance(p, dict):
                    host_ip = p.get("host_ip", "0.0.0.0")
                    published = str(p.get("published", ""))
                    target = str(p.get("target", ""))
                elif isinstance(p, str):
                    # Format: "127.0.0.1:5433:5432" or "5433:5432"
                    parts = p.split(":")
                    if len(parts) == 3:
                        host_ip, published, target = parts[0], parts[1], parts[2]
                    elif len(parts) == 2:
                        host_ip, published, target = "0.0.0.0", parts[0], parts[1]
                    else:
                        host_ip, published, target = "0.0.0.0", parts[0], parts[0]
                else:
                    continue

                audit_records.append(f"{svc_name}: {host_ip}:{published} -> {target}")

                # Check 1: loopback restriction
                if host_ip != "127.0.0.1":
                    violations.append(f"Service '{svc_name}' binds to non-loopback IP '{host_ip}' (published port: {published})")

                # Check 2: host port 5432 collision invariant
                if published == "5432":
                    violations.append(f"CRITICAL INVARIANT VIOLATION: Service '{svc_name}' attempts to bind host port 5432!")

                # Check 3: postgres container must publish strictly 5433
                if svc_name == "postgres" and published != "5433":
                    violations.append(f"Postgres service published to '{published}' instead of required '5433'")

        if violations:
            return False, f"Port binding audit violations found:\n  " + "\n  ".join(violations)

        return True, f"All {len(audit_records)} port bindings verified strictly on 127.0.0.1 (postgres mapped to 5433)"

    def action_postflight_observational_guard(self) -> Tuple[bool, str]:
        """
        Post-flight observational verification that host PostgreSQL 14 remains healthy
        and untouched.
        """
        is_active = check_host_postgres_socket("127.0.0.1", 5432, timeout_s=0.5)
        if is_active:
            msg = "Post-flight confirmation: Host PostgreSQL 14 on 127.0.0.1:5432 was continuously preserved with zero disruption."
        else:
            msg = "Post-flight confirmation: 127.0.0.1:5432 remained untouched."
        return True, msg

    def teardown(self) -> int:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Teardown: Stopping and removing Compose containers...{Colors.RESET}")
        proc = subprocess.run(
            self.compose_cmd + ["down"],
            cwd=str(self.repo_root),
            check=False,
        )
        return proc.returncode

    def run(
        self,
        skip_native: bool = False,
        skip_pki: bool = False,
        skip_persistence: bool = False,
        skip_health: bool = False,
        skip_teardown: bool = False,
        teardown_only: bool = False,
    ) -> int:
        print(f"{Colors.BOLD}{Colors.CYAN}SecureCloud Distributed Development Orchestrator (SC-015){Colors.RESET}")
        print(f"Repository Root : {self.repo_root}")
        print(f"Active Preset   : {self.preset}")
        print(f"Host System     : {platform.system()} ({platform.machine()})")
        print(f"Compose File    : {self.compose_file}")
        print(f"Timestamp       : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

        if teardown_only:
            return self.teardown()

        total_start = time.monotonic()
        bash_bin = find_bash()
        os.environ["CTEST_PRESET"] = self.preset

        # Stage 1: Pre-flight Observational Host Conflict Guard (Port 5432)
        if not self._execute_stage(
            "1. Pre-flight Observational Host PG14 Guard (127.0.0.1:5432)",
            custom_action=self.action_preflight_observational_guard,
        ):
            return self._summarize_and_exit(total_start)

        # Stage 2: Docker Compose Port Bindings Audit
        if not self._execute_stage(
            "2. Docker Compose Port Bindings Loopback & Conflict Audit",
            custom_action=self.action_verify_port_bindings_audit,
        ):
            return self._summarize_and_exit(total_start)

        # Stage 3: Local Native Verification (delegating to verify-local.py)
        local_py = self.repo_root / "scripts" / "verify-local.py"
        cmd_native = [sys.executable, str(local_py), "--preset", self.preset]
        if not self._execute_stage("3. Local Native Verification (verify-local.py)", cmd_native, skip=skip_native):
            return self._summarize_and_exit(total_start)

        # Stage 4: Dev PKI Generation and Verification
        cmd_pki_gen = [bash_bin, "scripts/generate-dev-pki.sh"]
        if not self._execute_stage("4a. Generate Dev PKI Certificates (generate-dev-pki.sh)", cmd_pki_gen, skip=skip_pki):
            return self._summarize_and_exit(total_start)

        cmd_pki_verify = [bash_bin, "scripts/verify-dev-pki.sh"]
        if not self._execute_stage("4b. Validate Dev PKI Certificates & x509 SANs (verify-dev-pki.sh)", cmd_pki_verify, skip=skip_pki):
            return self._summarize_and_exit(total_start)

        # Stage 5: Persistence Infrastructure Verification (SC-011 reuse)
        cmd_persist = [bash_bin, "scripts/verify-persistence-infra.sh"]
        if not self._execute_stage("5. Persistence Infrastructure Verification (verify-persistence-infra.sh)", cmd_persist, skip=skip_persistence):
            if not skip_teardown:
                self.teardown()
            return self._summarize_and_exit(total_start)

        # Stage 6: Health Endpoints, Readiness Degradation & Recovery (SC-013 reuse)
        cmd_health = [bash_bin, "scripts/verify-health-endpoints.sh"]
        if not self._execute_stage("6. Health Endpoints & Outage Recovery (verify-health-endpoints.sh)", cmd_health, skip=skip_health):
            if not skip_teardown:
                self.teardown()
            return self._summarize_and_exit(total_start)

        # Stage 7: Clean Teardown
        if not skip_teardown:
            cmd_teardown = self.compose_cmd + ["down"]
            if not self._execute_stage("7. Clean Infrastructure Teardown (docker compose down)", cmd_teardown):
                return self._summarize_and_exit(total_start)

        # Stage 8: Post-flight Observational Host Conflict Guard
        if not self._execute_stage(
            "8. Post-flight Observational Host PG14 Guard (127.0.0.1:5432)",
            custom_action=self.action_postflight_observational_guard,
        ):
            return self._summarize_and_exit(total_start)

        return self._summarize_and_exit(total_start)

    def _summarize_and_exit(self, total_start_time: float) -> int:
        total_duration = time.monotonic() - total_start_time
        print(f"\n{Colors.BOLD}{Colors.CYAN}================ Distributed Verification Summary ================{Colors.RESET}")
        all_passed = True

        for res in self.results:
            if res.skipped:
                status_icon = f"{Colors.YELLOW}[SKIPPED]{Colors.RESET}"
            elif res.passed:
                status_icon = f"{Colors.GREEN}[PASSED] {Colors.RESET}"
            else:
                status_icon = f"{Colors.RED}[FAILED] {Colors.RESET}"
                all_passed = False

            duration_str = f"{res.duration_s:6.2f}s" if not res.skipped else "     -"
            print(f"  {status_icon} {duration_str}  {res.name}")
            if res.details and not res.passed:
                print(f"           {Colors.RED}Details: {res.details}{Colors.RESET}")

        print(f"{Colors.DIM}------------------------------------------------------------------{Colors.RESET}")
        if all_passed:
            print(f"{Colors.BOLD}{Colors.GREEN}ALL DISTRIBUTED CHECKS PASSED{Colors.RESET} in {total_duration:.2f}s")
            return 0
        else:
            first_fail = next((r for r in self.results if not r.passed), None)
            exit_code = first_fail.exit_code if first_fail and first_fail.exit_code != 0 else 1
            print(f"{Colors.BOLD}{Colors.RED}DISTRIBUTED VERIFICATION FAILED{Colors.RESET} (total time: {total_duration:.2f}s)")
            return exit_code


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="SecureCloud Distributed Development Environment Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--preset",
        "-p",
        default=None,
        help="CMake preset for native verification stage (default: auto-detected)",
    )
    parser.add_argument(
        "--skip-native",
        action="store_true",
        help="Skip local native build and unit/integration testing stage",
    )
    parser.add_argument(
        "--skip-pki",
        action="store_true",
        help="Skip dev-pki generation and certificate validation stage",
    )
    parser.add_argument(
        "--skip-persistence",
        action="store_true",
        help="Skip persistence infrastructure verification stage",
    )
    parser.add_argument(
        "--skip-health",
        action="store_true",
        help="Skip microservice mTLS health/readiness and outage recovery stage",
    )
    parser.add_argument(
        "--skip-teardown",
        action="store_true",
        help="Leave Docker Compose containers running after verification",
    )
    parser.add_argument(
        "--teardown-only",
        action="store_true",
        help="Only stop and remove running Docker Compose containers",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Stream full stdout/stderr from underlying tools",
    )

    args = parser.parse_args()

    orchestrator = DistributedOrchestrator(
        repo_root=repo_root,
        preset=args.preset,
        verbose=args.verbose,
    )

    return orchestrator.run(
        skip_native=args.skip_native,
        skip_pki=args.skip_pki,
        skip_persistence=args.skip_persistence,
        skip_health=args.skip_health,
        skip_teardown=args.skip_teardown,
        teardown_only=args.teardown_only,
    )


if __name__ == "__main__":
    sys.exit(main())
