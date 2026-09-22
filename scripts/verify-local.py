#!/usr/bin/env python3
"""
SecureCloud Local Developer Verification Orchestrator

Unified, cross-platform orchestrator for local pre-commit and developer
verification across macOS, Windows (MSVC/MinGW), and Linux.

This script is strictly an ORCHESTRATOR: it consumes CMakePresets.json,
existing CMake targets (check-format, verify-contracts), and test suites.
It does NOT duplicate compiler flags, dependency resolution, or build logic.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


# ANSI Colors (disabled if non-interactive or on unsupported terminals)
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
    # Basic ANSI support check; modern Windows Terminal supports ANSI
    if platform.system() == "Windows" and "WT_SESSION" not in os.environ:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            Colors.disable()


@dataclass
class StageResult:
    name: str
    command: List[str]
    duration_s: float
    passed: bool
    exit_code: int
    skipped: bool = False
    details: str = ""


class VerificationOrchestrator:
    def __init__(self, repo_root: Path, preset: str, verbose: bool = False) -> None:
        self.repo_root = repo_root
        self.preset = preset
        self.verbose = verbose
        setup_windows_environment(self.preset)
        self.presets_data = self._load_presets()
        self.results: List[StageResult] = []

    def _load_presets(self) -> dict:
        presets_file = self.repo_root / "CMakePresets.json"
        if not presets_file.exists():
            raise FileNotFoundError(f"CMakePresets.json not found at {presets_file}")
        with open(presets_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def validate_preset(self) -> bool:
        configure_presets = [p["name"] for p in self.presets_data.get("configurePresets", [])]
        return self.preset in configure_presets

    def get_available_presets(self) -> List[str]:
        return [p["name"] for p in self.presets_data.get("configurePresets", [])]

    def _execute_stage(self, name: str, command: List[str], skip: bool = False) -> bool:
        print(f"\n{Colors.BOLD}{Colors.BLUE}=== Stage: {name} ==={Colors.RESET}")
        cmd_str = " ".join(command)
        print(f"{Colors.DIM}Command: {cmd_str}{Colors.RESET}")

        if skip:
            print(f"{Colors.YELLOW}[SKIPPED]{Colors.RESET} Stage was bypassed by flag")
            self.results.append(StageResult(
                name=name,
                command=command,
                duration_s=0.0,
                passed=True,
                exit_code=0,
                skipped=True,
            ))
            return True

        start_time = time.monotonic()
        try:
            proc = subprocess.run(
                command,
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
                command=command,
                duration_s=duration,
                passed=passed,
                exit_code=proc.returncode,
            ))
            return passed
        except Exception as e:
            duration = time.monotonic() - start_time
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to execute: {e}")
            self.results.append(StageResult(
                name=name,
                command=command,
                duration_s=duration,
                passed=False,
                exit_code=-1,
                details=str(e),
            ))
            return False

    def run(
        self,
        skip_configure: bool = False,
        skip_format: bool = False,
        skip_build: bool = False,
        skip_contracts: bool = False,
        skip_tests: bool = False,
        run_tidy: bool = False,
        run_full: bool = False,
    ) -> int:
        print(f"{Colors.BOLD}{Colors.CYAN}SecureCloud Local Developer Verification Orchestrator{Colors.RESET}")
        print(f"Repository Root : {self.repo_root}")
        print(f"Target Preset   : {Colors.BOLD}{self.preset}{Colors.RESET}")
        print(f"Host System     : {platform.system()} ({platform.machine()})")
        print(f"Timestamp       : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

        total_start = time.monotonic()

        # Stage 1: Configure
        cmd_config = ["cmake", "--preset", self.preset]
        if run_tidy:
            cmd_config.append("-DENABLE_CLANG_TIDY=ON")
        if not self._execute_stage("1. CMake Configure", cmd_config, skip=skip_configure):
            return self._summarize_and_exit(total_start)

        # Stage 2: Formatting Check
        cmd_format = ["cmake", "--build", "--preset", self.preset, "--target", "check-format"]
        if not self._execute_stage("2. Formatting Check (.clang-format)", cmd_format, skip=skip_format):
            print(f"\n{Colors.YELLOW}Hint: Run 'cmake --build --preset {self.preset} --target format' to format code in-place.{Colors.RESET}")
            return self._summarize_and_exit(total_start)

        # Stage 3: Build
        cmd_build = ["cmake", "--build", "--preset", self.preset]
        if not self._execute_stage("3. Native Compilation & Build", cmd_build, skip=skip_build):
            return self._summarize_and_exit(total_start)

        # Stage 4: Contracts Validation
        cmd_contracts = ["cmake", "--build", "--preset", self.preset, "--target", "verify-contracts"]
        if not self._execute_stage("4. Protobuf & gRPC Contracts Validation", cmd_contracts, skip=skip_contracts):
            return self._summarize_and_exit(total_start)

        # Stage 5: Test Suite (CTest)
        pki_ca = self.repo_root / "deploy" / "dev-pki" / "ca" / "ca.crt"
        pki_script = self.repo_root / "scripts" / "generate-dev-pki.sh"
        if not pki_ca.exists() and pki_script.exists():
            import shutil
            bash_bin = shutil.which("bash")
            if bash_bin:
                subprocess.run([bash_bin, str(pki_script)], cwd=str(self.repo_root), check=False)

        cmd_test = ["ctest", "--preset", self.preset, "--output-on-failure"]
        if not self._execute_stage("5. CTest Execution Suite", cmd_test, skip=skip_tests):
            return self._summarize_and_exit(total_start)

        # Stage 6 (Optional/Full): Static Scripts Verification
        if run_full:
            # Run dev-pki validation
            verify_pki_script = self.repo_root / "scripts" / "verify-dev-pki.sh"
            if verify_pki_script.exists() and platform.system() != "Windows":
                cmd_pki = ["bash", str(verify_pki_script)]
                if not self._execute_stage("6a. Dev PKI Infrastructure Verification", cmd_pki):
                    return self._summarize_and_exit(total_start)

            # Run service config validation
            verify_cfg_script = self.repo_root / "scripts" / "verify-service-config.sh"
            if verify_cfg_script.exists() and platform.system() != "Windows":
                cmd_cfg = ["bash", str(verify_cfg_script)]
                if not self._execute_stage("6b. Service Configuration Boundaries Validation", cmd_cfg):
                    return self._summarize_and_exit(total_start)

        return self._summarize_and_exit(total_start)

    def _summarize_and_exit(self, total_start_time: float) -> int:
        total_duration = time.monotonic() - total_start_time
        print(f"\n{Colors.BOLD}{Colors.CYAN}================ Verification Summary ================{Colors.RESET}")
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

        print(f"{Colors.DIM}-----------------------------------------------------{Colors.RESET}")
        if all_passed:
            print(f"{Colors.BOLD}{Colors.GREEN}ALL CHECKS PASSED{Colors.RESET} in {total_duration:.2f}s")
            return 0
        else:
            first_fail = next((r for r in self.results if not r.passed), None)
            exit_code = first_fail.exit_code if first_fail and first_fail.exit_code != 0 else 1
            print(f"{Colors.BOLD}{Colors.RED}VERIFICATION FAILED{Colors.RESET} (total time: {total_duration:.2f}s)")
            return exit_code


def setup_windows_environment(preset: str = "") -> None:
    """
    On Windows, ensure MSYS2 / MinGW binary search paths are discovered,
    sanitized, and prepended to PATH. Incompatible environments (e.g. mixing
    ucrt64 and mingw64) are filtered out to prevent DLL ABI/entrypoint mismatch.
    """
    if platform.system() != "Windows":
        return

    # Determine preferred MSYS2 environment
    preset_lower = preset.lower() if preset else ""
    is_ucrt = ("ucrt" in preset_lower or os.environ.get("MSYSTEM", "").upper() == "UCRT64")
    is_clang = ("clang" in preset_lower or os.environ.get("MSYSTEM", "").upper() == "CLANG64")

    target_env = "mingw64"
    if is_ucrt:
        target_env = "ucrt64"
    elif is_clang:
        target_env = "clang64"

    # Identify incompatible environments that should NOT be in PATH
    incompatible_envs = {"mingw64", "ucrt64", "clang64"} - {target_env}

    # Discover candidate installation directory
    target_bin: Optional[str] = None
    usr_bin: Optional[str] = None

    # Check MSYSTEM_PREFIX if active
    msystem_prefix = os.environ.get("MSYSTEM_PREFIX")
    if msystem_prefix and Path(msystem_prefix).exists():
        p = Path(msystem_prefix) / "bin"
        if p.exists():
            target_bin = str(p.resolve())

    # Check drive candidates
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

    # Clean existing PATH
    curr_path = os.environ.get("PATH", "")
    parts = [p.strip() for p in curr_path.split(os.pathsep) if p.strip()]

    # Filter out incompatible MSYS2 directories from PATH to prevent DLL pollution
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

    # Prepend target_bin and usr_bin to the VERY FRONT of PATH
    new_parts: List[str] = []
    if target_bin:
        new_parts.append(target_bin)
    if usr_bin:
        new_parts.append(usr_bin)

    # If ninja is not in PATH, probe VS bundled Ninja
    import shutil
    has_ninja = (shutil.which("ninja") is not None)
    if not has_ninja:
        for drive in ["C:", "D:"]:
            for prog in ["Program Files", "Program Files (x86)"]:
                for edition in ["Community", "Professional", "Enterprise", "BuildTools"]:
                    cand = Path(f"{drive}/{prog}/Microsoft Visual Studio/2022/{edition}/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe")
                    if cand.exists():
                        new_parts.append(str(cand.parent.resolve()))
                        break

    final_path = new_parts + filtered_parts
    os.environ["PATH"] = os.pathsep.join(final_path)


def auto_detect_preset() -> str:
    setup_windows_environment()
    system = platform.system()
    if system == "Darwin":
        return "ci-macos"
    elif system == "Windows":
        # Check if MinGW / MSYS2 / GCC environment is active
        msystem = os.environ.get("MSYSTEM", "").upper()
        if "MINGW" in msystem or "UCRT" in msystem or "CLANG" in msystem:
            return "ci-windows-mingw"

        import shutil
        has_gcc = (shutil.which("gcc") is not None or shutil.which("g++") is not None)
        has_cl = (shutil.which("cl") is not None)

        if has_gcc and not has_cl:
            return "ci-windows-mingw"

        if not has_cl and not has_gcc:
            # Probe standard MSYS2 MinGW / UCRT installation paths
            for candidate in [
                Path("C:/msys64/mingw64/bin/g++.exe"),
                Path("C:/msys64/ucrt64/bin/g++.exe"),
                Path("C:/msys64/clang64/bin/clang++.exe"),
            ]:
                if candidate.exists():
                    return "ci-windows-mingw"

        return "ci-windows-msvc"
    elif system == "Linux":
        return "ci-linux"
    return "dev-debug"


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="SecureCloud Local Developer Verification Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--preset",
        "-p",
        default=None,
        help="CMake preset to execute (default: auto-detected platform preset on Windows, dev-debug on POSIX)",
    )
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Force auto-detect preset based on host platform (ci-macos, ci-windows-mingw, ci-windows-msvc, etc.)",
    )
    parser.add_argument(
        "--list-presets",
        action="store_true",
        help="List available presets in CMakePresets.json and exit",
    )
    parser.add_argument(
        "--skip-configure",
        action="store_true",
        help="Skip the CMake configure stage",
    )
    parser.add_argument(
        "--skip-format",
        action="store_true",
        help="Skip the .clang-format check stage",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip the compilation/build stage",
    )
    parser.add_argument(
        "--skip-contracts",
        action="store_true",
        help="Skip the Protobuf & gRPC generated contracts check",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip the CTest execution suite",
    )
    parser.add_argument(
        "--tidy",
        action="store_true",
        help="Enable clang-tidy static analysis during configure/build",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Execute extended verification scripts (dev-pki, service config) if on POSIX",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Stream full stdout/stderr from underlying tools",
    )

    args = parser.parse_args()

    setup_windows_environment()

    if args.preset:
        preset = args.preset
    elif args.detect or platform.system() == "Windows":
        preset = auto_detect_preset()
    else:
        preset = "dev-debug"
    orchestrator = VerificationOrchestrator(repo_root, preset=preset, verbose=args.verbose)

    if args.list_presets:
        print(f"Available configure presets in {repo_root / 'CMakePresets.json'}:")
        for p in orchestrator.get_available_presets():
            marker = " (selected)" if p == preset else ""
            print(f"  - {p}{marker}")
        return 0

    if not orchestrator.validate_preset():
        print(f"{Colors.RED}Error: Preset '{preset}' not found in CMakePresets.json{Colors.RESET}")
        print(f"Available presets: {', '.join(orchestrator.get_available_presets())}")
        return 1

    return orchestrator.run(
        skip_configure=args.skip_configure,
        skip_format=args.skip_format,
        skip_build=args.skip_build,
        skip_contracts=args.skip_contracts,
        skip_tests=args.skip_tests,
        run_tidy=args.tidy,
        run_full=args.full,
    )


if __name__ == "__main__":
    sys.exit(main())
