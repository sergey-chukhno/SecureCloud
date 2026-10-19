#!/usr/bin/env python3
"""
SecureCloud Clang-Format Runner Script
Cross-platform execution wrapper for clang-format that avoids Windows command-line
length limits (8,191 chars) by batching file arguments safely across invocations.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def discover_clang_format(preferred_bin: Optional[str] = None) -> Optional[str]:
    """Find a valid clang-format executable."""
    if preferred_bin and preferred_bin.strip():
        # Check if the preferred binary actually exists and is executable
        cand = Path(preferred_bin.strip())
        if cand.is_file():
            return str(cand)
        which_cand = shutil.which(preferred_bin.strip())
        if which_cand:
            return which_cand

    # Common binary names
    names = [
        "clang-format",
        "clang-format-20",
        "clang-format-19",
        "clang-format-18",
        "clang-format-17",
    ]
    for name in names:
        path = shutil.which(name)
        if path:
            return path

    # Windows MSYS2 / UCRT64 / MinGW64 typical paths
    if sys.platform == "win32":
        win_hints = [
            Path("C:/msys64/ucrt64/bin/clang-format.exe"),
            Path("C:/msys64/mingw64/bin/clang-format.exe"),
            Path("C:/msys64/clang64/bin/clang-format.exe"),
            Path("C:/Program Files/LLVM/bin/clang-format.exe"),
        ]
        for hint in win_hints:
            if hint.is_file():
                return str(hint)

    return None


def collect_tooling_files(repo_root: Path) -> List[str]:
    """Authoritative file collection matching SecureCloudFormatting.cmake."""
    extensions = {".cpp", ".hpp", ".h"}
    excluded_dirs = {"build", "vcpkg_installed", ".git", ".gemini", "subprojects"}
    excluded_suffixes = {".pb.cc", ".pb.h"}

    collected: List[str] = []
    scan_dirs = [repo_root / "src", repo_root / "tests"]

    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for root, dirs, files in os.walk(scan_dir):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix in extensions:
                    # Check exclusions
                    if any(file.endswith(ex) for ex in excluded_suffixes):
                        continue
                    parts = file_path.parts
                    if any(ex in parts for ex in excluded_dirs):
                        continue
                    collected.append(str(file_path.resolve()))

    collected.sort()
    return collected


def chunk_list(items: List[str], chunk_size: int = 50) -> List[List[str]]:
    """Split items into sublists of size at most chunk_size."""
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureCloud clang-format runner")
    parser.add_argument(
        "--mode",
        choices=["check", "format"],
        required=True,
        help="'check' for read-only validation (--dry-run --Werror), 'format' for in-place reformatting (-i)",
    )
    parser.add_argument(
        "--binary",
        default=None,
        help="Path or name of clang-format executable",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Path to repository root (defaults to parent of scripts/)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Maximum files per clang-format execution (prevents Windows command length overflow)",
    )

    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve() if args.repo_root else Path(__file__).resolve().parent.parent
    clang_format = discover_clang_format(args.binary)

    if not clang_format:
        print(f"[SecureCloud] Warning: clang-format executable not found on this system.")
        if args.mode == "check":
            print(f"[SecureCloud] Formatting check skipped.")
            return 0
        else:
            print(f"[SecureCloud] Error: Cannot reformat files without clang-format.")
            return 1

    files = collect_tooling_files(repo_root)
    if not files:
        print("[SecureCloud] No C++ files found to format/check.")
        return 0

    batches = chunk_list(files, chunk_size=args.batch_size)
    total_violations = 0

    for batch in batches:
        cmd = [clang_format]
        if args.mode == "check":
            cmd.extend(["--dry-run", "--Werror"])
        elif args.mode == "format":
            cmd.append("-i")
        cmd.extend(batch)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                total_violations += 1
                if res.stdout:
                    print(res.stdout, end="")
                if res.stderr:
                    print(res.stderr, end="", file=sys.stderr)
        except Exception as e:
            print(f"[SecureCloud] Failed to execute clang-format: {e}", file=sys.stderr)
            return 1

    if args.mode == "check":
        if total_violations > 0:
            print(f"\n[SecureCloud] Formatting violations detected. Run format target to correct.")
            return 1
        else:
            print(f"[SecureCloud] All {len(files)} C++ files adhere to .clang-format.")
            return 0
    else:
        print(f"[SecureCloud] Successfully formatted {len(files)} C++ files in-place.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
