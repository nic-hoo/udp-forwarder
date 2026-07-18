#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build script: package server.py / client.py into single-file executables
using PyInstaller.

Usage:
    python build.py server     # build server only
    python build.py client     # build client only
    python build.py all        # build both (default)

Run this script on EACH target platform (Windows / Linux / macOS).
PyInstaller does not cross-compile.
"""

import os
import sys
import shutil
import subprocess

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))

# Each target: (script_relpath, display_name, config_relpath)
TARGETS = {
    "server": ("server/server.py", "server", "server/server_config.json"),
    "client": ("client/client.py", "client", "client/client_config.json"),
}

# Folders
BUILD_DIR = os.path.join(HERE, "build")
DIST_DIR = os.path.join(HERE, "dist")


def run(cmd, cwd=None):
    """Run a shell command, stream output to console."""
    print(f">>> {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, cwd=cwd, shell=False)
    if result.returncode != 0:
        print(f"[FAIL] Command exited with code {result.returncode}", flush=True)
        return False
    return True


def check_pyinstaller():
    """Ensure PyInstaller is importable."""
    try:
        import PyInstaller  # noqa: F401
        return True
    except ImportError:
        print("[ERROR] PyInstaller is not installed.")
        print("        Install it with:  pip install pyinstaller")
        return False


def clean_dirs(name):
    """Remove previous build artifacts for this target."""
    for d in (BUILD_DIR, DIST_DIR):
        if not os.path.isdir(d):
            continue
        # Remove target-specific subfolders
        for sub in (name, f"{name}.spec"):
            p = os.path.join(d, sub)
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            elif os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


def build_one(script_relpath, display_name):
    """Build a single target into a one-file executable."""
    script_path = os.path.join(HERE, script_relpath)
    if not os.path.isfile(script_path):
        print(f"[ERROR] Script not found: {script_path}")
        return False

    clean_dirs(display_name)

    # PyInstaller args
    # --onefile         : single executable
    # --clean           : clean PyInstaller cache
    # --noconfirm       : overwrite output without asking
    # --name            : output basename
    # --console         : keep console window (we are a CLI app)
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--clean",
        "--noconfirm",
        "--console",
        "--name", display_name,
        script_path,
    ]

    if not run(cmd, cwd=HERE):
        return False

    # Verify output exists
    ext = ".exe" if sys.platform == "win32" else ""
    out_path = os.path.join(DIST_DIR, f"{display_name}{ext}")
    if not os.path.isfile(out_path):
        print(f"[ERROR] Expected output not found: {out_path}")
        return False

    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"[OK]   Built: {out_path}  ({size_mb:.1f} MB)", flush=True)
    return True


def copy_sample_configs():
    """Copy sample configs next to the built executables for convenience."""
    for key, (script_relpath, display, cfg_relpath) in TARGETS.items():
        cfg_src = os.path.join(HERE, cfg_relpath)
        if os.path.isfile(cfg_src):
            cfg_dst = os.path.join(DIST_DIR, f"{display}_config.json")
            shutil.copy2(cfg_src, cfg_dst)
            print(f"[OK]   Copied: {cfg_dst}", flush=True)


def main():
    if not check_pyinstaller():
        return 1

    targets_arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    if targets_arg not in ("server", "client", "all"):
        print(f"Usage: python {os.path.basename(__file__)} [server|client|all]")
        return 1

    targets = list(TARGETS.keys()) if targets_arg == "all" else [targets_arg]

    print(f"Platform: {sys.platform}")
    print(f"Python:   {sys.version.split()[0]}")
    print(f"Targets:  {', '.join(targets)}")
    print("-" * 60)

    os.makedirs(DIST_DIR, exist_ok=True)

    success = True
    for key in targets:
        script_relpath, display_name, _cfg_relpath = TARGETS[key]
        print(f"\n=== Building {display_name} ===")
        if not build_one(script_relpath, display_name):
            success = False

    print("\n" + "=" * 60)
    if success:
        copy_sample_configs()
        print(f"\n[DONE] All targets built. Output in: {DIST_DIR}")
        print("\nNext steps:")
        print(f"  1. Copy executables + configs from dist/ to target machines")
        print(f"  2. Run the executable directly (no Python needed on target)")
        print(f"  3. Edit the *_config.json to change port mappings")
    else:
        print("\n[FAIL] Some targets failed. See messages above.")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
