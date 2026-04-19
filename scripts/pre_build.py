#!/usr/bin/env python3
# Pre-build script for PyOxidizer

import os
import sys

def pre_build():
    """Pre-build operations - check environment and prepare build"""
    print("Running pre-build operations...")

    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    print(f"Python version: {sys.version}")

    # Check Rust installation
    try:
        import subprocess
        result = subprocess.run(['rustc', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Rust version: {result.stdout.strip()}")
        else:
            print("Warning: Rust not found. Please install Rust from https://rustup.rs/")
    except FileNotFoundError:
        print("Warning: Rust not found. Please install Rust from https://rustup.rs/")

    # Check PyOxidizer installation
    try:
        result = subprocess.run(['pyoxidizer', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"PyOxidizer version: {result.stdout.strip()}")
        else:
            print("Warning: PyOxidizer not found. Installing via cargo...")
            install_pyoxidizer()
    except FileNotFoundError:
        print("Warning: PyOxidizer not found. Installing via cargo...")
        install_pyoxidizer()

    # Verify required files exist
    required_files = [
        "server.py",
        "init_app.py",
        "rsa_key_generator.py",
        "requirements.txt",
    ]

    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
        else:
            print(f"Found required file: {file}")

    if missing_files:
        print(f"Error: Missing required files: {missing_files}")
        sys.exit(1)

    # Verify required directories exist
    required_dirs = [
        "static",
        "templates",
        "lang",
        "key",
    ]

    for dir in required_dirs:
        if os.path.exists(dir):
            print(f"Found required directory: {dir}")
        else:
            print(f"Warning: Directory '{dir}' not found, creating...")
            os.makedirs(dir, exist_ok=True)

    print("Pre-build operations completed successfully!")

def install_pyoxidizer():
    """Install PyOxidizer via cargo"""
    try:
        import subprocess
        print("Installing PyOxidizer via cargo (this may take a while)...")
        result = subprocess.run(
            ['cargo', 'install', 'pyoxidizer'],
            capture_output=True,
            text=True,
            timeout=600
        )
        if result.returncode == 0:
            print("PyOxidizer installed successfully!")
        else:
            print(f"Failed to install PyOxidizer: {result.stderr}")
            print("Please install manually: cargo install pyoxidizer")
    except FileNotFoundError:
        print("Error: cargo not found. Please install Rust from https://rustup.rs/")
    except subprocess.TimeoutExpired:
        print("Installation timed out. Please install manually: cargo install pyoxidizer")
    except Exception as e:
        print(f"Error installing PyOxidizer: {e}")

if __name__ == "__main__":
    pre_build()
