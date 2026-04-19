#!/usr/bin/env python3
# Post-build script for PyOxidizer

import os
import shutil
import zipfile
import tarfile
import platform

def post_build():
    """Post-build operations - process build artifacts"""
    print("Running post-build operations...")

    # Determine current platform
    current_system = platform.system().lower()
    print(f"Current system: {current_system}")

    # Process each build directory
    build_dirs = [
        ("windows", "x86_64", "file-share-platform.exe"),
        ("linux", "x86_64", "file-share-platform"),
        ("linux", "aarch64", "file-share-platform"),
        ("macos", "x86_64", "file-share-platform"),
        ("macos", "aarch64", "file-share-platform"),
    ]

    for system, arch, executable in build_dirs:
        build_dir = f"build/{system}/{arch}"
        if os.path.exists(build_dir):
            print(f"Processing build for {system}-{arch}...")

            # Create distribution directory
            dist_dir = create_dist_directory(system, arch, build_dir)

            # Copy necessary files to distribution directory
            copy_necessary_files(build_dir, dist_dir, system)

            # Create distribution package
            create_distribution_package(system, arch, dist_dir)
        else:
            print(f"Build directory not found: {build_dir}")

    print("Post-build operations completed successfully!")

def create_dist_directory(system, arch, build_dir):
    """Create distribution directory"""
    dist_dir = f"dist/file-share-platform-{system}-{arch}"

    if os.path.exists(dist_dir):
        print(f"Removing existing distribution directory: {dist_dir}")
        shutil.rmtree(dist_dir)

    os.makedirs(dist_dir, exist_ok=True)
    print(f"Created distribution directory: {dist_dir}")

    # Copy the executable
    exe_name = "file-share-platform.exe" if system == "windows" else "file-share-platform"
    src_exe = os.path.join(build_dir, exe_name)
    dst_exe = os.path.join(dist_dir, exe_name)

    if os.path.exists(src_exe):
        shutil.copy2(src_exe, dst_exe)
        print(f"Copied executable: {src_exe} -> {dst_exe}")

        # Make executable on Unix systems
        if system != "windows":
            os.chmod(dst_exe, 0o755)
            print(f"Set executable permission: {dst_exe}")
    else:
        print(f"Warning: Executable not found: {src_exe}")

    return dist_dir

def copy_necessary_files(build_dir, dist_dir, system):
    """Copy necessary files to distribution directory"""
    # Only copy essential files that cannot be auto-generated
    items_to_copy = [
        "static",
        "templates",
        "server.py",
        "init_app.py",
        "rsa_key_generator.py",
        "requirements.txt",
    ]

    for item in items_to_copy:
        src = item
        dst = os.path.join(dist_dir, item)

        if os.path.exists(src):
            if os.path.isdir(src):
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
                print(f"Copied directory: {src} -> {dst}")
            else:
                shutil.copy2(src, dst)
                print(f"Copied file: {src} -> {dst}")
        else:
            print(f"Warning: Source not found: {src}")

def create_distribution_package(system, arch, dist_dir):
    """Create distribution package"""
    package_name = f"file-share-platform-{system}-{arch}"

    # Get parent directory of dist_dir
    parent_dir = os.path.dirname(dist_dir)

    if system == "windows":
        # Create ZIP package for Windows
        zip_path = os.path.join(parent_dir, f"{package_name}.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(dist_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, dist_dir)
                    zipf.write(file_path, arcname)
        print(f"Created ZIP package: {zip_path}")
    else:
        # Create tar.gz package for Linux and macOS
        tar_path = os.path.join(parent_dir, f"{package_name}.tar.gz")
        with tarfile.open(tar_path, 'w:gz') as tarf:
            for root, _, files in os.walk(dist_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, dist_dir)
                    tarf.add(file_path, arcname)
        print(f"Created tar.gz package: {tar_path}")

if __name__ == "__main__":
    post_build()
