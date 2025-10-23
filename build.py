#!/usr/bin/env python3
"""
Build script for Disk Cleaner
Handles version bumping and packaging into executable
"""

import subprocess
import sys
import os
import json
from datetime import datetime

VERSION_FILE = os.path.join('version_manager', 'version_info.json')

def load_version_info():
    """Load current version info"""
    with open(VERSION_FILE, 'r') as f:
        return json.load(f)

def save_version_info(data):
    """Save updated version info"""
    with open(VERSION_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def parse_version(version_str):
    """Parse version string into major, minor, patch"""
    parts = version_str.split('.')
    return int(parts[0]), int(parts[1]), int(parts[2])

def bump_version(current_version, bump_type):
    """
    Bump version based on type
    major: 1.0.0 -> 2.0.0
    minor: 1.0.0 -> 1.1.0
    patch: 1.0.0 -> 1.0.1
    """
    major, minor, patch = parse_version(current_version)

    if bump_type == 'major':
        major += 1
        minor = 0
        patch = 0
    elif bump_type == 'minor':
        minor += 1
        patch = 0
    elif bump_type == 'patch':
        patch += 1
    else:
        raise ValueError(f"Invalid bump type: {bump_type}")

    return f"{major}.{minor}.{patch}"

def handle_version_bump():
    """Handle version bumping before build"""
    data = load_version_info()
    current_version = data['version']
    current_build = data['build_number']

    print(f"\nCurrent version: {current_version} (build {current_build})")
    print("\nDo you want to bump the version?")
    print("  major - Breaking changes (1.0.0 -> 2.0.0)")
    print("  minor - New features (1.0.0 -> 1.1.0)")
    print("  patch - Bug fixes (1.0.0 -> 1.0.1)")
    print("  skip  - Keep current version")

    while True:
        bump_type = input("\nBump type [major/minor/patch/skip]: ").strip().lower()
        if bump_type in ['major', 'minor', 'patch', 'skip']:
            break
        print("Invalid choice. Enter 'major', 'minor', 'patch', or 'skip'")

    if bump_type == 'skip':
        print(f"Keeping version {current_version}")
        return current_version, current_build

    # Calculate new version
    new_version = bump_version(current_version, bump_type)
    new_build = current_build + 1

    print(f"\nNew version will be: {new_version} (build {new_build})")

    # Ask for changelog
    print("\nEnter changes for this version (one per line, empty line to finish):")
    changes = []
    while True:
        change = input("  - ").strip()
        if not change:
            break
        changes.append(change)

    if not changes:
        changes = [f"Version {new_version} release"]

    # Update version info
    data['version'] = new_version
    data['build_number'] = new_build
    data['release_date'] = datetime.now().strftime("%Y-%m-%d")

    # Add to changelog
    changelog_entry = {
        "version": new_version,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "changes": changes
    }
    data['changelog'].insert(0, changelog_entry)

    # Save
    save_version_info(data)
    print(f"\n✓ Version bumped to {new_version} (build {new_build})")

    return new_version, new_build

def run_command(cmd, description):
    """Run a command and print results"""
    print(f"\n{'=' * 60}")
    print(f"{description}")
    print(f"{'=' * 60}")
    print(f"Running: {' '.join(cmd)}\n")

    result = subprocess.run(cmd, capture_output=False, text=True)

    if result.returncode != 0:
        print(f"\n✗ {description} failed!")
        sys.exit(1)

    print(f"\n✓ {description} completed")
    return result

def main():
    print("=" * 60)
    print("Disk Cleaner Build Script")
    print("=" * 60)

    # Handle version bumping
    version, build = handle_version_bump()

    # Check if PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("\n✗ PyInstaller not found!")
        print("Install it with: pip install pyinstaller")
        sys.exit(1)

    print("\n✓ PyInstaller is installed")

    # Build command
    build_cmd = [
        'pyinstaller',
        '--onefile',           # Single executable
        '--windowed',          # No console window
        '--name', 'DiskCleaner',
        '--clean',             # Clean build
        '--add-data', f'version_manager{os.pathsep}version_manager',  # Include version_manager
        'main.py'
    ]

    # Optional: Add icon if it exists
    icon_path = 'icon.ico'
    if os.path.exists(icon_path):
        build_cmd.extend(['--icon', icon_path])
        print(f"✓ Using icon: {icon_path}")
    else:
        print(f"ℹ No icon.ico found, building without icon")

    # Run PyInstaller
    run_command(build_cmd, "Building executable")

    # Check output
    exe_path = os.path.join('dist', 'DiskCleaner.exe')
    if os.path.exists(exe_path):
        file_size = os.path.getsize(exe_path) / (1024 * 1024)  # MB
        print("\n" + "=" * 60)
        print("Build successful!")
        print("=" * 60)
        print(f"Executable: {exe_path}")
        print(f"Size: {file_size:.2f} MB")
        print(f"Version: {version} (build {build})")
        print("\nNext steps:")
        print("  1. Test the executable in dist/DiskCleaner.exe")
        print("  2. Send DiskCleaner.exe to your client")
        print("  3. Keep the .spec file for future builds")
    else:
        print("\n✗ Build completed but executable not found!")
        sys.exit(1)

if __name__ == '__main__':
    main()
