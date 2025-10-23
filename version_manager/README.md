# Version Manager

This directory handles all version tracking for Disk Cleaner.

## Files

- `version_info.json` - Single source of truth for version number and changelog
- `version.py` - Reads version info and exposes it to the app
- `__init__.py` - Makes this a Python package

## How it works

The version is stored in `version_info.json`. When you import `from version_manager import __version__`, it reads from that JSON file. This keeps everything in sync.

## Building and Version Bumping

Just run the build script:

```bash
python build.py
```

It will ask you:
- **major** - Breaking changes (1.0.0 → 2.0.0)
- **minor** - New features (1.0.0 → 1.1.0)
- **patch** - Bug fixes (1.0.0 → 1.0.1)
- **skip** - Keep current version (rebuild only)

Then it asks for changelog entries, updates the version, and builds the .exe automatically.
