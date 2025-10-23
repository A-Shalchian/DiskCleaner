"""
Version information for Disk Cleaner
Reads from version_info.json
"""

import json
import os

def _load_version_info():
    """Load version info from JSON file"""
    version_file = os.path.join(os.path.dirname(__file__), 'version_info.json')
    try:
        with open(version_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Fallback if file is missing or corrupted
        return {
            "version": "1.0.0",
            "build_number": 1,
            "release_date": None
        }

_version_data = _load_version_info()
__version__ = _version_data.get("version", "1.0.0")
__build__ = _version_data.get("build_number", 1)

def get_version():
    """Return the current version"""
    return __version__

def get_full_version():
    """Return version with build number"""
    return f"{__version__} (build {__build__})"

def get_version_info():
    """Return detailed version information"""
    return _version_data
