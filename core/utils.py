import os
from typing import Tuple

try:
    from send2trash import send2trash
    RECYCLE_BIN_AVAILABLE = True
except ImportError:
    RECYCLE_BIN_AVAILABLE = False
    send2trash = None


def format_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def delete_file(filepath: str, use_recycle_bin: bool = True) -> Tuple[bool, str]:
    try:
        if use_recycle_bin and RECYCLE_BIN_AVAILABLE:
            send2trash(filepath)
            return True, ""
        else:
            os.remove(filepath)
            return True, ""
    except Exception as e:
        return False, str(e)
