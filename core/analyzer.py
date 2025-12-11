import os
import hashlib
import psutil
import time
import stat
import pickle
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import format_size
from .categories import get_file_category


class DiskAnalyzer:
    def __init__(self, min_size_mb: int = 1):
        self.min_size_bytes = min_size_mb * 1024 * 1024
        self.file_hashes: Dict[str, List[str]] = defaultdict(list)
        self.large_files: List[Tuple[int, str]] = []
        self.scanned_files = 0
        self.total_size = 0
        self.stop_scanning = False
        self.max_workers = min(4, os.cpu_count() or 1)
        self.cache_dir = Path.home() / '.disk_cleaner_cache'
        self.cache_dir.mkdir(exist_ok=True)

    def get_available_drives(self) -> List[str]:
        drives = []
        if os.name == 'nt':
            for drive in psutil.disk_partitions():
                if 'cdrom' not in drive.opts.lower():
                    drives.append(drive.mountpoint)
        else:
            drives = ['/']
        return drives

    def calculate_file_hash(self, filepath: str, chunk_size: int = 8192) -> Optional[str]:
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except (IOError, OSError, PermissionError):
            return None

    def fast_hash(self, filepath: str) -> Optional[str]:
        try:
            stat_info = os.stat(filepath)
            file_size = stat_info.st_size

            if file_size == 0:
                return None

            hash_md5 = hashlib.md5()
            hash_md5.update(str(file_size).encode())
            hash_md5.update(str(stat_info.st_mtime).encode())

            sample_size = min(8192, file_size // 2)

            with open(filepath, "rb") as f:
                chunk = f.read(sample_size)
                hash_md5.update(chunk)

                if file_size > sample_size * 2:
                    f.seek(-sample_size, 2)
                    chunk = f.read(sample_size)
                    hash_md5.update(chunk)

            return hash_md5.hexdigest()
        except (IOError, OSError, PermissionError):
            return None

    def format_size(self, size_bytes: int) -> str:
        return format_size(size_bytes)

    def scan_directory(self, directory: str, progress_callback=None):
        try:
            for root, dirs, files in os.walk(directory):
                if self.stop_scanning:
                    break

                dirs[:] = [d for d in dirs if not d.startswith('.') and
                          d.lower() not in ['system volume information', '$recycle.bin',
                                          'windows', 'program files', 'program files (x86)',
                                          'temp', 'tmp', 'cache', 'node_modules']]

                for file in files:
                    if self.stop_scanning:
                        break

                    try:
                        filepath = os.path.join(root, file)

                        try:
                            stat_info = os.stat(filepath)
                            if not stat.S_ISREG(stat_info.st_mode):
                                continue
                            file_size = stat_info.st_size
                        except (OSError, PermissionError):
                            continue

                        self.scanned_files += 1
                        self.total_size += file_size

                        if file_size >= self.min_size_bytes:
                            self.large_files.append((file_size, filepath))

                            if file_size > 5 * 1024 * 1024:
                                file_hash = self.fast_hash(filepath)
                                if file_hash:
                                    self.file_hashes[file_hash].append(filepath)

                        if progress_callback and self.scanned_files % 500 == 0:
                            progress_callback(self.scanned_files, filepath)

                    except (OSError, PermissionError):
                        continue

        except (OSError, PermissionError):
            pass

    def find_largest_files(self, count: int = 50) -> List[Tuple[str, str]]:
        self.large_files.sort(reverse=True)
        return [(self.format_size(size), filepath) for size, filepath in self.large_files[:count]]

    def find_duplicates(self) -> Dict[str, List[str]]:
        return {h: paths for h, paths in self.file_hashes.items() if len(paths) > 1}

    def verify_duplicates_with_full_hash(self, progress_callback=None) -> Dict[str, List[str]]:
        verified_duplicates = {}
        potential_duplicates = self.find_duplicates()

        if not potential_duplicates:
            return verified_duplicates

        for i, (fast_hash, filepaths) in enumerate(potential_duplicates.items()):
            if self.stop_scanning:
                break

            full_hash_groups = defaultdict(list)
            for filepath in filepaths:
                full_hash = self.calculate_file_hash(filepath)
                if full_hash:
                    full_hash_groups[full_hash].append(filepath)

            for full_hash, paths in full_hash_groups.items():
                if len(paths) > 1:
                    verified_duplicates[full_hash] = paths

            if progress_callback and i % 5 == 0:
                progress_callback(i, len(potential_duplicates))

        return verified_duplicates

    def calculate_duplicate_waste(self, duplicates: Dict[str, List[str]]) -> int:
        total_waste = 0
        for filepaths in duplicates.values():
            if len(filepaths) > 1:
                try:
                    file_size = os.path.getsize(filepaths[0])
                    total_waste += (len(filepaths) - 1) * file_size
                except OSError:
                    continue
        return total_waste

    def get_cache_path(self, drive: str) -> Path:
        drive_name = drive.replace(':', '').replace('\\', '_').replace('/', '_')
        return self.cache_dir / f'cache_{drive_name}.pkl'

    def save_cache(self, drive: str):
        try:
            cache_data = {
                'timestamp': time.time(),
                'drive': drive,
                'min_size_bytes': self.min_size_bytes,
                'file_hashes': dict(self.file_hashes),
                'large_files': self.large_files,
                'scanned_files': self.scanned_files,
                'total_size': self.total_size
            }
            cache_path = self.get_cache_path(drive)
            with open(cache_path, 'wb') as f:
                pickle.dump(cache_data, f)
        except Exception:
            pass

    def load_cache(self, drive: str, max_age_hours: int = 24) -> bool:
        try:
            cache_path = self.get_cache_path(drive)
            if not cache_path.exists():
                return False

            with open(cache_path, 'rb') as f:
                cache_data = pickle.load(f)

            cache_age = time.time() - cache_data['timestamp']
            if cache_age > max_age_hours * 3600:
                return False

            if cache_data['min_size_bytes'] != self.min_size_bytes:
                return False

            self.file_hashes = defaultdict(list, cache_data['file_hashes'])
            self.large_files = cache_data['large_files']
            self.scanned_files = cache_data['scanned_files']
            self.total_size = cache_data['total_size']

            return True
        except Exception:
            return False

    def clear_cache(self, drive: str = None):
        try:
            if drive:
                cache_path = self.get_cache_path(drive)
                if cache_path.exists():
                    cache_path.unlink()
            else:
                for cache_file in self.cache_dir.glob('cache_*.pkl'):
                    cache_file.unlink()
        except Exception:
            pass
