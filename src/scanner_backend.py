#!/usr/bin/env python3
"""
Disk Scanner Backend - Fast Python implementation
Communicates with Electron via JSON over stdin/stdout
"""

import os
import sys
import json
import hashlib
import psutil
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import stat


class DiskAnalyzer:
    def __init__(self, min_size_mb: int = 1):
        self.min_size_bytes = min_size_mb * 1024 * 1024
        self.file_hashes: Dict[str, List[str]] = defaultdict(list)
        self.large_files: List[Tuple[int, str]] = []
        self.scanned_files = 0
        self.total_size = 0
        self.stop_scanning = False
        self.max_workers = min(4, os.cpu_count() or 1)

    def get_available_drives(self) -> List[str]:
        """Get list of available drives"""
        drives = []
        if os.name == 'nt':  # Windows
            for drive in psutil.disk_partitions():
                if 'cdrom' not in drive.opts.lower():
                    drives.append(drive.mountpoint)
        else:  # Unix-like
            drives = ['/']
        return drives

    def fast_hash(self, filepath: str) -> Optional[str]:
        """Fast hash using file size + sample from beginning and end"""
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

    def calculate_file_hash(self, filepath: str, chunk_size: int = 8192) -> str:
        """Calculate MD5 hash of a file"""
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except (IOError, OSError, PermissionError):
            return None

    def format_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def send_progress(self, message: str, progress_type: str = 'status'):
        """Send progress update to Electron"""
        print(json.dumps({
            'type': progress_type,
            'message': message,
            'filesScanned': self.scanned_files
        }), flush=True)

    def scan_directory(self, directory: str):
        """Scan directory for files"""
        try:
            for root, dirs, files in os.walk(directory):
                if self.stop_scanning:
                    break

                # Skip system directories
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

                        if self.scanned_files % 500 == 0:
                            self.send_progress(
                                f"Scanned {self.scanned_files:,} files... {filepath[:60]}...",
                                'progress'
                            )

                    except (OSError, PermissionError):
                        continue

        except (OSError, PermissionError) as e:
            pass  # Skip inaccessible directories

    def verify_duplicates_with_full_hash(self) -> Dict[str, List[str]]:
        """Verify potential duplicates with full file hash"""
        verified_duplicates = {}
        potential_duplicates = {k: v for k, v in self.file_hashes.items() if len(v) > 1}

        if not potential_duplicates:
            return verified_duplicates

        self.send_progress(f'Verifying {len(potential_duplicates)} potential duplicate groups...')

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

            if i % 5 == 0:
                self.send_progress(f'Verifying group {i+1}/{len(potential_duplicates)}')

        return verified_duplicates

    def scan(self, drives_to_scan: List[str]) -> dict:
        """Main scan function"""
        start_time = time.time()

        if len(drives_to_scan) > 1 and self.max_workers > 1:
            self.send_progress('Starting parallel drive scanning...')
            with ThreadPoolExecutor(max_workers=min(len(drives_to_scan), self.max_workers)) as executor:
                futures = []
                for drive in drives_to_scan:
                    if os.path.exists(drive):
                        future = executor.submit(self.scan_directory, drive)
                        futures.append(future)
                    else:
                        self.send_progress(f'Drive {drive} not accessible, skipping...')

                for future in as_completed(futures):
                    if self.stop_scanning:
                        break
                    try:
                        future.result()
                    except Exception as e:
                        pass
        else:
            for drive in drives_to_scan:
                if os.path.exists(drive) and not self.stop_scanning:
                    self.send_progress(f'Scanning drive: {drive}')
                    self.scan_directory(drive)
                else:
                    self.send_progress(f'Drive {drive} not accessible, skipping...')

        if self.stop_scanning:
            return {'cancelled': True}

        self.send_progress('Verifying duplicates with full hash...')
        duplicates = self.verify_duplicates_with_full_hash()

        scan_time = time.time() - start_time

        self.large_files.sort(reverse=True)
        largest_files = [
            {'size': self.format_size(size), 'path': path}
            for size, path in self.large_files[:100]
        ]

        duplicate_list = []
        for file_hash, filepaths in duplicates.items():
            try:
                file_size = os.path.getsize(filepaths[0])
                waste = (len(filepaths) - 1) * file_size
                duplicate_list.append({
                    'count': len(filepaths),
                    'size': self.format_size(file_size),
                    'waste': self.format_size(waste),
                    'waste_bytes': waste,
                    'files': filepaths
                })
            except OSError:
                continue

        duplicate_list.sort(key=lambda x: x['waste_bytes'], reverse=True)

        return {
            'message': f"Scan complete! {self.scanned_files:,} files ({self.format_size(self.total_size)}) in {scan_time:.1f}s",
            'largestFiles': largest_files,
            'duplicates': duplicate_list
        }


def main():
    """Main function - reads commands from stdin, sends results to stdout"""
    analyzer = None

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break

            command = json.loads(line.strip())
            cmd_type = command.get('command')

            if cmd_type == 'get_drives':
                temp_analyzer = DiskAnalyzer()
                drives = temp_analyzer.get_available_drives()
                print(json.dumps({'type': 'result', 'data': drives}), flush=True)

            elif cmd_type == 'start_scan':
                min_size_mb = command.get('minSizeMB', 1)
                drives_selection = command.get('drives', 'all')

                analyzer = DiskAnalyzer(min_size_mb=min_size_mb)

                if drives_selection == 'all':
                    drives_to_scan = analyzer.get_available_drives()
                else:
                    drives_to_scan = [drives_selection]

                results = analyzer.scan(drives_to_scan)
                print(json.dumps({'type': 'result', 'data': results}), flush=True)

            elif cmd_type == 'refresh_duplicates':
                if analyzer and analyzer.file_hashes:
                    duplicates = analyzer.verify_duplicates_with_full_hash()

                    duplicate_list = []
                    for file_hash, filepaths in duplicates.items():
                        try:
                            file_size = os.path.getsize(filepaths[0])
                            waste = (len(filepaths) - 1) * file_size
                            duplicate_list.append({
                                'count': len(filepaths),
                                'size': analyzer.format_size(file_size),
                                'waste': analyzer.format_size(waste),
                                'waste_bytes': waste,
                                'files': filepaths
                            })
                        except OSError:
                            continue

                    duplicate_list.sort(key=lambda x: x['waste_bytes'], reverse=True)

                    results = {
                        'message': 'Refresh complete!',
                        'largestFiles': [],
                        'duplicates': duplicate_list
                    }
                    print(json.dumps({'type': 'result', 'data': results}), flush=True)
                else:
                    print(json.dumps({'type': 'error', 'message': 'No scan data available'}), flush=True)

        except json.JSONDecodeError:
            print(json.dumps({'type': 'error', 'message': 'Invalid JSON'}), flush=True)
        except Exception as e:
            print(json.dumps({'type': 'error', 'message': str(e)}), flush=True)


if __name__ == "__main__":
    main()
