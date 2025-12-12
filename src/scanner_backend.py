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
import csv
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import stat

# Try to import send2trash for Recycle Bin support
try:
    from send2trash import send2trash
    RECYCLE_BIN_AVAILABLE = True
except ImportError:
    RECYCLE_BIN_AVAILABLE = False
    send2trash = None

# File type categories for filtering
FILE_CATEGORIES = {
    'All Files': None,  # No filter
    'Videos': {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpeg', '.mpg', '.3gp'},
    'Images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.svg', '.ico', '.raw', '.heic', '.heif'},
    'Audio': {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus', '.aiff'},
    'Documents': {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.odt', '.ods', '.odp', '.csv'},
    'Archives': {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.cab'},
    'Executables': {'.exe', '.msi', '.dll', '.bat', '.cmd', '.ps1', '.sh', '.app', '.dmg'},
    'Code': {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.cs', '.go', '.rs', '.php', '.rb', '.swift', '.kt', '.html', '.css', '.json', '.xml', '.yaml', '.yml'},
    'Databases': {'.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.sql'},
    'Disk Images': {'.iso', '.img', '.vhd', '.vhdx', '.vmdk', '.qcow2'},
}

def get_file_category(filepath: str) -> str:
    """Get the category of a file based on its extension"""
    ext = os.path.splitext(filepath)[1].lower()
    for category, extensions in FILE_CATEGORIES.items():
        if extensions and ext in extensions:
            return category
    return 'Other'


def send_log(level: str, message: str):
    """Send a log message to the Electron frontend"""
    from datetime import datetime
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(json.dumps({
        'type': 'log',
        'level': level,
        'message': message,
        'timestamp': timestamp
    }), flush=True)


def delete_file(filepath: str, use_recycle_bin: bool = True) -> Tuple[bool, str]:
    """
    Delete a file using either Recycle Bin or permanent delete.
    Returns (success, error_message)
    """
    try:
        if use_recycle_bin and RECYCLE_BIN_AVAILABLE:
            send2trash(filepath)
            return True, ""
        else:
            os.remove(filepath)
            return True, ""
    except Exception as e:
        return False, str(e)


class DiskAnalyzer:
    DEFAULT_SKIP_FOLDERS = {
        'system volume information', '$recycle.bin', 'windows',
        'program files', 'program files (x86)', 'temp', 'tmp', 'cache'
    }

    def __init__(self, min_size_mb: int = 1, skip_folders: set = None):
        self.min_size_bytes = min_size_mb * 1024 * 1024
        self.file_hashes: Dict[str, List[str]] = defaultdict(list)
        self.large_files: List[Tuple[int, str]] = []
        self.scanned_files = 0
        self.total_size = 0
        self.stop_scanning = False
        self.max_workers = min(4, os.cpu_count() or 1)
        self.skip_folders = skip_folders if skip_folders is not None else self.DEFAULT_SKIP_FOLDERS.copy()

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
        # Also send as log
        log_level = 'DEBUG' if progress_type == 'progress' else 'INFO'
        send_log(log_level, message)

    def scan_directory(self, directory: str):
        """Scan directory for files"""
        try:
            for root, dirs, files in os.walk(directory):
                if self.stop_scanning:
                    break

                dirs[:] = [d for d in dirs if not d.startswith('.') and
                          d.lower() not in self.skip_folders and
                          d.lower() != 'node_modules']

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

        # Calculate category breakdown
        category_sizes = defaultdict(int)
        category_counts = defaultdict(int)

        largest_files = []
        for size, path in self.large_files[:100]:
            category = get_file_category(path)
            largest_files.append({
                'size': self.format_size(size),
                'sizeBytes': size,
                'path': path,
                'category': category
            })

        # Calculate totals for all large files (not just top 100)
        for size, path in self.large_files:
            category = get_file_category(path)
            category_sizes[category] += size
            category_counts[category] += 1

        # Build category summary
        category_summary = []
        for category in list(FILE_CATEGORIES.keys())[1:] + ['Other']:  # Skip 'All Files'
            if category in category_sizes:
                category_summary.append({
                    'category': category,
                    'size': self.format_size(category_sizes[category]),
                    'sizeBytes': category_sizes[category],
                    'count': category_counts[category]
                })

        # Sort by size descending
        category_summary.sort(key=lambda x: x['sizeBytes'], reverse=True)

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
            'duplicates': duplicate_list,
            'categorySummary': category_summary,
            'categories': list(FILE_CATEGORIES.keys()) + ['Other']
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
                send_log('INFO', 'Getting available drives')
                temp_analyzer = DiskAnalyzer()
                drives = temp_analyzer.get_available_drives()
                send_log('INFO', f'Found drives: {", ".join(drives)}')
                print(json.dumps({'type': 'result', 'data': drives}), flush=True)

            elif cmd_type == 'start_scan':
                min_size_mb = command.get('minSizeMB', 1)
                drives_selection = command.get('drives', 'all')
                skip_folders_list = command.get('skipFolders', [])
                skip_folders = set(skip_folders_list) if skip_folders_list else None

                analyzer = DiskAnalyzer(min_size_mb=min_size_mb, skip_folders=skip_folders)

                if drives_selection == 'all':
                    drives_to_scan = analyzer.get_available_drives()
                else:
                    drives_to_scan = [drives_selection]

                skip_info = f", skipping: {len(skip_folders_list)} folders" if skip_folders_list else " (default exclusions)"
                send_log('INFO', f'Starting scan: {", ".join(drives_to_scan)} (min size: {min_size_mb}MB{skip_info})')
                results = analyzer.scan(drives_to_scan)

                # Log completion
                if 'cancelled' not in results:
                    send_log('SUCCESS', results.get('message', 'Scan complete'))
                    send_log('INFO', f'Found {len(results.get("largestFiles", []))} large files, {len(results.get("duplicates", []))} duplicate groups')

                print(json.dumps({'type': 'result', 'data': results}), flush=True)

            elif cmd_type == 'get_categories':
                # Return list of available file categories
                categories = list(FILE_CATEGORIES.keys()) + ['Other']
                print(json.dumps({'type': 'result', 'data': categories}), flush=True)

            elif cmd_type == 'filter_by_category':
                # Filter large files by category (client-side filtering helper)
                category = command.get('category', 'All Files')
                send_log('INFO', f'Filtering by category: {category}')
                if analyzer and analyzer.large_files:
                    filtered_files = []
                    for size, path in analyzer.large_files[:100]:
                        file_category = get_file_category(path)
                        if category == 'All Files' or file_category == category:
                            filtered_files.append({
                                'size': analyzer.format_size(size),
                                'sizeBytes': size,
                                'path': path,
                                'category': file_category
                            })
                    send_log('INFO', f'Filter returned {len(filtered_files)} files')
                    print(json.dumps({'type': 'result', 'data': filtered_files}), flush=True)
                else:
                    send_log('WARNING', 'No scan data available for filtering')
                    print(json.dumps({'type': 'error', 'message': 'No scan data available'}), flush=True)

            elif cmd_type == 'refresh_duplicates':
                send_log('INFO', 'Refreshing duplicates')
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
                    send_log('SUCCESS', f'Refresh complete - {len(duplicate_list)} duplicate groups')
                    print(json.dumps({'type': 'result', 'data': results}), flush=True)
                else:
                    send_log('WARNING', 'No scan data available for refresh')
                    print(json.dumps({'type': 'error', 'message': 'No scan data available'}), flush=True)

            elif cmd_type == 'delete_files':
                # Handle file deletion
                files_to_delete = command.get('files', [])
                use_recycle_bin = command.get('useRecycleBin', True)  # Default to Recycle Bin

                mode_text = "Recycle Bin" if (use_recycle_bin and RECYCLE_BIN_AVAILABLE) else "permanent delete"
                send_log('INFO', f'Delete request for {len(files_to_delete)} files (mode: {mode_text})')

                deleted_count = 0
                errors = []

                for filepath in files_to_delete:
                    success, error = delete_file(filepath, use_recycle_bin)
                    if success:
                        deleted_count += 1
                        send_log('DEBUG', f'Deleted: {filepath}')
                    else:
                        errors.append(f"{filepath}: {error}")
                        send_log('ERROR', f'Failed to delete {filepath}: {error}')

                if deleted_count > 0:
                    if use_recycle_bin and RECYCLE_BIN_AVAILABLE:
                        send_log('SUCCESS', f'Moved {deleted_count} files to Recycle Bin')
                    else:
                        send_log('SUCCESS', f'Permanently deleted {deleted_count} files')

                print(json.dumps({
                    'type': 'result',
                    'data': {
                        'deletedCount': deleted_count,
                        'errors': errors,
                        'usedRecycleBin': use_recycle_bin and RECYCLE_BIN_AVAILABLE
                    }
                }), flush=True)

            elif cmd_type == 'get_recycle_bin_status':
                # Return whether Recycle Bin is available
                print(json.dumps({
                    'type': 'result',
                    'data': {
                        'available': RECYCLE_BIN_AVAILABLE,
                        'message': 'send2trash installed' if RECYCLE_BIN_AVAILABLE else 'send2trash not installed - permanent delete only'
                    }
                }), flush=True)

            elif cmd_type == 'get_logs':
                # Just acknowledge - logs are sent in real-time
                print(json.dumps({'type': 'result', 'data': 'Logs are sent in real-time'}), flush=True)

            elif cmd_type == 'export_large_files':
                # Export large files to file
                format_type = command.get('format', 'csv')
                filepath = command.get('filepath', '')

                if not filepath:
                    print(json.dumps({'type': 'error', 'message': 'No filepath provided'}), flush=True)
                    continue

                if not analyzer or not analyzer.large_files:
                    send_log('WARNING', 'No scan data available for export')
                    print(json.dumps({'type': 'error', 'message': 'No scan data available. Run a scan first.'}), flush=True)
                    continue

                try:
                    send_log('INFO', f'Exporting large files to {format_type.upper()}: {filepath}')

                    # Prepare export data
                    export_data = []
                    for rank, (size_bytes, path) in enumerate(analyzer.large_files[:100], 1):
                        category = get_file_category(path)
                        export_data.append({
                            'rank': rank,
                            'size': analyzer.format_size(size_bytes),
                            'size_bytes': size_bytes,
                            'path': path,
                            'category': category,
                            'filename': os.path.basename(path)
                        })

                    if format_type == 'csv':
                        with open(filepath, 'w', newline='', encoding='utf-8') as f:
                            writer = csv.DictWriter(f, fieldnames=['rank', 'size', 'size_bytes', 'path', 'category', 'filename'])
                            writer.writeheader()
                            writer.writerows(export_data)

                    elif format_type == 'json':
                        with open(filepath, 'w', encoding='utf-8') as f:
                            json.dump({
                                'export_type': 'large_files',
                                'export_date': datetime.now().isoformat(),
                                'total_files': len(export_data),
                                'files': export_data
                            }, f, indent=2, ensure_ascii=False)

                    else:  # txt
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write("=" * 80 + "\n")
                            f.write("LARGE FILES REPORT\n")
                            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                            f.write(f"Total Files: {len(export_data)}\n")
                            f.write("=" * 80 + "\n\n")

                            for item in export_data:
                                f.write(f"{item['rank']:4d}. [{item['category']:12s}] {item['size']:>12s}  {item['path']}\n")

                            f.write("\n" + "=" * 80 + "\n")
                            f.write("END OF REPORT\n")
                            f.write("=" * 80 + "\n")

                    send_log('SUCCESS', f'Exported {len(export_data)} large files to {filepath}')
                    print(json.dumps({
                        'type': 'result',
                        'data': {
                            'success': True,
                            'exportedCount': len(export_data),
                            'filepath': filepath
                        }
                    }), flush=True)

                except Exception as e:
                    send_log('ERROR', f'Export failed: {str(e)}')
                    print(json.dumps({'type': 'error', 'message': f'Export failed: {str(e)}'}), flush=True)

            elif cmd_type == 'export_duplicates':
                # Export duplicates to file
                format_type = command.get('format', 'csv')
                filepath = command.get('filepath', '')

                if not filepath:
                    print(json.dumps({'type': 'error', 'message': 'No filepath provided'}), flush=True)
                    continue

                if not analyzer or not analyzer.file_hashes:
                    send_log('WARNING', 'No scan data available for export')
                    print(json.dumps({'type': 'error', 'message': 'No scan data available. Run a scan first.'}), flush=True)
                    continue

                try:
                    send_log('INFO', f'Exporting duplicates to {format_type.upper()}: {filepath}')

                    # Get verified duplicates
                    duplicates = {k: v for k, v in analyzer.file_hashes.items() if len(v) > 1}

                    # Prepare export data
                    export_data = []
                    total_waste = 0
                    group_num = 0

                    for file_hash, filepaths in duplicates.items():
                        if len(filepaths) <= 1:
                            continue

                        group_num += 1
                        try:
                            size_bytes = os.path.getsize(filepaths[0])
                            waste = (len(filepaths) - 1) * size_bytes
                            total_waste += waste
                        except OSError:
                            size_bytes = 0
                            waste = 0

                        for path in filepaths:
                            export_data.append({
                                'group': group_num,
                                'size': analyzer.format_size(size_bytes),
                                'size_bytes': size_bytes,
                                'waste': analyzer.format_size(waste),
                                'waste_bytes': waste,
                                'copies': len(filepaths),
                                'path': path,
                                'filename': os.path.basename(path)
                            })

                    if format_type == 'csv':
                        with open(filepath, 'w', newline='', encoding='utf-8') as f:
                            writer = csv.DictWriter(f, fieldnames=['group', 'size', 'size_bytes', 'copies', 'waste', 'path', 'filename'])
                            writer.writeheader()
                            writer.writerows(export_data)

                    elif format_type == 'json':
                        # Group data for JSON
                        grouped_data = {}
                        for item in export_data:
                            group = item['group']
                            if group not in grouped_data:
                                grouped_data[group] = {
                                    'group': group,
                                    'size': item['size'],
                                    'size_bytes': item['size_bytes'],
                                    'copies': item['copies'],
                                    'waste': item['waste'],
                                    'waste_bytes': item['waste_bytes'],
                                    'files': []
                                }
                            grouped_data[group]['files'].append(item['path'])

                        with open(filepath, 'w', encoding='utf-8') as f:
                            json.dump({
                                'export_type': 'duplicates',
                                'export_date': datetime.now().isoformat(),
                                'total_groups': len(grouped_data),
                                'total_waste': analyzer.format_size(total_waste),
                                'total_waste_bytes': total_waste,
                                'groups': list(grouped_data.values())
                            }, f, indent=2, ensure_ascii=False)

                    else:  # txt
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write("=" * 80 + "\n")
                            f.write("DUPLICATE FILES REPORT\n")
                            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                            f.write(f"Total Duplicate Groups: {group_num}\n")
                            f.write(f"Potential Space Savings: {analyzer.format_size(total_waste)}\n")
                            f.write("=" * 80 + "\n\n")

                            current_group = None
                            for item in export_data:
                                if item['group'] != current_group:
                                    if current_group is not None:
                                        f.write("\n")
                                    current_group = item['group']
                                    f.write(f"Group #{item['group']} - {item['copies']} copies of {item['size']} file (waste: {item['waste']})\n")
                                    f.write("-" * 60 + "\n")
                                f.write(f"  - {item['path']}\n")

                            f.write("\n" + "=" * 80 + "\n")
                            f.write("END OF REPORT\n")
                            f.write("=" * 80 + "\n")

                    send_log('SUCCESS', f'Exported {group_num} duplicate groups to {filepath}')
                    print(json.dumps({
                        'type': 'result',
                        'data': {
                            'success': True,
                            'exportedGroups': group_num,
                            'filepath': filepath
                        }
                    }), flush=True)

                except Exception as e:
                    send_log('ERROR', f'Export failed: {str(e)}')
                    print(json.dumps({'type': 'error', 'message': f'Export failed: {str(e)}'}), flush=True)

        except json.JSONDecodeError:
            send_log('ERROR', 'Invalid JSON received')
            print(json.dumps({'type': 'error', 'message': 'Invalid JSON'}), flush=True)
        except Exception as e:
            send_log('ERROR', f'Unexpected error: {str(e)}')
            print(json.dumps({'type': 'error', 'message': str(e)}), flush=True)


if __name__ == "__main__":
    main()
