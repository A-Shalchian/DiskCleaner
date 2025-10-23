#!/usr/bin/env python3
"""
Disk Space Analyzer and Duplicate File Finder
Scans drives to find largest files and potential duplicates
"""

import os
from version_manager import __version__
import hashlib
import argparse
from collections import defaultdict
import time
import psutil
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
        self.max_workers = min(4, os.cpu_count() or 1)  # Optimize thread count
        
    def get_available_drives(self) -> List[str]:
        """Get list of available drives on Windows"""
        drives = []
        if os.name == 'nt':  # Windows
            for drive in psutil.disk_partitions():
                if 'cdrom' not in drive.opts:
                    drives.append(drive.mountpoint)
        else:  # Unix-like
            drives = ['/']
        return drives
    
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
    
    def fast_hash(self, filepath: str) -> Optional[str]:
        """Fast hash using file size + sample from beginning and end for initial duplicate detection"""
        try:
            # Get file stats efficiently
            stat_info = os.stat(filepath)
            file_size = stat_info.st_size
            
            if file_size == 0:
                return None
                
            hash_md5 = hashlib.md5()
            # Include file size and modification time for uniqueness
            hash_md5.update(str(file_size).encode())
            hash_md5.update(str(stat_info.st_mtime).encode())
            
            # Sample from beginning and end for large files
            sample_size = min(8192, file_size // 2)
            
            with open(filepath, "rb") as f:
                # Hash beginning
                chunk = f.read(sample_size)
                hash_md5.update(chunk)
                
                # Hash end if file is large enough
                if file_size > sample_size * 2:
                    f.seek(-sample_size, 2)
                    chunk = f.read(sample_size)
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
    
    def scan_directory(self, directory: str, progress_callback=None):
        """Scan directory for files and collect size/hash information with optimizations"""
        try:
            for root, dirs, files in os.walk(directory):
                # Skip system directories that might cause issues
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d.lower() not in ['system volume information', '$recycle.bin', 
                                          'windows', 'program files', 'program files (x86)',
                                          'temp', 'tmp', 'cache']]
                
                # Process files in batches for better performance
                for file in files:
                    try:
                        filepath = os.path.join(root, file)
                        
                        # Use os.stat for faster file info gathering
                        try:
                            stat_info = os.stat(filepath)
                            if not stat.S_ISREG(stat_info.st_mode):  # Skip if not regular file
                                continue
                            file_size = stat_info.st_size
                        except (OSError, PermissionError):
                            continue
                            
                        self.scanned_files += 1
                        self.total_size += file_size
                        
                        # Track large files
                        if file_size >= self.min_size_bytes:
                            self.large_files.append((file_size, filepath))
                            
                            # Use fast hash for initial duplicate detection (files > 5MB for speed)
                            if file_size > 5 * 1024 * 1024:
                                file_hash = self.fast_hash(filepath)
                                if file_hash:
                                    self.file_hashes[file_hash].append(filepath)
                        
                        # Progress update (more frequent for better UX)
                        if progress_callback and self.scanned_files % 500 == 0:
                            progress_callback(self.scanned_files, filepath)
                            
                    except (OSError, PermissionError):
                        continue
                        
        except (OSError, PermissionError) as e:
            print(f"Cannot access directory {directory}: {e}")
    
    def find_largest_files(self, count: int = 50) -> List[Tuple[str, str]]:
        """Return the largest files found"""
        self.large_files.sort(reverse=True)
        return [(self.format_size(size), filepath) for size, filepath in self.large_files[:count]]
    
    def find_duplicates(self) -> Dict[str, List[str]]:
        """Return dictionary of duplicate files grouped by hash"""
        duplicates = {}
        for file_hash, filepaths in self.file_hashes.items():
            if len(filepaths) > 1:
                duplicates[file_hash] = filepaths
        return duplicates
    
    def verify_duplicates_with_full_hash(self) -> Dict[str, List[str]]:
        """Verify potential duplicates with full file hash for accuracy"""
        verified_duplicates = {}
        potential_duplicates = self.find_duplicates()
        
        if not potential_duplicates:
            return verified_duplicates
            
        print(f"\n🔍 Verifying {len(potential_duplicates)} potential duplicate groups with full hash...")
        
        for i, (fast_hash, filepaths) in enumerate(potential_duplicates.items()):
            # Group by full hash for final verification
            full_hash_groups = defaultdict(list)
            for filepath in filepaths:
                full_hash = self.calculate_file_hash(filepath)
                if full_hash:
                    full_hash_groups[full_hash].append(filepath)
            
            # Keep only actual duplicates
            for full_hash, paths in full_hash_groups.items():
                if len(paths) > 1:
                    verified_duplicates[full_hash] = paths
            
            # Progress update
            if i % 5 == 0 and i > 0:
                print(f"Verified {i}/{len(potential_duplicates)} groups...")
        
        return verified_duplicates
    
    def calculate_duplicate_waste(self, duplicates: Dict[str, List[str]]) -> int:
        """Calculate total space wasted by duplicates"""
        total_waste = 0
        for filepaths in duplicates.values():
            if len(filepaths) > 1:
                try:
                    file_size = os.path.getsize(filepaths[0])
                    # Waste is (number of copies - 1) * file size
                    total_waste += (len(filepaths) - 1) * file_size
                except OSError:
                    continue
        return total_waste

def progress_callback(files_scanned: int, current_file: str):
    """Progress callback function"""
    if files_scanned % 2500 == 0:  # More frequent updates
        print(f"Scanned {files_scanned:,} files... Currently processing: {current_file[:80]}...")

def main():
    parser = argparse.ArgumentParser(
        description="Analyze disk usage and find duplicates",
        epilog=f"Disk Cleaner v{__version__}"
    )
    parser.add_argument("--version", action="version", version=f"Disk Cleaner {__version__}")
    parser.add_argument("--drives", nargs="+", help="Specific drives to scan (e.g., C: D:)")
    parser.add_argument("--min-size", type=int, default=1, help="Minimum file size in MB to consider (default: 1)")
    parser.add_argument("--top-files", type=int, default=50, help="Number of largest files to show (default: 50)")
    parser.add_argument("--no-duplicates", action="store_true", help="Skip duplicate detection")

    args = parser.parse_args()
    
    analyzer = DiskAnalyzer(min_size_mb=args.min_size)
    
    # Determine drives to scan
    if args.drives:
        drives_to_scan = args.drives
    else:
        drives_to_scan = analyzer.get_available_drives()
        print(f"Auto-detected drives: {', '.join(drives_to_scan)}")
    
    print(f"Starting disk analysis...")
    print(f"Minimum file size: {args.min_size} MB")
    print(f"Drives to scan: {', '.join(drives_to_scan)}")
    print("-" * 60)
    
    start_time = time.time()
    
    # Scan drives with optional multi-threading for better performance
    if len(drives_to_scan) > 1 and analyzer.max_workers > 1:
        print(f"\n🚀 Using parallel scanning with {analyzer.max_workers} workers...")
        with ThreadPoolExecutor(max_workers=min(len(drives_to_scan), analyzer.max_workers)) as executor:
            futures = []
            for drive in drives_to_scan:
                if os.path.exists(drive):
                    print(f"Starting scan of drive: {drive}")
                    future = executor.submit(analyzer.scan_directory, drive, progress_callback)
                    futures.append(future)
                else:
                    print(f"Drive {drive} not accessible, skipping...")
            
            # Wait for all drives to complete
            for future in as_completed(futures):
                try:
                    future.result()  # This will raise any exceptions
                except Exception as e:
                    print(f"Drive scan error: {e}")
    else:
        # Sequential scanning for single drive or limited workers
        for drive in drives_to_scan:
            if os.path.exists(drive):
                print(f"\nScanning drive: {drive}")
                analyzer.scan_directory(drive, progress_callback)
            else:
                print(f"Drive {drive} not accessible, skipping...")
    
    scan_time = time.time() - start_time
    
    print(f"\n" + "="*60)
    print(f"SCAN COMPLETE")
    print(f"="*60)
    print(f"Files scanned: {analyzer.scanned_files:,}")
    print(f"Total data scanned: {analyzer.format_size(analyzer.total_size)}")
    print(f"Scan time: {scan_time:.2f} seconds")
    
    # Show largest files
    print(f"\n📊 TOP {args.top_files} LARGEST FILES:")
    print("-" * 60)
    largest_files = analyzer.find_largest_files(args.top_files)
    
    for i, (size, filepath) in enumerate(largest_files, 1):
        print(f"{i:2d}. {size:>10} - {filepath}")
    
    # Find and show duplicates
    if not args.no_duplicates:
        print(f"\n🔍 DUPLICATE FILES ANALYSIS:")
        print("-" * 60)
        
        # Use improved duplicate verification with full hash
        duplicates = analyzer.verify_duplicates_with_full_hash()
        if duplicates:
            total_waste = analyzer.calculate_duplicate_waste(duplicates)
            print(f"Found {len(duplicates)} sets of duplicate files")
            print(f"Potential space savings: {analyzer.format_size(total_waste)}")
            print()
            
            # Show top duplicate groups by waste
            duplicate_groups = []
            for file_hash, filepaths in duplicates.items():
                try:
                    file_size = os.path.getsize(filepaths[0])
                    waste = (len(filepaths) - 1) * file_size
                    duplicate_groups.append((waste, file_size, filepaths))
                except OSError:
                    continue
            
            duplicate_groups.sort(reverse=True)
            
            print("Top duplicate groups (by space waste):")
            for i, (waste, file_size, filepaths) in enumerate(duplicate_groups[:20], 1):
                print(f"\n{i}. {analyzer.format_size(waste)} waste ({len(filepaths)} copies of {analyzer.format_size(file_size)} file):")
                for filepath in filepaths:
                    print(f"   - {filepath}")
        else:
            print("No duplicate files found (files > 5MB only)")
    
    print(f"\n" + "="*60)
    print("🏁 ANALYSIS COMPLETE! (Optimized with fast hashing & multi-threading)")
    print("="*60)
    print("Review the results above to identify:")
    print("• Large files that might be unnecessary")
    print("• Duplicate files that can be safely removed (verified with full hash)")
    print("• Directories consuming the most space")
    print(f"\n🚀 Performance: {analyzer.scanned_files/scan_time:.0f} files/second")
    print("="*60)

if __name__ == "__main__":
    main()