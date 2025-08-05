#!/usr/bin/env python3
"""
Disk Space Analyzer and Duplicate File Finder
Scans drives to find largest files and potential duplicates
"""

import os
import hashlib
import argparse
from pathlib import Path
from collections import defaultdict
import time
import psutil
from typing import Dict, List, Tuple, Set

class DiskAnalyzer:
    def __init__(self, min_size_mb: int = 1):
        self.min_size_bytes = min_size_mb * 1024 * 1024
        self.file_hashes: Dict[str, List[str]] = defaultdict(list)
        self.large_files: List[Tuple[int, str]] = []
        self.scanned_files = 0
        self.total_size = 0
        
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
    
    def format_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def scan_directory(self, directory: str, progress_callback=None):
        """Scan directory for files and collect size/hash information"""
        try:
            for root, dirs, files in os.walk(directory):
                # Skip system directories that might cause issues
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d.lower() not in ['system volume information', '$recycle.bin', 
                                          'windows', 'program files', 'program files (x86)']]
                
                for file in files:
                    try:
                        filepath = os.path.join(root, file)
                        if not os.path.isfile(filepath):
                            continue
                            
                        file_size = os.path.getsize(filepath)
                        self.scanned_files += 1
                        self.total_size += file_size
                        
                        # Track large files
                        if file_size >= self.min_size_bytes:
                            self.large_files.append((file_size, filepath))
                            
                            # Calculate hash for potential duplicates (only for files > 10MB)
                            if file_size > 10 * 1024 * 1024:
                                file_hash = self.calculate_file_hash(filepath)
                                if file_hash:
                                    self.file_hashes[file_hash].append(filepath)
                        
                        # Progress update
                        if progress_callback and self.scanned_files % 1000 == 0:
                            progress_callback(self.scanned_files, filepath)
                            
                    except (OSError, PermissionError) as e:
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
    if files_scanned % 5000 == 0:
        print(f"Scanned {files_scanned:,} files... Currently processing: {current_file[:80]}...")

def main():
    parser = argparse.ArgumentParser(description="Analyze disk usage and find duplicates")
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
    
    # Scan each drive
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
        
        duplicates = analyzer.find_duplicates()
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
            print("No duplicate files found (files > 10MB only)")
    
    print(f"\n" + "="*60)
    print("Analysis complete! Review the results above to identify:")
    print("• Large files that might be unnecessary")
    print("• Duplicate files that can be safely removed")
    print("• Directories consuming the most space")
    print("="*60)

if __name__ == "__main__":
    main()