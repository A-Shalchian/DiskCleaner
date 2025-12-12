#!/usr/bin/env python3
"""
Disk Space Analyzer and Duplicate File Finder - GUI Version
Using the same proven functionality as the original disk_analyzer.py
"""

import os
from version_manager import __version__
import hashlib
import threading
import time
import psutil
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import queue
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import stat
import pickle
import json
import csv
from pathlib import Path
from datetime import datetime

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
        self.cache_dir = Path.home() / '.disk_cleaner_cache'
        self.cache_dir.mkdir(exist_ok=True)
        self.skip_folders = skip_folders if skip_folders is not None else self.DEFAULT_SKIP_FOLDERS.copy()
        
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
    
    def scan_directory(self, directory: str, progress_queue: queue.Queue):
        """Scan directory for files and collect size/hash information with optimizations"""
        try:
            for root, dirs, files in os.walk(directory):
                if self.stop_scanning:
                    break
                    
                dirs[:] = [d for d in dirs if not d.startswith('.') and
                          d.lower() not in self.skip_folders]
                
                # Process files in batches for better performance
                for file in files:
                    if self.stop_scanning:
                        break
                        
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
                        if self.scanned_files % 500 == 0:
                            progress_queue.put(('progress', self.scanned_files, filepath))
                            
                    except (OSError, PermissionError):
                        continue
                        
        except (OSError, PermissionError) as e:
            progress_queue.put(('error', f"Cannot access directory {directory}: {e}"))
    
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
    
    def verify_duplicates_with_full_hash(self, progress_queue: queue.Queue) -> Dict[str, List[str]]:
        """Verify potential duplicates with full file hash for accuracy"""
        verified_duplicates = {}
        potential_duplicates = self.find_duplicates()
        
        if not potential_duplicates:
            return verified_duplicates
            
        progress_queue.put(('status', f'Verifying {len(potential_duplicates)} potential duplicate groups...'))
        
        for i, (fast_hash, filepaths) in enumerate(potential_duplicates.items()):
            if self.stop_scanning:
                break
                
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
            
            if i % 5 == 0:  # More frequent updates
                progress_queue.put(('progress', i, f'Verifying group {i+1}/{len(potential_duplicates)}'))
        
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

    def get_cache_path(self, drive: str) -> Path:
        """Get cache file path for a specific drive"""
        # Sanitize drive name for filename
        drive_name = drive.replace(':', '').replace('\\', '_').replace('/', '_')
        return self.cache_dir / f'cache_{drive_name}.pkl'

    def save_cache(self, drive: str):
        """Save scan results to cache"""
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
        except Exception as e:
            print(f"Warning: Could not save cache: {e}")

    def load_cache(self, drive: str, max_age_hours: int = 24) -> bool:
        """Load scan results from cache if available and fresh"""
        try:
            cache_path = self.get_cache_path(drive)
            if not cache_path.exists():
                return False

            with open(cache_path, 'rb') as f:
                cache_data = pickle.load(f)

            # Check cache age
            cache_age = time.time() - cache_data['timestamp']
            if cache_age > max_age_hours * 3600:
                return False

            # Check if min size matches
            if cache_data['min_size_bytes'] != self.min_size_bytes:
                return False

            # Restore data
            self.file_hashes = defaultdict(list, cache_data['file_hashes'])
            self.large_files = cache_data['large_files']
            self.scanned_files = cache_data['scanned_files']
            self.total_size = cache_data['total_size']

            return True
        except Exception as e:
            print(f"Warning: Could not load cache: {e}")
            return False

    def clear_cache(self, drive: str = None):
        """Clear cache for a specific drive or all drives"""
        try:
            if drive:
                cache_path = self.get_cache_path(drive)
                if cache_path.exists():
                    cache_path.unlink()
            else:
                for cache_file in self.cache_dir.glob('cache_*.pkl'):
                    cache_file.unlink()
        except Exception as e:
            print(f"Warning: Could not clear cache: {e}")

class DiskCleanerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Disk Cleaner - Space Analyzer & Duplicate Finder")
        self.root.geometry("1200x800")

        self.analyzer = DiskAnalyzer()
        self.progress_queue = queue.Queue()
        self.scanning = False
        self.scan_thread = None
        self.duplicate_data = {}  # Store file paths by item ID
        self.selected_large_files = set()  # Track selected large files
        self.selected_duplicates = set()  # Track selected duplicate groups
        self.last_scanned_path = None  # Track what was last scanned for cache invalidation
        self.all_large_files = []  # Store all large files for filtering
        self.current_filter = 'All Files'  # Current file type filter
        self.use_recycle_bin = tk.BooleanVar(value=RECYCLE_BIN_AVAILABLE)  # Use Recycle Bin by default if available

        self.skip_windows = tk.BooleanVar(value=True)
        self.skip_program_files = tk.BooleanVar(value=True)
        self.skip_program_files_x86 = tk.BooleanVar(value=True)
        self.skip_temp = tk.BooleanVar(value=True)
        self.skip_recycle_bin = tk.BooleanVar(value=True)
        self.skip_system_volume = tk.BooleanVar(value=True)

        self.setup_ui()
        self.check_progress_queue()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)

        # Title with version
        title_label = ttk.Label(main_frame, text=f"Disk Cleaner v{__version__}", font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Settings frame
        settings_frame = ttk.LabelFrame(main_frame, text="Scan Settings", padding="10")
        settings_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        settings_frame.columnconfigure(1, weight=1)
        
        # Drive/Directory selection
        ttk.Label(settings_frame, text="Scan location:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.drives_var = tk.StringVar()
        self.drives_combo = ttk.Combobox(settings_frame, textvariable=self.drives_var, width=40)
        self.update_drives_list()
        self.drives_combo.set('All Drives')
        self.drives_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        # Browse button for custom directory
        self.browse_button = ttk.Button(settings_frame, text="📁 Browse...", command=self.browse_directory, width=12)
        self.browse_button.grid(row=0, column=2, padx=(0, 10))
        
        # Min size
        ttk.Label(settings_frame, text="Min file size (MB):").grid(row=0, column=3, sticky=tk.W, padx=(10, 5))
        self.min_size_var = tk.StringVar(value="1")
        min_size_entry = ttk.Entry(settings_frame, textvariable=self.min_size_var, width=10)
        min_size_entry.grid(row=0, column=4, sticky=tk.W)

        # Delete settings row
        delete_settings_frame = ttk.Frame(settings_frame)
        delete_settings_frame.grid(row=1, column=0, columnspan=5, sticky=tk.W, pady=(10, 0))

        # Recycle Bin checkbox
        self.recycle_bin_check = ttk.Checkbutton(
            delete_settings_frame,
            text="🗑️ Move to Recycle Bin (safer)",
            variable=self.use_recycle_bin,
            command=self.on_recycle_bin_toggle
        )
        self.recycle_bin_check.pack(side=tk.LEFT, padx=(0, 20))

        # Status label for Recycle Bin availability
        if RECYCLE_BIN_AVAILABLE:
            recycle_status = ttk.Label(delete_settings_frame, text="✓ send2trash installed", foreground='green')
        else:
            recycle_status = ttk.Label(delete_settings_frame, text="⚠ send2trash not installed - using permanent delete", foreground='orange')
            self.recycle_bin_check.config(state=tk.DISABLED)
        recycle_status.pack(side=tk.LEFT)

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=2, column=0, columnspan=3, pady=(0, 10))
        
        self.scan_button = ttk.Button(control_frame, text="🔍 Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(control_frame, text="⏹ Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(control_frame, text="🗑 Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))

        self.clear_cache_button = ttk.Button(control_frame, text="🔄 Clear Cache", command=self.clear_all_cache)
        self.clear_cache_button.pack(side=tk.LEFT)
        
        # Progress (separate row to avoid overlap)
        self.progress_var = tk.StringVar(value="Ready to scan")
        progress_label = ttk.Label(main_frame, textvariable=self.progress_var)
        progress_label.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(10, 5))
        
        self.progress_bar = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Results notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.setup_tabs()
        
    def setup_tabs(self):
        """Setup all tabs"""
        # Large files tab
        self.large_files_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.large_files_frame, text="📊 Largest Files")

        # Top control frame for large files
        large_files_top_frame = ttk.Frame(self.large_files_frame)
        large_files_top_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        large_files_top_frame.columnconfigure(1, weight=1)

        # Filter controls (left side)
        filter_frame = ttk.Frame(large_files_top_frame)
        filter_frame.grid(row=0, column=0, sticky=tk.W)

        ttk.Label(filter_frame, text="Filter by type:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar(value='All Files')
        self.filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, width=15, state='readonly')
        self.filter_combo['values'] = list(FILE_CATEGORIES.keys()) + ['Other']
        self.filter_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.filter_combo.bind('<<ComboboxSelected>>', self.on_filter_changed)

        # Category summary label (right side)
        self.category_summary_var = tk.StringVar(value="")
        self.category_summary_label = ttk.Label(large_files_top_frame, textvariable=self.category_summary_var,
                                                 font=('Arial', 9))
        self.category_summary_label.grid(row=0, column=1, sticky=tk.E, padx=(10, 0))

        # Button frame for large files
        large_files_btn_frame = ttk.Frame(self.large_files_frame)
        large_files_btn_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Button(large_files_btn_frame, text="Select All", command=self.select_all_large_files).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(large_files_btn_frame, text="Deselect All", command=self.deselect_all_large_files).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(large_files_btn_frame, text="Delete Selected", command=self.delete_selected_large_files,
                   style='Danger.TButton').pack(side=tk.LEFT, padx=(10, 0))

        # Export buttons
        ttk.Separator(large_files_btn_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=(15, 10), fill=tk.Y)
        ttk.Label(large_files_btn_frame, text="Export:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(large_files_btn_frame, text="CSV", command=lambda: self.export_large_files('csv'), width=5).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(large_files_btn_frame, text="JSON", command=lambda: self.export_large_files('json'), width=5).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(large_files_btn_frame, text="TXT", command=lambda: self.export_large_files('txt'), width=5).pack(side=tk.LEFT)

        columns = ('Select', 'Size', 'Path')
        self.large_files_tree = ttk.Treeview(self.large_files_frame, columns=columns, show='headings', height=20)
        self.large_files_tree.heading('Select', text='☐')
        self.large_files_tree.heading('Size', text='Size')
        self.large_files_tree.heading('Path', text='File Path')
        self.large_files_tree.column('Select', width=50, anchor='center')
        self.large_files_tree.column('Size', width=100)
        self.large_files_tree.column('Path', width=750)

        large_files_scroll = ttk.Scrollbar(self.large_files_frame, orient=tk.VERTICAL, command=self.large_files_tree.yview)
        self.large_files_tree.configure(yscrollcommand=large_files_scroll.set)

        self.large_files_tree.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        large_files_scroll.grid(row=2, column=1, sticky=(tk.N, tk.S))

        self.large_files_frame.columnconfigure(0, weight=1)
        self.large_files_frame.rowconfigure(2, weight=1)

        # Bind click event for checkbox column
        self.large_files_tree.bind('<Button-1>', self.on_large_file_click)
        
        # Duplicates tab
        self.duplicates_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.duplicates_frame, text="🔍 Duplicate Files")

        # Info and action buttons frame
        info_action_frame = ttk.Frame(self.duplicates_frame)
        info_action_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        info_action_frame.columnconfigure(0, weight=1)

        self.duplicates_info = ttk.Label(info_action_frame, text="No duplicates found yet")
        self.duplicates_info.grid(row=0, column=0, sticky=tk.W)

        # Action buttons for better accessibility
        action_buttons_frame = ttk.Frame(info_action_frame)
        action_buttons_frame.grid(row=0, column=1, sticky=tk.E)

        ttk.Button(action_buttons_frame, text="Select All", command=self.select_all_duplicates).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_buttons_frame, text="Deselect All", command=self.deselect_all_duplicates).pack(side=tk.LEFT, padx=(0, 5))

        self.refresh_btn = ttk.Button(action_buttons_frame, text="Refresh",
                                     command=self.refresh_duplicates, width=10)
        self.refresh_btn.pack(side=tk.LEFT, padx=(5, 5))

        ttk.Button(action_buttons_frame, text="Delete Selected",
                   command=self.delete_selected_duplicates_new,
                   style='Danger.TButton', width=15).pack(side=tk.LEFT, padx=(5, 0))

        # Export buttons for duplicates
        ttk.Separator(action_buttons_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=(15, 10), fill=tk.Y)
        ttk.Label(action_buttons_frame, text="Export:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_buttons_frame, text="CSV", command=lambda: self.export_duplicates('csv'), width=5).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(action_buttons_frame, text="JSON", command=lambda: self.export_duplicates('json'), width=5).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(action_buttons_frame, text="TXT", command=lambda: self.export_duplicates('txt'), width=5).pack(side=tk.LEFT)

        # Duplicates tree with improved layout
        tree_frame = ttk.Frame(self.duplicates_frame)
        tree_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        dup_columns = ('Select', 'Group', 'Count', 'Size', 'Waste', 'Files')
        self.duplicates_tree = ttk.Treeview(tree_frame, columns=dup_columns, show='headings', height=16)

        self.duplicates_tree.heading('Select', text='☐')
        self.duplicates_tree.heading('Group', text='Group')
        self.duplicates_tree.heading('Count', text='Count')
        self.duplicates_tree.heading('Size', text='Size')
        self.duplicates_tree.heading('Waste', text='Waste')
        self.duplicates_tree.heading('Files', text='Files')

        self.duplicates_tree.column('Select', width=50, anchor='center')
        self.duplicates_tree.column('Group', width=60)
        self.duplicates_tree.column('Count', width=60)
        self.duplicates_tree.column('Size', width=100)
        self.duplicates_tree.column('Waste', width=100)
        self.duplicates_tree.column('Files', width=670)

        dup_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.duplicates_tree.yview)
        self.duplicates_tree.configure(yscrollcommand=dup_scroll.set)

        self.duplicates_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        dup_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))

        self.duplicates_frame.columnconfigure(0, weight=1)
        self.duplicates_frame.rowconfigure(1, weight=1)

        # Bind events
        self.duplicates_tree.bind('<Button-1>', self.on_duplicate_click_new)
        self.duplicates_tree.bind('<Double-1>', self.on_duplicate_double_click)

        # Bind right-click menu for large files
        self.large_files_tree.bind("<Button-3>", self.show_large_files_menu)

        # Logs tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="📋 Logs")

        # Logs control frame
        logs_control_frame = ttk.Frame(self.logs_frame)
        logs_control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))

        ttk.Button(logs_control_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(logs_control_frame, text="Copy to Clipboard", command=self.copy_logs).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(logs_control_frame, text="Save Logs", command=self.save_logs).pack(side=tk.LEFT)

        # Log level filter
        ttk.Label(logs_control_frame, text="    Filter:").pack(side=tk.LEFT, padx=(20, 5))
        self.log_filter_var = tk.StringVar(value='All')
        log_filter_combo = ttk.Combobox(logs_control_frame, textvariable=self.log_filter_var,
                                        values=['All', 'INFO', 'WARNING', 'ERROR', 'DEBUG'],
                                        width=10, state='readonly')
        log_filter_combo.pack(side=tk.LEFT)
        log_filter_combo.bind('<<ComboboxSelected>>', self.filter_logs)

        # Logs text area
        self.logs_text = scrolledtext.ScrolledText(self.logs_frame, height=20, width=100,
                                                    font=('Consolas', 9), state=tk.DISABLED)
        self.logs_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.logs_frame.columnconfigure(0, weight=1)
        self.logs_frame.rowconfigure(1, weight=1)

        # Configure log text tags for different levels
        self.logs_text.tag_configure('INFO', foreground='black')
        self.logs_text.tag_configure('WARNING', foreground='orange')
        self.logs_text.tag_configure('ERROR', foreground='red')
        self.logs_text.tag_configure('DEBUG', foreground='gray')
        self.logs_text.tag_configure('SUCCESS', foreground='green')

        # Store all logs for filtering
        self.all_logs = []

        # Settings tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="⚙️ Settings")

        self.setup_settings_tab()

    def setup_settings_tab(self):
        """Setup the settings tab with folder exclusion options"""
        # Main container with padding
        settings_container = ttk.Frame(self.settings_frame, padding="20")
        settings_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.settings_frame.columnconfigure(0, weight=1)
        self.settings_frame.rowconfigure(0, weight=1)

        # Folder Exclusions Section
        exclusions_frame = ttk.LabelFrame(settings_container, text="Folder Exclusions", padding="15")
        exclusions_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        exclusions_frame.columnconfigure(1, weight=1)

        # Description
        desc_label = ttk.Label(exclusions_frame,
                               text="Uncheck folders to include them in scans. Warning: Scanning system folders may take much longer and include protected files.",
                               wraplength=600, foreground='gray')
        desc_label.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 15))

        # Folder exclusion checkboxes - arranged in a grid
        folders_frame = ttk.Frame(exclusions_frame)
        folders_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))

        # Row 1
        ttk.Checkbutton(folders_frame, text="Windows", variable=self.skip_windows,
                       command=self.on_folder_setting_changed).grid(row=0, column=0, sticky=tk.W, padx=(0, 30), pady=5)
        ttk.Label(folders_frame, text="(~20-40 GB)", foreground='gray').grid(row=0, column=1, sticky=tk.W, padx=(0, 50))

        ttk.Checkbutton(folders_frame, text="Program Files", variable=self.skip_program_files,
                       command=self.on_folder_setting_changed).grid(row=0, column=2, sticky=tk.W, padx=(0, 30), pady=5)
        ttk.Label(folders_frame, text="(varies)", foreground='gray').grid(row=0, column=3, sticky=tk.W)

        # Row 2
        ttk.Checkbutton(folders_frame, text="Program Files (x86)", variable=self.skip_program_files_x86,
                       command=self.on_folder_setting_changed).grid(row=1, column=0, sticky=tk.W, padx=(0, 30), pady=5)
        ttk.Label(folders_frame, text="(varies)", foreground='gray').grid(row=1, column=1, sticky=tk.W, padx=(0, 50))

        ttk.Checkbutton(folders_frame, text="Temp/Cache", variable=self.skip_temp,
                       command=self.on_folder_setting_changed).grid(row=1, column=2, sticky=tk.W, padx=(0, 30), pady=5)
        ttk.Label(folders_frame, text="(temp, tmp, cache)", foreground='gray').grid(row=1, column=3, sticky=tk.W)

        # Row 3
        ttk.Checkbutton(folders_frame, text="Recycle Bin", variable=self.skip_recycle_bin,
                       command=self.on_folder_setting_changed).grid(row=2, column=0, sticky=tk.W, padx=(0, 30), pady=5)
        ttk.Label(folders_frame, text="($Recycle.Bin)", foreground='gray').grid(row=2, column=1, sticky=tk.W, padx=(0, 50))

        ttk.Checkbutton(folders_frame, text="System Volume Info", variable=self.skip_system_volume,
                       command=self.on_folder_setting_changed).grid(row=2, column=2, sticky=tk.W, padx=(0, 30), pady=5)
        ttk.Label(folders_frame, text="(System restore)", foreground='gray').grid(row=2, column=3, sticky=tk.W)

        # Quick toggle buttons
        buttons_frame = ttk.Frame(exclusions_frame)
        buttons_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=(15, 0))

        ttk.Button(buttons_frame, text="Skip All (Default)", command=self.skip_all_folders).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="Include All (Full Scan)", command=self.include_all_folders).pack(side=tk.LEFT, padx=(0, 10))

        # Current status label
        self.folder_status_var = tk.StringVar(value="")
        self.update_folder_status()
        status_label = ttk.Label(exclusions_frame, textvariable=self.folder_status_var, foreground='blue')
        status_label.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(10, 0))

        # Note about cache
        note_frame = ttk.LabelFrame(settings_container, text="Notes", padding="15")
        note_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))

        note_text = ("• Changing folder settings will clear the cache for the next scan.\n"
                     "• Including system folders may show protected files that cannot be deleted.\n"
                     "• A full scan of C: drive with all folders included can take 10+ minutes.")
        ttk.Label(note_frame, text=note_text, wraplength=600, justify=tk.LEFT).grid(row=0, column=0, sticky=tk.W)

    def on_folder_setting_changed(self):
        """Handle folder exclusion checkbox changes"""
        self.update_folder_status()
        # Clear cache when settings change
        self.analyzer.clear_cache()
        self.log("INFO", "Folder settings changed - cache cleared")

    def update_folder_status(self):
        """Update the folder status label"""
        skipped = []
        if self.skip_windows.get():
            skipped.append("Windows")
        if self.skip_program_files.get():
            skipped.append("Program Files")
        if self.skip_program_files_x86.get():
            skipped.append("Program Files (x86)")
        if self.skip_temp.get():
            skipped.append("Temp/Cache")
        if self.skip_recycle_bin.get():
            skipped.append("Recycle Bin")
        if self.skip_system_volume.get():
            skipped.append("System Volume")

        if len(skipped) == 6:
            self.folder_status_var.set("Status: Default mode (skipping system folders)")
        elif len(skipped) == 0:
            self.folder_status_var.set("Status: Full scan mode (including all folders)")
        else:
            self.folder_status_var.set(f"Status: Skipping {len(skipped)} folder(s): {', '.join(skipped)}")

    def skip_all_folders(self):
        """Set all folder exclusions to True (default)"""
        self.skip_windows.set(True)
        self.skip_program_files.set(True)
        self.skip_program_files_x86.set(True)
        self.skip_temp.set(True)
        self.skip_recycle_bin.set(True)
        self.skip_system_volume.set(True)
        self.on_folder_setting_changed()

    def include_all_folders(self):
        """Set all folder exclusions to False (full scan)"""
        self.skip_windows.set(False)
        self.skip_program_files.set(False)
        self.skip_program_files_x86.set(False)
        self.skip_temp.set(False)
        self.skip_recycle_bin.set(False)
        self.skip_system_volume.set(False)
        self.on_folder_setting_changed()

    def get_skip_folders(self) -> set:
        """Get the set of folders to skip based on current settings"""
        skip = set()
        if self.skip_windows.get():
            skip.add('windows')
        if self.skip_program_files.get():
            skip.add('program files')
        if self.skip_program_files_x86.get():
            skip.add('program files (x86)')
        if self.skip_temp.get():
            skip.update(['temp', 'tmp', 'cache'])
        if self.skip_recycle_bin.get():
            skip.add('$recycle.bin')
        if self.skip_system_volume.get():
            skip.add('system volume information')
        return skip

    def update_drives_list(self):
        """Update the drives/directories combo box"""
        drives = self.analyzer.get_available_drives()
        self.drives_combo['values'] = ['All Drives'] + drives + ['── Custom Directories ──']

    def invalidate_cache(self):
        """Invalidate cache after files are deleted"""
        if self.last_scanned_path:
            self.analyzer.clear_cache(self.last_scanned_path)

    def clear_all_cache(self):
        """Clear all cached scan results"""
        self.analyzer.clear_cache()  # Clears all cache when no drive specified
        self.progress_var.set("Cache cleared - next scan will be fresh")
        self.log("INFO", "Cache cleared by user")

    def on_recycle_bin_toggle(self):
        """Handle Recycle Bin checkbox toggle"""
        if self.use_recycle_bin.get():
            self.log("INFO", "Delete mode: Move to Recycle Bin")
        else:
            self.log("INFO", "Delete mode: Permanent delete")

    def delete_file(self, filepath: str) -> Tuple[bool, str]:
        """
        Delete a file using either Recycle Bin or permanent delete.
        Returns (success, error_message)
        """
        try:
            if self.use_recycle_bin.get() and RECYCLE_BIN_AVAILABLE:
                send2trash(filepath)
                return True, ""
            else:
                os.remove(filepath)
                return True, ""
        except Exception as e:
            return False, str(e)

    def get_delete_action_text(self) -> str:
        """Get the appropriate text for delete action based on mode"""
        if self.use_recycle_bin.get() and RECYCLE_BIN_AVAILABLE:
            return "Move to Recycle Bin"
        return "Permanently delete"

    def log(self, level: str, message: str):
        """Add a log entry with timestamp"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"

        # Store log entry
        self.all_logs.append((level, log_entry))

        # Check if this log should be displayed based on current filter
        current_filter = self.log_filter_var.get()
        if current_filter == 'All' or current_filter == level:
            self._append_log(level, log_entry)

    def _append_log(self, level: str, log_entry: str):
        """Append a log entry to the text widget"""
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.insert(tk.END, log_entry + "\n", level)
        self.logs_text.see(tk.END)  # Auto-scroll to bottom
        self.logs_text.config(state=tk.DISABLED)

    def clear_logs(self):
        """Clear all logs"""
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.config(state=tk.DISABLED)
        self.all_logs.clear()

    def copy_logs(self):
        """Copy logs to clipboard"""
        self.root.clipboard_clear()
        logs_content = "\n".join(entry for _, entry in self.all_logs)
        self.root.clipboard_append(logs_content)
        self.log("INFO", "Logs copied to clipboard")

    def save_logs(self):
        """Save logs to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Logs"
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    for _, entry in self.all_logs:
                        f.write(entry + "\n")
                self.log("SUCCESS", f"Logs saved to {filename}")
            except Exception as e:
                self.log("ERROR", f"Failed to save logs: {e}")

    def filter_logs(self, event=None):
        """Filter displayed logs by level"""
        current_filter = self.log_filter_var.get()

        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.delete(1.0, tk.END)

        for level, entry in self.all_logs:
            if current_filter == 'All' or current_filter == level:
                self.logs_text.insert(tk.END, entry + "\n", level)

        self.logs_text.see(tk.END)
        self.logs_text.config(state=tk.DISABLED)

    def browse_directory(self):
        """Open directory browser and add selected directory to scan options"""
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        if directory:
            # Normalize the path
            directory = os.path.normpath(directory)

            # Get current values and add the new directory if not already present
            current_values = list(self.drives_combo['values'])

            # Find or create the custom directories section
            separator_text = '── Custom Directories ──'
            if separator_text not in current_values:
                current_values.append(separator_text)

            # Add the directory after the separator if not already there
            if directory not in current_values:
                separator_idx = current_values.index(separator_text)
                current_values.insert(separator_idx + 1, directory)
                self.drives_combo['values'] = current_values

            # Select the newly added directory
            self.drives_var.set(directory)

    def start_scan(self):
        """Start the disk scan"""
        if self.scanning:
            return

        try:
            min_size = int(self.min_size_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid minimum file size")
            return

        skip_folders = self.get_skip_folders()
        self.analyzer = DiskAnalyzer(min_size_mb=min_size, skip_folders=skip_folders)

        # Determine drives/directories to scan
        drives_selection = self.drives_var.get()
        if drives_selection == 'All Drives':
            drives_to_scan = self.analyzer.get_available_drives()
        elif drives_selection == '── Custom Directories ──':
            messagebox.showwarning("Invalid Selection", "Please select a specific drive or use 'Browse...' to select a directory")
            return
        else:
            # Could be a drive or a custom directory path
            drives_to_scan = [drives_selection]

        # Clear previous results
        self.clear_results()

        # Update UI
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar.start()
        self.progress_var.set(f"Starting scan of {', '.join(drives_to_scan)}...")

        # Log scan start
        self.log("INFO", f"Starting scan: {', '.join(drives_to_scan)} (min size: {min_size}MB)")

        # Track what we're scanning for cache invalidation
        self.last_scanned_path = drives_to_scan[0] if len(drives_to_scan) == 1 else None

        # Start scan thread
        self.scan_thread = threading.Thread(target=self.scan_worker, args=(drives_to_scan,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def scan_worker(self, drives_to_scan):
        """Worker thread for scanning with optimizations and caching"""
        try:
            start_time = time.time()
            cache_used = False

            # Try to load from cache for single drive scans
            if len(drives_to_scan) == 1:
                drive = drives_to_scan[0]
                self.progress_queue.put(('status', f'Checking cache for {drive}...'))
                if self.analyzer.load_cache(drive):
                    cache_used = True
                    self.progress_queue.put(('status', f'Loaded cached results for {drive}!'))
                    scan_time = time.time() - start_time

                    # Verify duplicates
                    duplicates = self.analyzer.verify_duplicates_with_full_hash(self.progress_queue)

                    # Send results
                    self.progress_queue.put(('complete', {
                        'scan_time': scan_time,
                        'files_scanned': self.analyzer.scanned_files,
                        'total_size': self.analyzer.total_size,
                        'largest_files': self.analyzer.find_largest_files(100),
                        'duplicates': duplicates,
                        'cache_used': True
                    }))
                    return

            # If no cache, perform full scan
            # Scan drives in parallel for better performance
            if len(drives_to_scan) > 1 and self.analyzer.max_workers > 1:
                self.progress_queue.put(('status', 'Starting parallel drive scanning...'))
                with ThreadPoolExecutor(max_workers=min(len(drives_to_scan), self.analyzer.max_workers)) as executor:
                    futures = []
                    for drive in drives_to_scan:
                        if os.path.exists(drive):
                            future = executor.submit(self.analyzer.scan_directory, drive, self.progress_queue)
                            futures.append(future)
                        else:
                            self.progress_queue.put(('status', f'Drive {drive} not accessible, skipping...'))

                    # Wait for all drives to complete
                    for future in as_completed(futures):
                        if self.analyzer.stop_scanning:
                            break
                        try:
                            future.result()  # This will raise any exceptions
                        except Exception as e:
                            self.progress_queue.put(('error', f'Drive scan error: {str(e)}'))
            else:
                # Sequential scanning for single drive or limited workers
                for drive in drives_to_scan:
                    if os.path.exists(drive) and not self.analyzer.stop_scanning:
                        self.progress_queue.put(('status', f'Scanning drive: {drive}'))
                        self.analyzer.scan_directory(drive, self.progress_queue)
                    else:
                        self.progress_queue.put(('status', f'Drive {drive} not accessible, skipping...'))

            if not self.analyzer.stop_scanning:
                # Save cache for single drive scans
                if len(drives_to_scan) == 1:
                    self.progress_queue.put(('status', 'Saving scan results to cache...'))
                    self.analyzer.save_cache(drives_to_scan[0])

                # Verify duplicates with full hash for accuracy
                self.progress_queue.put(('status', 'Verifying duplicates with full hash...'))
                duplicates = self.analyzer.verify_duplicates_with_full_hash(self.progress_queue)

                scan_time = time.time() - start_time

                # Send results
                self.progress_queue.put(('complete', {
                    'scan_time': scan_time,
                    'files_scanned': self.analyzer.scanned_files,
                    'total_size': self.analyzer.total_size,
                    'largest_files': self.analyzer.find_largest_files(100),
                    'duplicates': duplicates,
                    'cache_used': False
                }))

        except Exception as e:
            self.progress_queue.put(('error', str(e)))
        
    def stop_scan(self):
        """Stop the current scan"""
        self.analyzer.stop_scanning = True
        self.progress_var.set("Stopping scan...")
        self.log("WARNING", "Scan stopped by user")
        
    def check_progress_queue(self):
        """Check for progress updates"""
        try:
            while True:
                msg_type, *data = self.progress_queue.get_nowait()

                if msg_type == 'progress':
                    files_scanned, current_file = data
                    self.progress_var.set(f"Scanned {files_scanned:,} files... {current_file[:60]}...")
                    self.log("DEBUG", f"Scanned {files_scanned:,} files - {current_file}")

                elif msg_type == 'status':
                    status = data[0]
                    self.progress_var.set(status)
                    self.log("INFO", status)

                elif msg_type == 'complete':
                    self.scan_complete(data[0])

                elif msg_type == 'refresh_complete':
                    self.refresh_complete(data[0])

                elif msg_type == 'error':
                    self.scan_error(data[0])

        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(100, self.check_progress_queue)
        
    def scan_complete(self, results):
        """Handle scan completion"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()

        # Update progress
        scan_time = results['scan_time']
        files_scanned = results['files_scanned']
        total_size = self.analyzer.format_size(results['total_size'])
        cache_used = results.get('cache_used', False)

        if cache_used:
            self.progress_var.set(f"Loaded from cache! {files_scanned:,} files ({total_size}) in {scan_time:.1f}s")
            self.log("SUCCESS", f"Loaded from cache: {files_scanned:,} files ({total_size}) in {scan_time:.1f}s")
        else:
            self.progress_var.set(f"Scan complete! {files_scanned:,} files ({total_size}) in {scan_time:.1f}s")
            self.log("SUCCESS", f"Scan complete: {files_scanned:,} files ({total_size}) in {scan_time:.1f}s")

        # Log summary
        num_large_files = len(results['largest_files'])
        num_duplicates = len(results['duplicates'])
        self.log("INFO", f"Found {num_large_files} large files and {num_duplicates} duplicate groups")

        # Populate results
        self.populate_large_files(results['largest_files'])
        self.populate_duplicates(results['duplicates'])
        
    def refresh_complete(self, duplicates):
        """Handle refresh completion"""
        self.progress_bar.stop()
        self.progress_var.set("Refresh complete!")
        self.log("SUCCESS", f"Refresh complete - {len(duplicates)} duplicate groups")
        
        # Update duplicates display
        self.populate_duplicates(duplicates)
        
    def scan_error(self, error_msg):
        """Handle scan error"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.progress_var.set(f"Scan error: {error_msg}")
        self.log("ERROR", f"Scan error: {error_msg}")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")
        
    def populate_large_files(self, largest_files):
        """Populate the large files tree"""
        # Store all files for filtering
        self.all_large_files = largest_files
        self.current_filter = 'All Files'
        self.filter_var.set('All Files')

        # Calculate and display category breakdown
        self.update_category_summary()

        # Apply filter and display
        self.apply_file_filter()

    def update_category_summary(self):
        """Calculate and update the category breakdown summary"""
        if not self.all_large_files:
            self.category_summary_var.set("")
            return

        # Calculate totals by category
        category_sizes = defaultdict(int)
        category_counts = defaultdict(int)

        for size, filepath in self.all_large_files:
            # Parse size string back to bytes for calculation
            category = get_file_category(filepath)
            try:
                # Get actual file size if possible
                actual_size = os.path.getsize(filepath)
                category_sizes[category] += actual_size
                category_counts[category] += 1
            except OSError:
                category_counts[category] += 1

        # Build summary string (top 4 categories by size)
        sorted_categories = sorted(category_sizes.items(), key=lambda x: x[1], reverse=True)[:4]
        summary_parts = []
        for cat, size in sorted_categories:
            summary_parts.append(f"{cat}: {self.analyzer.format_size(size)}")

        if summary_parts:
            self.category_summary_var.set(" | ".join(summary_parts))
        else:
            self.category_summary_var.set("")

    def apply_file_filter(self):
        """Apply the current filter to the large files list"""
        # Clear current display
        for item in self.large_files_tree.get_children():
            self.large_files_tree.delete(item)

        self.selected_large_files.clear()

        # Get filter
        filter_category = self.filter_var.get()

        # Filter and display files
        for size, filepath in self.all_large_files:
            if filter_category == 'All Files':
                self.large_files_tree.insert('', tk.END, values=('☐', size, filepath))
            else:
                file_category = get_file_category(filepath)
                if file_category == filter_category:
                    self.large_files_tree.insert('', tk.END, values=('☐', size, filepath))

    def on_filter_changed(self, event=None):
        """Handle filter dropdown change"""
        self.current_filter = self.filter_var.get()
        self.apply_file_filter()
            
    def populate_duplicates(self, duplicates):
        """Populate the duplicates tree"""
        for item in self.duplicates_tree.get_children():
            self.duplicates_tree.delete(item)

        self.selected_duplicates.clear()
        self.duplicate_data.clear()

        if not duplicates:
            self.duplicates_info.config(text="No duplicate files found")
            return

        # Calculate total waste
        total_waste = self.analyzer.calculate_duplicate_waste(duplicates)
        self.duplicates_info.config(text=f"Found {len(duplicates)} duplicate groups, potential savings: {self.analyzer.format_size(total_waste)}")

        # Sort by waste
        duplicate_groups = []
        for file_hash, filepaths in duplicates.items():
            try:
                file_size = os.path.getsize(filepaths[0])
                waste = (len(filepaths) - 1) * file_size
                duplicate_groups.append((waste, file_size, filepaths))
            except OSError:
                continue

        duplicate_groups.sort(reverse=True)

        # Add to tree
        for i, (waste, file_size, filepaths) in enumerate(duplicate_groups[:50], 1):
            files_str = " | ".join(filepaths)
            item_id = self.duplicates_tree.insert('', tk.END, values=(
                '☐',
                f"#{i}",
                len(filepaths),
                self.analyzer.format_size(file_size),
                self.analyzer.format_size(waste),
                files_str
            ))
            # Store the file paths in our data dictionary
            self.duplicate_data[item_id] = filepaths
            
    def refresh_duplicates(self):
        """Refresh the duplicates list by re-analyzing current data"""
        if not hasattr(self.analyzer, 'file_hashes') or not self.analyzer.file_hashes:
            messagebox.showinfo("No Data", "Please run a scan first to find duplicates")
            return
        
        # Show progress
        self.progress_var.set("Refreshing duplicates...")
        self.progress_bar.start()
        
        # Re-verify duplicates in a separate thread to avoid blocking UI
        def refresh_worker():
            try:
                duplicates = self.analyzer.verify_duplicates_with_full_hash(self.progress_queue)
                self.progress_queue.put(('refresh_complete', duplicates))
            except Exception as e:
                self.progress_queue.put(('error', f'Refresh error: {str(e)}'))
        
        refresh_thread = threading.Thread(target=refresh_worker)
        refresh_thread.daemon = True
        refresh_thread.start()
        
    def show_large_files_menu(self, event):
        """Show context menu for large files"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Open File Location", command=self.open_file_location)
        menu.add_command(label="Delete File", command=self.delete_selected_file)
        menu.tk_popup(event.x_root, event.y_root)
        
        
    def open_file_location(self):
        """Open file location in explorer"""
        selection = self.large_files_tree.selection()
        if selection:
            item = selection[0]
            filepath = self.large_files_tree.item(item)['values'][2]  # Updated index for checkbox column
            try:
                subprocess.run(['explorer', '/select,', filepath])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file location: {e}")

    def delete_selected_file(self):
        """Delete selected file (from right-click menu)"""
        selection = self.large_files_tree.selection()
        if selection:
            item = selection[0]
            filepath = self.large_files_tree.item(item)['values'][2]  # Updated index for checkbox column

            action = self.get_delete_action_text()
            result = messagebox.askyesno("Confirm Delete",
                                       f"{action} this file?\n\n{filepath}")
            if result:
                success, error = self.delete_file(filepath)
                if success:
                    self.large_files_tree.delete(item)
                    if item in self.selected_large_files:
                        self.selected_large_files.remove(item)
                    self.invalidate_cache()
                    self.log("SUCCESS", f"Deleted: {filepath}")
                    if self.use_recycle_bin.get() and RECYCLE_BIN_AVAILABLE:
                        messagebox.showinfo("Success", "File moved to Recycle Bin")
                    else:
                        messagebox.showinfo("Success", "File deleted permanently")
                else:
                    self.log("ERROR", f"Failed to delete {filepath}: {error}")
                    messagebox.showerror("Error", f"Could not delete file: {error}")
                    
    
    def delete_duplicate_group(self, item):
        """Delete duplicates for a specific group"""
        try:
            filepaths = self.duplicate_data.get(item, [])
            if not filepaths or len(filepaths) <= 1:
                return

            action = self.get_delete_action_text()
            # Show confirmation dialog
            files_to_delete = filepaths[1:]  # Keep first file, delete rest
            message = f"{action} {len(files_to_delete)} duplicate files?\n\nKeep: {filepaths[0]}\n\nDelete:\n"
            message += "\n".join(f"• {fp}" for fp in files_to_delete[:5])
            if len(files_to_delete) > 5:
                message += f"\n... and {len(files_to_delete) - 5} more"

            result = messagebox.askyesno("Confirm Delete Duplicates", message)
            if result:
                deleted_count = 0
                errors = []

                for filepath in files_to_delete:
                    success, error = self.delete_file(filepath)
                    if success:
                        deleted_count += 1
                    else:
                        errors.append(f"{filepath}: {error}")

                # Show results
                if deleted_count > 0:
                    self.duplicates_tree.delete(item)
                    # Remove from our data dictionary
                    if item in self.duplicate_data:
                        del self.duplicate_data[item]
                    self.invalidate_cache()
                    if self.use_recycle_bin.get() and RECYCLE_BIN_AVAILABLE:
                        message = f"Moved {deleted_count} duplicate files to Recycle Bin"
                    else:
                        message = f"Permanently deleted {deleted_count} duplicate files"
                    if errors:
                        message += f"\n\nErrors ({len(errors)}):\n" + "\n".join(errors[:3])
                        if len(errors) > 3:
                            message += f"\n... and {len(errors) - 3} more errors"
                    messagebox.showinfo("Delete Complete", message)
                else:
                    messagebox.showerror("Delete Failed", "No files were deleted.\n\n" + "\n".join(errors[:5]))

        except Exception as e:
            messagebox.showerror("Error", f"Could not delete duplicates: {e}")
    
    def open_duplicate_group_locations(self, item):
        """Open file locations for a specific duplicate group"""
        try:
            filepaths = self.duplicate_data.get(item, [])
            if not filepaths:
                return
            
            # Open up to 3 locations to avoid overwhelming the user
            for filepath in filepaths[:3]:
                try:
                    subprocess.run(['explorer', '/select,', filepath], check=False)
                except Exception:
                    pass
                    
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file locations: {e}")
    
    def delete_selected_duplicates(self):
        """Delete duplicates for selected items (old method, kept for compatibility)"""
        selection = self.duplicates_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select duplicate groups to delete")
            return

        for item in selection:
            self.delete_duplicate_group(item)

        # Refresh the duplicates list after deletion
        if selection:
            self.refresh_duplicates()

    def clear_results(self):
        """Clear all results"""
        for item in self.large_files_tree.get_children():
            self.large_files_tree.delete(item)
        for item in self.duplicates_tree.get_children():
            self.duplicates_tree.delete(item)
        self.duplicate_data.clear()
        self.selected_large_files.clear()
        self.selected_duplicates.clear()
        self.all_large_files.clear()
        self.filter_var.set('All Files')
        self.category_summary_var.set("")
        self.duplicates_info.config(text="No duplicates found yet")

    # New checkbox-based selection methods
    def on_large_file_click(self, event):
        """Handle clicks on large files tree"""
        region = self.large_files_tree.identify('region', event.x, event.y)
        if region == 'cell':
            column = self.large_files_tree.identify_column(event.x)
            item = self.large_files_tree.identify_row(event.y)

            if column == '#1' and item:  # Checkbox column
                self.toggle_large_file_selection(item)
                return 'break'

    def toggle_large_file_selection(self, item):
        """Toggle selection of a large file"""
        values = list(self.large_files_tree.item(item)['values'])
        if item in self.selected_large_files:
            self.selected_large_files.remove(item)
            values[0] = '☐'
        else:
            self.selected_large_files.add(item)
            values[0] = '☑'
        self.large_files_tree.item(item, values=values)

    def select_all_large_files(self):
        """Select all large files"""
        for item in self.large_files_tree.get_children():
            if item not in self.selected_large_files:
                self.selected_large_files.add(item)
                values = list(self.large_files_tree.item(item)['values'])
                values[0] = '☑'
                self.large_files_tree.item(item, values=values)

    def deselect_all_large_files(self):
        """Deselect all large files"""
        for item in self.large_files_tree.get_children():
            if item in self.selected_large_files:
                self.selected_large_files.remove(item)
                values = list(self.large_files_tree.item(item)['values'])
                values[0] = '☐'
                self.large_files_tree.item(item, values=values)

    def delete_selected_large_files(self):
        """Delete all selected large files with confirmation"""
        if not self.selected_large_files:
            messagebox.showwarning("No Selection", "Please select files to delete using the checkboxes")
            return

        action = self.get_delete_action_text()

        # Collect file paths
        files_to_delete = []
        for item in self.selected_large_files:
            filepath = self.large_files_tree.item(item)['values'][2]
            files_to_delete.append((item, filepath))

        # Show confirmation
        message = f"{action} {len(files_to_delete)} selected files?\n\n"
        message += "\n".join(f"• {fp}" for _, fp in files_to_delete[:10])
        if len(files_to_delete) > 10:
            message += f"\n... and {len(files_to_delete) - 10} more files"

        result = messagebox.askyesno("Confirm Delete", message)
        if not result:
            return

        # Delete files
        deleted_count = 0
        errors = []

        for item, filepath in files_to_delete:
            success, error = self.delete_file(filepath)
            if success:
                self.large_files_tree.delete(item)
                deleted_count += 1
            else:
                errors.append(f"{filepath}: {error}")

        # Clean up selected set
        self.selected_large_files.clear()

        # Invalidate cache if any files were deleted
        if deleted_count > 0:
            self.invalidate_cache()

        # Show results and log
        if deleted_count > 0:
            if self.use_recycle_bin.get() and RECYCLE_BIN_AVAILABLE:
                self.log("SUCCESS", f"Moved {deleted_count} files to Recycle Bin")
                message = f"Moved {deleted_count} files to Recycle Bin"
            else:
                self.log("SUCCESS", f"Permanently deleted {deleted_count} files")
                message = f"Permanently deleted {deleted_count} files"
            if errors:
                message += f"\n\nErrors ({len(errors)}):\n" + "\n".join(errors[:5])
                if len(errors) > 5:
                    message += f"\n... and {len(errors) - 5} more errors"
                for err in errors:
                    self.log("ERROR", f"Delete failed: {err}")
            messagebox.showinfo("Delete Complete", message)
        else:
            self.log("ERROR", f"Delete failed - no files deleted")
            messagebox.showerror("Delete Failed", "No files were deleted.\n\n" + "\n".join(errors[:5]))

    def on_duplicate_click_new(self, event):
        """Handle clicks on duplicates tree"""
        region = self.duplicates_tree.identify('region', event.x, event.y)
        if region == 'cell':
            column = self.duplicates_tree.identify_column(event.x)
            item = self.duplicates_tree.identify_row(event.y)

            if column == '#1' and item:  # Checkbox column
                self.toggle_duplicate_selection(item)
                return 'break'

    def on_duplicate_double_click(self, event):
        """Handle double-click on duplicates to open file locations"""
        item = self.duplicates_tree.selection()[0] if self.duplicates_tree.selection() else None
        if item:
            self.open_duplicate_group_locations(item)

    def toggle_duplicate_selection(self, item):
        """Toggle selection of a duplicate group"""
        values = list(self.duplicates_tree.item(item)['values'])
        if item in self.selected_duplicates:
            self.selected_duplicates.remove(item)
            values[0] = '☐'
        else:
            self.selected_duplicates.add(item)
            values[0] = '☑'
        self.duplicates_tree.item(item, values=values)

    def select_all_duplicates(self):
        """Select all duplicate groups"""
        for item in self.duplicates_tree.get_children():
            if item not in self.selected_duplicates:
                self.selected_duplicates.add(item)
                values = list(self.duplicates_tree.item(item)['values'])
                values[0] = '☑'
                self.duplicates_tree.item(item, values=values)

    def deselect_all_duplicates(self):
        """Deselect all duplicate groups"""
        for item in self.duplicates_tree.get_children():
            if item in self.selected_duplicates:
                self.selected_duplicates.remove(item)
                values = list(self.duplicates_tree.item(item)['values'])
                values[0] = '☐'
                self.duplicates_tree.item(item, values=values)

    def delete_selected_duplicates_new(self):
        """Delete all selected duplicate groups with confirmation"""
        if not self.selected_duplicates:
            messagebox.showwarning("No Selection", "Please select duplicate groups to delete using the checkboxes")
            return

        action = self.get_delete_action_text()

        # Collect all files to delete
        all_files_to_delete = []
        total_groups = len(self.selected_duplicates)

        for item in self.selected_duplicates:
            filepaths = self.duplicate_data.get(item, [])
            if len(filepaths) > 1:
                # Keep first file, delete rest
                files_to_delete = filepaths[1:]
                all_files_to_delete.extend([(item, fp) for fp in files_to_delete])

        if not all_files_to_delete:
            messagebox.showinfo("No Files", "No duplicate files to delete")
            return

        # Show confirmation
        message = f"{action} {len(all_files_to_delete)} duplicate files from {total_groups} groups?\n\n"
        message += "First 10 files to be deleted:\n"
        message += "\n".join(f"• {fp}" for _, fp in all_files_to_delete[:10])
        if len(all_files_to_delete) > 10:
            message += f"\n... and {len(all_files_to_delete) - 10} more files"

        result = messagebox.askyesno("Confirm Delete Duplicates", message)
        if not result:
            return

        # Delete files
        deleted_count = 0
        errors = []
        deleted_items = set()

        for item, filepath in all_files_to_delete:
            success, error = self.delete_file(filepath)
            if success:
                deleted_count += 1
                deleted_items.add(item)
            else:
                errors.append(f"{filepath}: {error}")

        # Remove deleted items from tree
        for item in deleted_items:
            self.duplicates_tree.delete(item)
            if item in self.duplicate_data:
                del self.duplicate_data[item]

        # Clean up selected set
        self.selected_duplicates.clear()

        # Invalidate cache if any files were deleted
        if deleted_count > 0:
            self.invalidate_cache()

        # Show results and log
        if deleted_count > 0:
            if self.use_recycle_bin.get() and RECYCLE_BIN_AVAILABLE:
                self.log("SUCCESS", f"Moved {deleted_count} duplicate files to Recycle Bin from {len(deleted_items)} groups")
                message = f"Moved {deleted_count} duplicate files to Recycle Bin from {len(deleted_items)} groups"
            else:
                self.log("SUCCESS", f"Permanently deleted {deleted_count} duplicate files from {len(deleted_items)} groups")
                message = f"Permanently deleted {deleted_count} duplicate files from {len(deleted_items)} groups"
            if errors:
                message += f"\n\nErrors ({len(errors)}):\n" + "\n".join(errors[:5])
                if len(errors) > 5:
                    message += f"\n... and {len(errors) - 5} more errors"
                for err in errors:
                    self.log("ERROR", f"Delete failed: {err}")
            messagebox.showinfo("Delete Complete", message)

            # Refresh duplicates if needed
            if not errors:
                self.refresh_duplicates()
        else:
            self.log("ERROR", "Delete failed - no duplicate files deleted")
            messagebox.showerror("Delete Failed", "No files were deleted.\n\n" + "\n".join(errors[:10]))

    # ===== EXPORT METHODS =====

    def export_large_files(self, format_type: str):
        """Export large files list to CSV, JSON, or TXT"""
        if not self.all_large_files:
            messagebox.showwarning("No Data", "No large files to export. Please run a scan first.")
            return

        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"large_files_{timestamp}"

        # Get file extension and filetypes based on format
        if format_type == 'csv':
            ext = '.csv'
            filetypes = [("CSV files", "*.csv"), ("All files", "*.*")]
        elif format_type == 'json':
            ext = '.json'
            filetypes = [("JSON files", "*.json"), ("All files", "*.*")]
        else:  # txt
            ext = '.txt'
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]

        # Ask for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=filetypes,
            initialfile=default_filename + ext,
            title=f"Export Large Files as {format_type.upper()}"
        )

        if not filename:
            return

        try:
            # Prepare data
            export_data = []
            for rank, (size, filepath) in enumerate(self.all_large_files, 1):
                try:
                    size_bytes = os.path.getsize(filepath)
                except OSError:
                    size_bytes = 0
                category = get_file_category(filepath)
                export_data.append({
                    'rank': rank,
                    'size': size,
                    'size_bytes': size_bytes,
                    'path': filepath,
                    'category': category,
                    'filename': os.path.basename(filepath)
                })

            # Write file based on format
            if format_type == 'csv':
                self._export_csv(filename, export_data, ['rank', 'size', 'size_bytes', 'path', 'category', 'filename'])
            elif format_type == 'json':
                self._export_json(filename, {
                    'export_type': 'large_files',
                    'export_date': datetime.now().isoformat(),
                    'total_files': len(export_data),
                    'files': export_data
                })
            else:  # txt
                self._export_large_files_txt(filename, export_data)

            self.log("SUCCESS", f"Exported {len(export_data)} large files to {filename}")
            messagebox.showinfo("Export Complete", f"Successfully exported {len(export_data)} files to:\n{filename}")

        except Exception as e:
            self.log("ERROR", f"Export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    def export_duplicates(self, format_type: str):
        """Export duplicates list to CSV, JSON, or TXT"""
        if not self.duplicate_data:
            messagebox.showwarning("No Data", "No duplicates to export. Please run a scan first.")
            return

        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"duplicates_{timestamp}"

        # Get file extension and filetypes based on format
        if format_type == 'csv':
            ext = '.csv'
            filetypes = [("CSV files", "*.csv"), ("All files", "*.*")]
        elif format_type == 'json':
            ext = '.json'
            filetypes = [("JSON files", "*.json"), ("All files", "*.*")]
        else:  # txt
            ext = '.txt'
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]

        # Ask for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=filetypes,
            initialfile=default_filename + ext,
            title=f"Export Duplicates as {format_type.upper()}"
        )

        if not filename:
            return

        try:
            # Prepare data
            export_data = []
            total_waste = 0

            for group_num, (item_id, filepaths) in enumerate(self.duplicate_data.items(), 1):
                if len(filepaths) <= 1:
                    continue

                try:
                    size_bytes = os.path.getsize(filepaths[0])
                    size = self.analyzer.format_size(size_bytes)
                    waste = (len(filepaths) - 1) * size_bytes
                    total_waste += waste
                except OSError:
                    size_bytes = 0
                    size = "Unknown"
                    waste = 0

                for filepath in filepaths:
                    export_data.append({
                        'group': group_num,
                        'size': size,
                        'size_bytes': size_bytes,
                        'waste_bytes': waste,
                        'waste': self.analyzer.format_size(waste),
                        'copies': len(filepaths),
                        'path': filepath,
                        'filename': os.path.basename(filepath)
                    })

            # Write file based on format
            if format_type == 'csv':
                self._export_csv(filename, export_data, ['group', 'size', 'size_bytes', 'copies', 'waste', 'path', 'filename'])
            elif format_type == 'json':
                # For JSON, group by duplicate groups
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

                self._export_json(filename, {
                    'export_type': 'duplicates',
                    'export_date': datetime.now().isoformat(),
                    'total_groups': len(grouped_data),
                    'total_waste': self.analyzer.format_size(total_waste),
                    'total_waste_bytes': total_waste,
                    'groups': list(grouped_data.values())
                })
            else:  # txt
                self._export_duplicates_txt(filename, export_data, total_waste)

            num_groups = len(set(item['group'] for item in export_data))
            self.log("SUCCESS", f"Exported {num_groups} duplicate groups to {filename}")
            messagebox.showinfo("Export Complete", f"Successfully exported {num_groups} duplicate groups to:\n{filename}")

        except Exception as e:
            self.log("ERROR", f"Export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    def _export_csv(self, filename: str, data: list, fieldnames: list):
        """Write data to CSV file"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(data)

    def _export_json(self, filename: str, data: dict):
        """Write data to JSON file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _export_large_files_txt(self, filename: str, data: list):
        """Write large files data to TXT file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("LARGE FILES REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Files: {len(data)}\n")
            f.write("=" * 80 + "\n\n")

            for item in data:
                f.write(f"{item['rank']:4d}. [{item['category']:12s}] {item['size']:>12s}  {item['path']}\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")

    def _export_duplicates_txt(self, filename: str, data: list, total_waste: int):
        """Write duplicates data to TXT file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("DUPLICATE FILES REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            num_groups = len(set(item['group'] for item in data))
            f.write(f"Total Duplicate Groups: {num_groups}\n")
            f.write(f"Potential Space Savings: {self.analyzer.format_size(total_waste)}\n")
            f.write("=" * 80 + "\n\n")

            current_group = None
            for item in data:
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

def main():
    root = tk.Tk()
    app = DiskCleanerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
