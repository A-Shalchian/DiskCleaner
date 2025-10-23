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

class DiskAnalyzer:
    def __init__(self, min_size_mb: int = 1):
        self.min_size_bytes = min_size_mb * 1024 * 1024
        self.file_hashes: Dict[str, List[str]] = defaultdict(list)
        self.large_files: List[Tuple[int, str]] = []
        self.scanned_files = 0
        self.total_size = 0
        self.stop_scanning = False
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
    
    def scan_directory(self, directory: str, progress_queue: queue.Queue):
        """Scan directory for files and collect size/hash information with optimizations"""
        try:
            for root, dirs, files in os.walk(directory):
                if self.stop_scanning:
                    break
                    
                # Skip system directories that might cause issues
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d.lower() not in ['system volume information', '$recycle.bin', 
                                          'windows', 'program files', 'program files (x86)',
                                          'temp', 'tmp', 'cache']]
                
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
        
        # Drive selection
        ttk.Label(settings_frame, text="Drives to scan:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.drives_var = tk.StringVar()
        drives_combo = ttk.Combobox(settings_frame, textvariable=self.drives_var, width=30)
        drives_combo['values'] = ['All Drives'] + self.analyzer.get_available_drives()
        drives_combo.set('All Drives')
        drives_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Min size
        ttk.Label(settings_frame, text="Min file size (MB):").grid(row=0, column=2, sticky=tk.W, padx=(10, 5))
        self.min_size_var = tk.StringVar(value="1")
        min_size_entry = ttk.Entry(settings_frame, textvariable=self.min_size_var, width=10)
        min_size_entry.grid(row=0, column=3, sticky=tk.W)
        
        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=2, column=0, columnspan=3, pady=(0, 10))
        
        self.scan_button = ttk.Button(control_frame, text="🔍 Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(control_frame, text="⏹ Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(control_frame, text="🗑 Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT)
        
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
        
        columns = ('Size', 'Path')
        self.large_files_tree = ttk.Treeview(self.large_files_frame, columns=columns, show='headings', height=20)
        self.large_files_tree.heading('Size', text='Size')
        self.large_files_tree.heading('Path', text='File Path')
        self.large_files_tree.column('Size', width=100)
        self.large_files_tree.column('Path', width=800)
        
        large_files_scroll = ttk.Scrollbar(self.large_files_frame, orient=tk.VERTICAL, command=self.large_files_tree.yview)
        self.large_files_tree.configure(yscrollcommand=large_files_scroll.set)
        
        self.large_files_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        large_files_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.large_files_frame.columnconfigure(0, weight=1)
        self.large_files_frame.rowconfigure(0, weight=1)
        
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
        
        self.refresh_btn = ttk.Button(action_buttons_frame, text="🔄 Refresh", 
                                     command=self.refresh_duplicates, width=12)
        self.refresh_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.open_locations_btn = ttk.Button(action_buttons_frame, text="📂 Open Locations", 
                                            command=self.open_duplicate_locations, width=15)
        self.open_locations_btn.pack(side=tk.LEFT)
        
        # Duplicates tree with improved layout
        tree_frame = ttk.Frame(self.duplicates_frame)
        tree_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        dup_columns = ('Group', 'Count', 'Size', 'Waste', 'Files', 'Actions')
        self.duplicates_tree = ttk.Treeview(tree_frame, columns=dup_columns, show='headings', height=16)
        
        for col in dup_columns:
            self.duplicates_tree.heading(col, text=col)
        self.duplicates_tree.column('Group', width=60)
        self.duplicates_tree.column('Count', width=60)
        self.duplicates_tree.column('Size', width=100)
        self.duplicates_tree.column('Waste', width=100)
        self.duplicates_tree.column('Files', width=600)
        self.duplicates_tree.column('Actions', width=120)
        
        dup_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.duplicates_tree.yview)
        self.duplicates_tree.configure(yscrollcommand=dup_scroll.set)
        
        self.duplicates_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        dup_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.duplicates_frame.columnconfigure(0, weight=1)
        self.duplicates_frame.rowconfigure(1, weight=1)
        
        # Commands tab
        self.commands_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.commands_frame, text="💻 Delete Commands")
        
        instructions = ttk.Label(self.commands_frame, 
                                text="Generated delete commands will appear here. Review carefully before executing!",
                                font=('Arial', 10, 'bold'))
        instructions.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        
        self.commands_text = scrolledtext.ScrolledText(self.commands_frame, height=20, width=100)
        self.commands_text.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        button_frame = ttk.Frame(self.commands_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(10, 0))
        
        ttk.Button(button_frame, text="💾 Save Commands", command=self.save_commands).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="📋 Copy to Clipboard", command=self.copy_commands).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="🗑 Clear Commands", command=self.clear_commands).pack(side=tk.LEFT)
        
        self.commands_frame.columnconfigure(0, weight=1)
        self.commands_frame.rowconfigure(1, weight=1)
        
        # Bind right-click menus and double-click for actions
        self.large_files_tree.bind("<Button-3>", self.show_large_files_menu)
        self.duplicates_tree.bind("<Button-3>", self.show_duplicates_menu)
        self.duplicates_tree.bind("<Double-1>", self.on_duplicate_action_click)
        self.duplicates_tree.bind("<Button-1>", self.on_duplicate_click)
        
    def start_scan(self):
        """Start the disk scan"""
        if self.scanning:
            return
            
        try:
            min_size = int(self.min_size_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid minimum file size")
            return
            
        # Reset analyzer
        self.analyzer = DiskAnalyzer(min_size_mb=min_size)
        
        # Determine drives to scan
        drives_selection = self.drives_var.get()
        if drives_selection == 'All Drives':
            drives_to_scan = self.analyzer.get_available_drives()
        else:
            drives_to_scan = [drives_selection]
        
        # Clear previous results
        self.clear_results()
        
        # Update UI
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar.start()
        self.progress_var.set(f"Starting scan of {', '.join(drives_to_scan)}...")
        
        # Start scan thread
        self.scan_thread = threading.Thread(target=self.scan_worker, args=(drives_to_scan,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def scan_worker(self, drives_to_scan):
        """Worker thread for scanning with optimizations"""
        try:
            start_time = time.time()
            
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
                    'duplicates': duplicates
                }))
            
        except Exception as e:
            self.progress_queue.put(('error', str(e)))
        
    def stop_scan(self):
        """Stop the current scan"""
        self.analyzer.stop_scanning = True
        self.progress_var.set("Stopping scan...")
        
    def check_progress_queue(self):
        """Check for progress updates"""
        try:
            while True:
                msg_type, *data = self.progress_queue.get_nowait()
                
                if msg_type == 'progress':
                    files_scanned, current_file = data
                    self.progress_var.set(f"Scanned {files_scanned:,} files... {current_file[:60]}...")
                    
                elif msg_type == 'status':
                    status = data[0]
                    self.progress_var.set(status)
                    
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
        
        self.progress_var.set(f"Scan complete! {files_scanned:,} files ({total_size}) in {scan_time:.1f}s")
        
        # Populate results
        self.populate_large_files(results['largest_files'])
        self.populate_duplicates(results['duplicates'])
        
    def refresh_complete(self, duplicates):
        """Handle refresh completion"""
        self.progress_bar.stop()
        self.progress_var.set("Refresh complete!")
        
        # Update duplicates display
        self.populate_duplicates(duplicates)
        
    def scan_error(self, error_msg):
        """Handle scan error"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.progress_var.set(f"Scan error: {error_msg}")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")
        
    def populate_large_files(self, largest_files):
        """Populate the large files tree"""
        for item in self.large_files_tree.get_children():
            self.large_files_tree.delete(item)
            
        for size, filepath in largest_files:
            self.large_files_tree.insert('', tk.END, values=(size, filepath))
            
    def populate_duplicates(self, duplicates):
        """Populate the duplicates tree"""
        for item in self.duplicates_tree.get_children():
            self.duplicates_tree.delete(item)
            
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
                f"#{i}",
                len(filepaths),
                self.analyzer.format_size(file_size),
                self.analyzer.format_size(waste),
                files_str,
                "🗑️ Delete | 📂 Open"
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
        
    def show_duplicates_menu(self, event):
        """Show context menu for duplicates"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="🗑️ Delete Duplicates", command=self.delete_selected_duplicates)
        menu.add_command(label="📂 Open File Locations", command=self.open_duplicate_locations)
        menu.tk_popup(event.x_root, event.y_root)
        
    def open_file_location(self):
        """Open file location in explorer"""
        selection = self.large_files_tree.selection()
        if selection:
            item = selection[0]
            filepath = self.large_files_tree.item(item)['values'][1]
            try:
                subprocess.run(['explorer', '/select,', filepath])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file location: {e}")
                
    def open_duplicate_locations(self):
        """Open duplicate file locations"""
        selection = self.duplicates_tree.selection()
        if selection:
            item = selection[0]
            files_str = self.duplicates_tree.item(item)['values'][4]
            filepaths = files_str.split(" | ")
            
            for filepath in filepaths[:3]:  # Limit to first 3 files
                try:
                    subprocess.run(['explorer', '/select,', filepath])
                except Exception:
                    pass
                    
    def delete_selected_file(self):
        """Delete selected file"""
        selection = self.large_files_tree.selection()
        if selection:
            item = selection[0]
            filepath = self.large_files_tree.item(item)['values'][1]
            
            result = messagebox.askyesno("Confirm Delete", 
                                       f"Are you sure you want to delete this file?\n\n{filepath}")
            if result:
                try:
                    os.remove(filepath)
                    self.large_files_tree.delete(item)
                    messagebox.showinfo("Success", "File deleted successfully")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not delete file: {e}")
                    
    def save_commands(self):
        """Save commands to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".bat",
            filetypes=[("Batch files", "*.bat"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.commands_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Commands saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {e}")
                
    def copy_commands(self):
        """Copy commands to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.commands_text.get(1.0, tk.END))
        messagebox.showinfo("Success", "Commands copied to clipboard")
        
    def clear_commands(self):
        """Clear the commands text"""
        self.commands_text.delete(1.0, tk.END)
        
    def on_duplicate_click(self, event):
        """Handle clicks on duplicate tree items"""
        item = self.duplicates_tree.identify('item', event.x, event.y)
        column = self.duplicates_tree.identify('column', event.x, event.y)
        
        if item and column == '#6':  # Actions column
            # Determine which action based on x position within the column
            bbox = self.duplicates_tree.bbox(item, column)
            if bbox:
                relative_x = event.x - bbox[0]
                if relative_x < bbox[2] // 2:  # Left half - Delete
                    self.delete_duplicate_group(item)
                else:  # Right half - Open
                    self.open_duplicate_group_locations(item)
    
    def on_duplicate_action_click(self, event):
        """Handle double-click on duplicate items"""
        item = self.duplicates_tree.selection()[0] if self.duplicates_tree.selection() else None
        if item:
            self.open_duplicate_group_locations(item)
    
    def delete_duplicate_group(self, item):
        """Delete duplicates for a specific group"""
        try:
            filepaths = self.duplicate_data.get(item, [])
            if not filepaths or len(filepaths) <= 1:
                return
            
            # Show confirmation dialog
            files_to_delete = filepaths[1:]  # Keep first file, delete rest
            message = f"Delete {len(files_to_delete)} duplicate files?\n\nKeep: {filepaths[0]}\n\nDelete:\n"
            message += "\n".join(f"• {fp}" for fp in files_to_delete[:5])
            if len(files_to_delete) > 5:
                message += f"\n... and {len(files_to_delete) - 5} more"
            
            result = messagebox.askyesno("Confirm Delete Duplicates", message)
            if result:
                deleted_count = 0
                errors = []
                
                for filepath in files_to_delete:
                    try:
                        os.remove(filepath)
                        deleted_count += 1
                    except Exception as e:
                        errors.append(f"{filepath}: {str(e)}")
                
                # Show results
                if deleted_count > 0:
                    self.duplicates_tree.delete(item)
                    # Remove from our data dictionary
                    if item in self.duplicate_data:
                        del self.duplicate_data[item]
                    message = f"Successfully deleted {deleted_count} duplicate files"
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
        """Delete duplicates for selected items"""
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
        self.duplicate_data.clear()  # Clear stored file paths
        self.duplicates_info.config(text="No duplicates found yet")
        self.commands_text.delete(1.0, tk.END)

def main():
    root = tk.Tk()
    app = DiskCleanerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
