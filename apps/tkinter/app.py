import os
import threading
import time
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import DiskAnalyzer, RECYCLE_BIN_AVAILABLE
from version_manager import __version__

from .tabs import LargeFilesTab, DuplicatesTab, LogsTab


class DiskCleanerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Disk Cleaner - Space Analyzer & Duplicate Finder")
        self.root.geometry("1200x800")

        self.analyzer = DiskAnalyzer()
        self.progress_queue = queue.Queue()
        self.scanning = False
        self.scan_thread = None
        self.last_scanned_path = None
        self.use_recycle_bin = tk.BooleanVar(value=RECYCLE_BIN_AVAILABLE)

        self.setup_ui()
        self.check_progress_queue()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)

        title_label = ttk.Label(main_frame, text=f"Disk Cleaner v{__version__}", font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        settings_frame = ttk.LabelFrame(main_frame, text="Scan Settings", padding="10")
        settings_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        settings_frame.columnconfigure(1, weight=1)

        ttk.Label(settings_frame, text="Scan location:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.drives_var = tk.StringVar()
        self.drives_combo = ttk.Combobox(settings_frame, textvariable=self.drives_var, width=40)
        self.update_drives_list()
        self.drives_combo.set('All Drives')
        self.drives_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        ttk.Button(settings_frame, text="Browse...", command=self.browse_directory, width=12).grid(row=0, column=2, padx=(0, 10))

        ttk.Label(settings_frame, text="Min file size (MB):").grid(row=0, column=3, sticky=tk.W, padx=(10, 5))
        self.min_size_var = tk.StringVar(value="1")
        ttk.Entry(settings_frame, textvariable=self.min_size_var, width=10).grid(row=0, column=4, sticky=tk.W)

        delete_settings_frame = ttk.Frame(settings_frame)
        delete_settings_frame.grid(row=1, column=0, columnspan=5, sticky=tk.W, pady=(10, 0))

        self.recycle_bin_check = ttk.Checkbutton(
            delete_settings_frame,
            text="Move to Recycle Bin (safer)",
            variable=self.use_recycle_bin,
            command=self.on_recycle_bin_toggle
        )
        self.recycle_bin_check.pack(side=tk.LEFT, padx=(0, 20))

        if RECYCLE_BIN_AVAILABLE:
            recycle_status = ttk.Label(delete_settings_frame, text="send2trash installed", foreground='green')
        else:
            recycle_status = ttk.Label(delete_settings_frame, text="send2trash not installed - using permanent delete", foreground='orange')
            self.recycle_bin_check.config(state=tk.DISABLED)
        recycle_status.pack(side=tk.LEFT)

        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=2, column=0, columnspan=3, pady=(0, 10))

        self.scan_button = ttk.Button(control_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(control_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="Clear Cache", command=self.clear_all_cache).pack(side=tk.LEFT)

        self.progress_var = tk.StringVar(value="Ready to scan")
        ttk.Label(main_frame, textvariable=self.progress_var).grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(10, 5))

        self.progress_bar = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.large_files_tab = LargeFilesTab(self.notebook, self)
        self.duplicates_tab = DuplicatesTab(self.notebook, self)
        self.logs_tab = LogsTab(self.notebook, self)

        self.notebook.add(self.large_files_tab.frame, text="Largest Files")
        self.notebook.add(self.duplicates_tab.frame, text="Duplicate Files")
        self.notebook.add(self.logs_tab.frame, text="Logs")

    def update_drives_list(self):
        drives = self.analyzer.get_available_drives()
        self.drives_combo['values'] = ['All Drives'] + drives + ['-- Custom Directories --']

    def browse_directory(self):
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        if directory:
            directory = os.path.normpath(directory)
            current_values = list(self.drives_combo['values'])
            separator = '-- Custom Directories --'
            if separator not in current_values:
                current_values.append(separator)
            if directory not in current_values:
                separator_idx = current_values.index(separator)
                current_values.insert(separator_idx + 1, directory)
                self.drives_combo['values'] = current_values
            self.drives_var.set(directory)

    def on_recycle_bin_toggle(self):
        if self.use_recycle_bin.get():
            self.log("INFO", "Delete mode: Move to Recycle Bin")
        else:
            self.log("INFO", "Delete mode: Permanent delete")

    def log(self, level: str, message: str):
        self.logs_tab.log(level, message)

    def invalidate_cache(self):
        if self.last_scanned_path:
            self.analyzer.clear_cache(self.last_scanned_path)

    def clear_all_cache(self):
        self.analyzer.clear_cache()
        self.progress_var.set("Cache cleared - next scan will be fresh")
        self.log("INFO", "Cache cleared by user")

    def start_scan(self):
        if self.scanning:
            return

        try:
            min_size = int(self.min_size_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid minimum file size")
            return

        self.analyzer = DiskAnalyzer(min_size_mb=min_size)

        drives_selection = self.drives_var.get()
        if drives_selection == 'All Drives':
            drives_to_scan = self.analyzer.get_available_drives()
        elif drives_selection == '-- Custom Directories --':
            messagebox.showwarning("Invalid Selection", "Please select a specific drive or use 'Browse...' to select a directory")
            return
        else:
            drives_to_scan = [drives_selection]

        self.clear_results()

        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar.start()
        self.progress_var.set(f"Starting scan of {', '.join(drives_to_scan)}...")

        self.log("INFO", f"Starting scan: {', '.join(drives_to_scan)} (min size: {min_size}MB)")

        self.last_scanned_path = drives_to_scan[0] if len(drives_to_scan) == 1 else None

        self.scan_thread = threading.Thread(target=self.scan_worker, args=(drives_to_scan,))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def scan_worker(self, drives_to_scan):
        try:
            start_time = time.time()
            cache_used = False

            if len(drives_to_scan) == 1:
                drive = drives_to_scan[0]
                self.progress_queue.put(('status', f'Checking cache for {drive}...'))
                if self.analyzer.load_cache(drive):
                    cache_used = True
                    self.progress_queue.put(('status', f'Loaded cached results for {drive}!'))
                    scan_time = time.time() - start_time
                    duplicates = self.analyzer.verify_duplicates_with_full_hash(
                        lambda i, total: self.progress_queue.put(('progress', i, f'Verifying group {i+1}/{total}'))
                    )
                    self.progress_queue.put(('complete', {
                        'scan_time': scan_time,
                        'files_scanned': self.analyzer.scanned_files,
                        'total_size': self.analyzer.total_size,
                        'largest_files': self.analyzer.find_largest_files(100),
                        'duplicates': duplicates,
                        'cache_used': True
                    }))
                    return

            if len(drives_to_scan) > 1 and self.analyzer.max_workers > 1:
                self.progress_queue.put(('status', 'Starting parallel drive scanning...'))
                with ThreadPoolExecutor(max_workers=min(len(drives_to_scan), self.analyzer.max_workers)) as executor:
                    futures = []
                    for drive in drives_to_scan:
                        if os.path.exists(drive):
                            future = executor.submit(
                                self.analyzer.scan_directory, drive,
                                lambda count, path: self.progress_queue.put(('progress', count, path))
                            )
                            futures.append(future)

                    for future in as_completed(futures):
                        if self.analyzer.stop_scanning:
                            break
                        try:
                            future.result()
                        except Exception as e:
                            self.progress_queue.put(('error', str(e)))
            else:
                for drive in drives_to_scan:
                    if os.path.exists(drive) and not self.analyzer.stop_scanning:
                        self.progress_queue.put(('status', f'Scanning drive: {drive}'))
                        self.analyzer.scan_directory(
                            drive,
                            lambda count, path: self.progress_queue.put(('progress', count, path))
                        )

            if not self.analyzer.stop_scanning:
                if len(drives_to_scan) == 1:
                    self.progress_queue.put(('status', 'Saving scan results to cache...'))
                    self.analyzer.save_cache(drives_to_scan[0])

                self.progress_queue.put(('status', 'Verifying duplicates with full hash...'))
                duplicates = self.analyzer.verify_duplicates_with_full_hash(
                    lambda i, total: self.progress_queue.put(('progress', i, f'Verifying group {i+1}/{total}'))
                )

                scan_time = time.time() - start_time

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
        self.analyzer.stop_scanning = True
        self.progress_var.set("Stopping scan...")
        self.log("WARNING", "Scan stopped by user")

    def check_progress_queue(self):
        try:
            while True:
                msg_type, *data = self.progress_queue.get_nowait()

                if msg_type == 'progress':
                    files_scanned, current = data
                    self.progress_var.set(f"Scanned {files_scanned:,} files... {str(current)[:60]}...")
                    self.log("DEBUG", f"Scanned {files_scanned:,} files - {current}")

                elif msg_type == 'status':
                    self.progress_var.set(data[0])
                    self.log("INFO", data[0])

                elif msg_type == 'complete':
                    self.scan_complete(data[0])

                elif msg_type == 'refresh_complete':
                    self.refresh_complete(data[0])

                elif msg_type == 'error':
                    self.scan_error(data[0])

        except queue.Empty:
            pass

        self.root.after(100, self.check_progress_queue)

    def scan_complete(self, results):
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()

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

        self.log("INFO", f"Found {len(results['largest_files'])} large files and {len(results['duplicates'])} duplicate groups")

        self.large_files_tab.populate(results['largest_files'])
        self.duplicates_tab.populate(results['duplicates'])

    def refresh_duplicates(self):
        if not hasattr(self.analyzer, 'file_hashes') or not self.analyzer.file_hashes:
            messagebox.showinfo("No Data", "Please run a scan first to find duplicates")
            return

        self.progress_var.set("Refreshing duplicates...")
        self.progress_bar.start()

        def refresh_worker():
            try:
                duplicates = self.analyzer.verify_duplicates_with_full_hash(
                    lambda i, total: self.progress_queue.put(('progress', i, f'Verifying group {i+1}/{total}'))
                )
                self.progress_queue.put(('refresh_complete', duplicates))
            except Exception as e:
                self.progress_queue.put(('error', f'Refresh error: {str(e)}'))

        thread = threading.Thread(target=refresh_worker)
        thread.daemon = True
        thread.start()

    def refresh_complete(self, duplicates):
        self.progress_bar.stop()
        self.progress_var.set("Refresh complete!")
        self.log("SUCCESS", f"Refresh complete - {len(duplicates)} duplicate groups")
        self.duplicates_tab.populate(duplicates)

    def scan_error(self, error_msg):
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.progress_var.set(f"Scan error: {error_msg}")
        self.log("ERROR", f"Scan error: {error_msg}")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")

    def clear_results(self):
        self.large_files_tab.clear()
        self.duplicates_tab.clear()


def main():
    root = tk.Tk()
    app = DiskCleanerApp(root)
    root.mainloop()
