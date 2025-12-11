import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
from datetime import datetime

from core import FILE_CATEGORIES, get_file_category, delete_file, RECYCLE_BIN_AVAILABLE
from core import export_large_files_csv, export_large_files_json, export_large_files_txt


class LargeFilesTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = ttk.Frame(parent)
        self.all_large_files = []
        self.selected_files = set()
        self.current_filter = 'All Files'

        self.setup_ui()

    def setup_ui(self):
        top_frame = ttk.Frame(self.frame)
        top_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        top_frame.columnconfigure(1, weight=1)

        filter_frame = ttk.Frame(top_frame)
        filter_frame.grid(row=0, column=0, sticky=tk.W)

        ttk.Label(filter_frame, text="Filter by type:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar(value='All Files')
        self.filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, width=15, state='readonly')
        self.filter_combo['values'] = list(FILE_CATEGORIES.keys()) + ['Other']
        self.filter_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.filter_combo.bind('<<ComboboxSelected>>', self.on_filter_changed)

        self.category_summary_var = tk.StringVar(value="")
        self.category_summary_label = ttk.Label(top_frame, textvariable=self.category_summary_var, font=('Arial', 9))
        self.category_summary_label.grid(row=0, column=1, sticky=tk.E, padx=(10, 0))

        btn_frame = ttk.Frame(self.frame)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Button(btn_frame, text="Select All", command=self.select_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Deselect All", command=self.deselect_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected, style='Danger.TButton').pack(side=tk.LEFT, padx=(10, 0))

        ttk.Separator(btn_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=(15, 10), fill=tk.Y)
        ttk.Label(btn_frame, text="Export:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="CSV", command=lambda: self.export('csv'), width=5).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(btn_frame, text="JSON", command=lambda: self.export('json'), width=5).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(btn_frame, text="TXT", command=lambda: self.export('txt'), width=5).pack(side=tk.LEFT)

        columns = ('Select', 'Size', 'Path')
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings', height=20)
        self.tree.heading('Select', text='☐')
        self.tree.heading('Size', text='Size')
        self.tree.heading('Path', text='File Path')
        self.tree.column('Select', width=50, anchor='center')
        self.tree.column('Size', width=100)
        self.tree.column('Path', width=750)

        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=2, column=1, sticky=(tk.N, tk.S))

        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(2, weight=1)

        self.tree.bind('<Button-1>', self.on_click)
        self.tree.bind('<Button-3>', self.show_context_menu)

    def populate(self, large_files):
        self.all_large_files = large_files
        self.current_filter = 'All Files'
        self.filter_var.set('All Files')
        self.update_category_summary()
        self.apply_filter()

    def update_category_summary(self):
        if not self.all_large_files:
            self.category_summary_var.set("")
            return

        from collections import defaultdict
        category_sizes = defaultdict(int)

        for size, filepath in self.all_large_files:
            category = get_file_category(filepath)
            try:
                actual_size = os.path.getsize(filepath)
                category_sizes[category] += actual_size
            except OSError:
                pass

        sorted_categories = sorted(category_sizes.items(), key=lambda x: x[1], reverse=True)[:4]
        summary_parts = []
        for cat, size in sorted_categories:
            summary_parts.append(f"{cat}: {self.app.analyzer.format_size(size)}")

        self.category_summary_var.set(" | ".join(summary_parts) if summary_parts else "")

    def apply_filter(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.selected_files.clear()

        filter_category = self.filter_var.get()

        for size, filepath in self.all_large_files:
            if filter_category == 'All Files':
                self.tree.insert('', tk.END, values=('☐', size, filepath))
            else:
                file_category = get_file_category(filepath)
                if file_category == filter_category:
                    self.tree.insert('', tk.END, values=('☐', size, filepath))

    def on_filter_changed(self, event=None):
        self.current_filter = self.filter_var.get()
        self.apply_filter()

    def on_click(self, event):
        region = self.tree.identify('region', event.x, event.y)
        if region == 'cell':
            column = self.tree.identify_column(event.x)
            item = self.tree.identify_row(event.y)
            if column == '#1' and item:
                self.toggle_selection(item)
                return 'break'

    def toggle_selection(self, item):
        values = list(self.tree.item(item)['values'])
        if item in self.selected_files:
            self.selected_files.remove(item)
            values[0] = '☐'
        else:
            self.selected_files.add(item)
            values[0] = '☑'
        self.tree.item(item, values=values)

    def select_all(self):
        for item in self.tree.get_children():
            if item not in self.selected_files:
                self.selected_files.add(item)
                values = list(self.tree.item(item)['values'])
                values[0] = '☑'
                self.tree.item(item, values=values)

    def deselect_all(self):
        for item in self.tree.get_children():
            if item in self.selected_files:
                self.selected_files.remove(item)
                values = list(self.tree.item(item)['values'])
                values[0] = '☐'
                self.tree.item(item, values=values)

    def delete_selected(self):
        if not self.selected_files:
            messagebox.showwarning("No Selection", "Please select files to delete using the checkboxes")
            return

        use_recycle = self.app.use_recycle_bin.get()
        action = "Move to Recycle Bin" if (use_recycle and RECYCLE_BIN_AVAILABLE) else "Permanently delete"

        files_to_delete = []
        for item in self.selected_files:
            filepath = self.tree.item(item)['values'][2]
            files_to_delete.append((item, filepath))

        message = f"{action} {len(files_to_delete)} selected files?\n\n"
        message += "\n".join(f"• {fp}" for _, fp in files_to_delete[:10])
        if len(files_to_delete) > 10:
            message += f"\n... and {len(files_to_delete) - 10} more files"

        if not messagebox.askyesno("Confirm Delete", message):
            return

        deleted_count = 0
        errors = []

        for item, filepath in files_to_delete:
            success, error = delete_file(filepath, use_recycle)
            if success:
                self.tree.delete(item)
                deleted_count += 1
            else:
                errors.append(f"{filepath}: {error}")

        self.selected_files.clear()

        if deleted_count > 0:
            self.app.invalidate_cache()
            if use_recycle and RECYCLE_BIN_AVAILABLE:
                self.app.log("SUCCESS", f"Moved {deleted_count} files to Recycle Bin")
                msg = f"Moved {deleted_count} files to Recycle Bin"
            else:
                self.app.log("SUCCESS", f"Permanently deleted {deleted_count} files")
                msg = f"Permanently deleted {deleted_count} files"
            if errors:
                msg += f"\n\nErrors ({len(errors)}):\n" + "\n".join(errors[:5])
            messagebox.showinfo("Delete Complete", msg)
        else:
            messagebox.showerror("Delete Failed", "No files were deleted.\n\n" + "\n".join(errors[:5]))

    def show_context_menu(self, event):
        menu = tk.Menu(self.frame, tearoff=0)
        menu.add_command(label="Open File Location", command=self.open_file_location)
        menu.add_command(label="Delete File", command=self.delete_single_file)
        menu.tk_popup(event.x_root, event.y_root)

    def open_file_location(self):
        selection = self.tree.selection()
        if selection:
            filepath = self.tree.item(selection[0])['values'][2]
            try:
                subprocess.run(['explorer', '/select,', filepath])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file location: {e}")

    def delete_single_file(self):
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            filepath = self.tree.item(item)['values'][2]
            use_recycle = self.app.use_recycle_bin.get()
            action = "Move to Recycle Bin" if (use_recycle and RECYCLE_BIN_AVAILABLE) else "Permanently delete"

            if messagebox.askyesno("Confirm Delete", f"{action} this file?\n\n{filepath}"):
                success, error = delete_file(filepath, use_recycle)
                if success:
                    self.tree.delete(item)
                    if item in self.selected_files:
                        self.selected_files.remove(item)
                    self.app.invalidate_cache()
                    self.app.log("SUCCESS", f"Deleted: {filepath}")
                else:
                    messagebox.showerror("Error", f"Could not delete file: {error}")

    def export(self, format_type):
        if not self.all_large_files:
            messagebox.showwarning("No Data", "No large files to export. Please run a scan first.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"large_files_{timestamp}"

        ext_map = {'csv': '.csv', 'json': '.json', 'txt': '.txt'}
        filetypes_map = {
            'csv': [("CSV files", "*.csv"), ("All files", "*.*")],
            'json': [("JSON files", "*.json"), ("All files", "*.*")],
            'txt': [("Text files", "*.txt"), ("All files", "*.*")]
        }

        filename = filedialog.asksaveasfilename(
            defaultextension=ext_map[format_type],
            filetypes=filetypes_map[format_type],
            initialfile=default_filename + ext_map[format_type],
            title=f"Export Large Files as {format_type.upper()}"
        )

        if not filename:
            return

        try:
            data = [(os.path.getsize(fp) if os.path.exists(fp) else 0, fp) for _, fp in self.all_large_files]

            if format_type == 'csv':
                export_large_files_csv(filename, data, self.app.analyzer.format_size)
            elif format_type == 'json':
                export_large_files_json(filename, data, self.app.analyzer.format_size)
            else:
                export_large_files_txt(filename, data, self.app.analyzer.format_size)

            self.app.log("SUCCESS", f"Exported {len(data)} large files to {filename}")
            messagebox.showinfo("Export Complete", f"Successfully exported {len(data)} files to:\n{filename}")
        except Exception as e:
            self.app.log("ERROR", f"Export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.selected_files.clear()
        self.all_large_files.clear()
        self.filter_var.set('All Files')
        self.category_summary_var.set("")
