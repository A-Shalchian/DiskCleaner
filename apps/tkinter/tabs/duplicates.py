import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
from datetime import datetime

from core import delete_file, RECYCLE_BIN_AVAILABLE
from core import export_duplicates_csv, export_duplicates_json, export_duplicates_txt


class DuplicatesTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = ttk.Frame(parent)
        self.duplicate_data = {}
        self.selected_duplicates = set()

        self.setup_ui()

    def setup_ui(self):
        info_frame = ttk.Frame(self.frame)
        info_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        info_frame.columnconfigure(0, weight=1)

        self.info_label = ttk.Label(info_frame, text="No duplicates found yet")
        self.info_label.grid(row=0, column=0, sticky=tk.W)

        btn_frame = ttk.Frame(info_frame)
        btn_frame.grid(row=0, column=1, sticky=tk.E)

        ttk.Button(btn_frame, text="Select All", command=self.select_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Deselect All", command=self.deselect_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Refresh", command=self.app.refresh_duplicates, width=10).pack(side=tk.LEFT, padx=(5, 5))
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected, style='Danger.TButton', width=15).pack(side=tk.LEFT, padx=(5, 0))

        ttk.Separator(btn_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=(15, 10), fill=tk.Y)
        ttk.Label(btn_frame, text="Export:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="CSV", command=lambda: self.export('csv'), width=5).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(btn_frame, text="JSON", command=lambda: self.export('json'), width=5).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(btn_frame, text="TXT", command=lambda: self.export('txt'), width=5).pack(side=tk.LEFT)

        tree_frame = ttk.Frame(self.frame)
        tree_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        columns = ('Select', 'Group', 'Count', 'Size', 'Waste', 'Files')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=16)

        self.tree.heading('Select', text='☐')
        self.tree.heading('Group', text='Group')
        self.tree.heading('Count', text='Count')
        self.tree.heading('Size', text='Size')
        self.tree.heading('Waste', text='Waste')
        self.tree.heading('Files', text='Files')

        self.tree.column('Select', width=50, anchor='center')
        self.tree.column('Group', width=60)
        self.tree.column('Count', width=60)
        self.tree.column('Size', width=100)
        self.tree.column('Waste', width=100)
        self.tree.column('Files', width=670)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(1, weight=1)

        self.tree.bind('<Button-1>', self.on_click)
        self.tree.bind('<Double-1>', self.on_double_click)

    def populate(self, duplicates):
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.selected_duplicates.clear()
        self.duplicate_data.clear()

        if not duplicates:
            self.info_label.config(text="No duplicate files found")
            return

        total_waste = self.app.analyzer.calculate_duplicate_waste(duplicates)
        self.info_label.config(text=f"Found {len(duplicates)} duplicate groups, potential savings: {self.app.analyzer.format_size(total_waste)}")

        duplicate_groups = []
        for file_hash, filepaths in duplicates.items():
            try:
                file_size = os.path.getsize(filepaths[0])
                waste = (len(filepaths) - 1) * file_size
                duplicate_groups.append((waste, file_size, filepaths))
            except OSError:
                continue

        duplicate_groups.sort(reverse=True)

        for i, (waste, file_size, filepaths) in enumerate(duplicate_groups[:50], 1):
            files_str = " | ".join(filepaths)
            item_id = self.tree.insert('', tk.END, values=(
                '☐',
                f"#{i}",
                len(filepaths),
                self.app.analyzer.format_size(file_size),
                self.app.analyzer.format_size(waste),
                files_str
            ))
            self.duplicate_data[item_id] = filepaths

    def on_click(self, event):
        region = self.tree.identify('region', event.x, event.y)
        if region == 'cell':
            column = self.tree.identify_column(event.x)
            item = self.tree.identify_row(event.y)
            if column == '#1' and item:
                self.toggle_selection(item)
                return 'break'

    def on_double_click(self, event):
        selection = self.tree.selection()
        if selection:
            self.open_file_locations(selection[0])

    def toggle_selection(self, item):
        values = list(self.tree.item(item)['values'])
        if item in self.selected_duplicates:
            self.selected_duplicates.remove(item)
            values[0] = '☐'
        else:
            self.selected_duplicates.add(item)
            values[0] = '☑'
        self.tree.item(item, values=values)

    def select_all(self):
        for item in self.tree.get_children():
            if item not in self.selected_duplicates:
                self.selected_duplicates.add(item)
                values = list(self.tree.item(item)['values'])
                values[0] = '☑'
                self.tree.item(item, values=values)

    def deselect_all(self):
        for item in self.tree.get_children():
            if item in self.selected_duplicates:
                self.selected_duplicates.remove(item)
                values = list(self.tree.item(item)['values'])
                values[0] = '☐'
                self.tree.item(item, values=values)

    def open_file_locations(self, item):
        filepaths = self.duplicate_data.get(item, [])
        for filepath in filepaths[:3]:
            try:
                subprocess.run(['explorer', '/select,', filepath], check=False)
            except Exception:
                pass

    def delete_selected(self):
        if not self.selected_duplicates:
            messagebox.showwarning("No Selection", "Please select duplicate groups to delete using the checkboxes")
            return

        use_recycle = self.app.use_recycle_bin.get()
        action = "Move to Recycle Bin" if (use_recycle and RECYCLE_BIN_AVAILABLE) else "Permanently delete"

        all_files_to_delete = []
        total_groups = len(self.selected_duplicates)

        for item in self.selected_duplicates:
            filepaths = self.duplicate_data.get(item, [])
            if len(filepaths) > 1:
                files_to_delete = filepaths[1:]
                all_files_to_delete.extend([(item, fp) for fp in files_to_delete])

        if not all_files_to_delete:
            messagebox.showinfo("No Files", "No duplicate files to delete")
            return

        message = f"{action} {len(all_files_to_delete)} duplicate files from {total_groups} groups?\n\n"
        message += "First 10 files to be deleted:\n"
        message += "\n".join(f"• {fp}" for _, fp in all_files_to_delete[:10])
        if len(all_files_to_delete) > 10:
            message += f"\n... and {len(all_files_to_delete) - 10} more files"

        if not messagebox.askyesno("Confirm Delete Duplicates", message):
            return

        deleted_count = 0
        errors = []
        deleted_items = set()

        for item, filepath in all_files_to_delete:
            success, error = delete_file(filepath, use_recycle)
            if success:
                deleted_count += 1
                deleted_items.add(item)
            else:
                errors.append(f"{filepath}: {error}")

        for item in deleted_items:
            self.tree.delete(item)
            if item in self.duplicate_data:
                del self.duplicate_data[item]

        self.selected_duplicates.clear()

        if deleted_count > 0:
            self.app.invalidate_cache()
            if use_recycle and RECYCLE_BIN_AVAILABLE:
                self.app.log("SUCCESS", f"Moved {deleted_count} duplicate files to Recycle Bin")
                msg = f"Moved {deleted_count} duplicate files to Recycle Bin from {len(deleted_items)} groups"
            else:
                self.app.log("SUCCESS", f"Permanently deleted {deleted_count} duplicate files")
                msg = f"Permanently deleted {deleted_count} duplicate files from {len(deleted_items)} groups"
            if errors:
                msg += f"\n\nErrors ({len(errors)}):\n" + "\n".join(errors[:5])
            messagebox.showinfo("Delete Complete", msg)

            if not errors:
                self.app.refresh_duplicates()
        else:
            messagebox.showerror("Delete Failed", "No files were deleted.\n\n" + "\n".join(errors[:10]))

    def export(self, format_type):
        if not self.duplicate_data:
            messagebox.showwarning("No Data", "No duplicates to export. Please run a scan first.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"duplicates_{timestamp}"

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
            title=f"Export Duplicates as {format_type.upper()}"
        )

        if not filename:
            return

        try:
            duplicates_dict = {str(i): paths for i, paths in enumerate(self.duplicate_data.values())}

            if format_type == 'csv':
                export_duplicates_csv(filename, duplicates_dict, self.app.analyzer.format_size)
            elif format_type == 'json':
                export_duplicates_json(filename, duplicates_dict, self.app.analyzer.format_size)
            else:
                export_duplicates_txt(filename, duplicates_dict, self.app.analyzer.format_size)

            num_groups = len(self.duplicate_data)
            self.app.log("SUCCESS", f"Exported {num_groups} duplicate groups to {filename}")
            messagebox.showinfo("Export Complete", f"Successfully exported {num_groups} duplicate groups to:\n{filename}")
        except Exception as e:
            self.app.log("ERROR", f"Export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.duplicate_data.clear()
        self.selected_duplicates.clear()
        self.info_label.config(text="No duplicates found yet")
