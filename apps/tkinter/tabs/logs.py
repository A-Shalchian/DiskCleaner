import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from datetime import datetime


class LogsTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = ttk.Frame(parent)
        self.all_logs = []

        self.setup_ui()

    def setup_ui(self):
        control_frame = ttk.Frame(self.frame)
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))

        ttk.Button(control_frame, text="Clear Logs", command=self.clear).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="Copy to Clipboard", command=self.copy).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="Save Logs", command=self.save).pack(side=tk.LEFT)

        ttk.Label(control_frame, text="    Filter:").pack(side=tk.LEFT, padx=(20, 5))
        self.filter_var = tk.StringVar(value='All')
        filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var,
                                    values=['All', 'INFO', 'WARNING', 'ERROR', 'DEBUG', 'SUCCESS'],
                                    width=10, state='readonly')
        filter_combo.pack(side=tk.LEFT)
        filter_combo.bind('<<ComboboxSelected>>', self.filter_logs)

        self.text = scrolledtext.ScrolledText(self.frame, height=20, width=100,
                                               font=('Consolas', 9), state=tk.DISABLED)
        self.text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(1, weight=1)

        self.text.tag_configure('INFO', foreground='black')
        self.text.tag_configure('WARNING', foreground='orange')
        self.text.tag_configure('ERROR', foreground='red')
        self.text.tag_configure('DEBUG', foreground='gray')
        self.text.tag_configure('SUCCESS', foreground='green')

    def log(self, level: str, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"

        self.all_logs.append((level, log_entry))

        current_filter = self.filter_var.get()
        if current_filter == 'All' or current_filter == level:
            self._append_log(level, log_entry)

    def _append_log(self, level: str, log_entry: str):
        self.text.config(state=tk.NORMAL)
        self.text.insert(tk.END, log_entry + "\n", level)
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)

    def clear(self):
        self.text.config(state=tk.NORMAL)
        self.text.delete(1.0, tk.END)
        self.text.config(state=tk.DISABLED)
        self.all_logs.clear()

    def copy(self):
        self.frame.clipboard_clear()
        logs_content = "\n".join(entry for _, entry in self.all_logs)
        self.frame.clipboard_append(logs_content)
        self.log("INFO", "Logs copied to clipboard")

    def save(self):
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
        current_filter = self.filter_var.get()

        self.text.config(state=tk.NORMAL)
        self.text.delete(1.0, tk.END)

        for level, entry in self.all_logs:
            if current_filter == 'All' or current_filter == level:
                self.text.insert(tk.END, entry + "\n", level)

        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)
