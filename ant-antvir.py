#!/usr/bin/env python3
# Ant-Anti Virus - Monitor (Tkinter)
# Process-based heuristic monitor with progress bar + status text + folder rules
# Requires: pip install psutil

import os
import subprocess
import sys
import re
import threading
import queue
from pathlib import Path
from typing import List, Tuple

# --- Tkinter imports ---
try:
    import tkinter as tk
    from tkinter import messagebox
    from tkinter import N, S, E, W, END
    from tkinter import ttk
except Exception as e:
    print("Tkinter is required to run this program.", file=sys.stderr)
    raise

# --- psutil import with friendly fallback ---
try:
    import psutil
except ImportError:
    root = tk.Tk(); root.withdraw()
    messagebox.showerror(
        "Missing dependency",
        "psutil is not installed.\n\nActivate your venv, then run:\n\npip install psutil"
    )
    sys.exit(1)

# ===================== Heuristics config =====================

POSITIVE_KEYWORDS = [
    "service", "windows", "microsoft",
    "spam", "virus", "torrent", "opera", "gx", "universal", "cyber",
    "happy", "avast", "coke", "system", "drone", "hack", "mail"
]
NEGATIVE_KEYWORDS = [
    "chrome", "edge", "explorer", "system", "svchost", "teams", "discord",
    "steam", "vscode", "idea", "blender", "photoshop", "OVR", "meta", "NVIDIA", "java", "gpt", "open",
    "idle", "wsl", "media", "linux", "calculator"
]

# NEW: folder-based rules (paths are matched by prefix, case-insensitive on Windows)
# +2 points for POSITIVE folders, -2 points for NEGATIVE folders
FOLDER_POSITIVE = [
    # Example: r"C:\Users\You\Downloads",
    # Example: r"C:\Users\You\AppData\Local\Temp",
]
FOLDER_NEGATIVE = [
    r"C:\Windows\System32",   # requested
    r"C:\Windows\SysWOW64",   # common 32-bit system dir on 64-bit Windows
]

THRESHOLDS = [
    (90, 8),
    (75, 5),
    (50, 2),
    (35, 1),
]

CATS = [
    (10, "VERY DANGEROUS"),
    (7,  "Dangerous"),
    (4,  "Caution"),
    (2,  "Maybe"),
]

PMON_LINE = re.compile(r"^\s*(\d+)\s+([\w.\\-]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")

# ===================== Path helpers =====================

def _norm(p: str) -> str:
    if not p:
        return ""
    try:
        p = os.path.expandvars(os.path.expanduser(p))
    except Exception:
        pass
    return Path(os.path.normcase(os.path.normpath(p))).as_posix()

def _ensure_slash(p: str) -> str:
    if not p:
        return p
    return p if p.endswith("/") else p + "/"

NORM_FOLDER_POS = [_ensure_slash(_norm(p)) for p in FOLDER_POSITIVE if p]
NORM_FOLDER_NEG = [_ensure_slash(_norm(p)) for p in FOLDER_NEGATIVE if p]

# ===================== GPU helper =====================

def get_gpu_util_by_pid() -> dict[int, int]:
    """
    Return dict {pid:int -> sm_util:int} using `nvidia-smi pmon -c 1`.
    If unavailable or fails, return {} and we count GPU as 0.
    """
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "pmon", "-c", "1"], stderr=subprocess.STDOUT, text=True, timeout=2
        )
    except Exception:
        return {}
    util: dict[int, int] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', 'idx')):
            continue
        m = PMON_LINE.match(line)
        if not m:
            parts = line.split()
            if len(parts) >= 6:
                try:
                    pid = int(parts[1])
                    sm = int(parts[3])  # heuristic position
                    util[pid] = max(util.get(pid, 0), sm)
                except Exception:
                    pass
            continue
        pid = int(m.group(2))
        sm = int(m.group(4))
        util[pid] = max(util.get(pid, 0), sm)
    return util

# ===================== Scoring helpers =====================

def tier_points(percent: float) -> int:
    for thr, pts in THRESHOLDS:
        if percent >= thr:
            return pts
    return 0

def keyword_points(name: str) -> int:
    n = name.lower()
    score = 0
    if any(k.lower() in n for k in POSITIVE_KEYWORDS):
        score += 2
    if any(k.lower() in n for k in NEGATIVE_KEYWORDS):
        score -= 2
    return score

def folder_points(path: str) -> int:
    if not path or path == "(unknown)":
        return 0
    p = _norm(path)
    for base in NORM_FOLDER_POS:
        if p.startswith(base):
            return 2
    for base in NORM_FOLDER_NEG:
        if p.startswith(base):
            return -2
    return 0

def category(score: int):
    for thr, label in CATS:
        if score >= thr:
            return label
    return None

# ===================== Scanning logic =====================

Row = Tuple[str, str, str, int]  # (name, path, label, score)

def collect_process_snapshot():
    """Snapshot of (pid, name, path) to build a determinate progress bar."""
    snapshot = []
    for p in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = p.info.get('name') or f"pid-{p.pid}"
            raw = p.info.get('exe')
            path = Path(raw).as_posix() if raw else "(unknown)"
            snapshot.append((p.pid, name, path))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    return snapshot

def scan_processes_with_snapshot(snapshot, progress_cb=None) -> List[Row]:
    """
    Scan using a fixed snapshot for progress. Returns rows with score >= 2.
    Hides items whose path is '(unknown)'.
    """
    for p in psutil.process_iter(['pid']):
        try:
            p.cpu_percent(None)
        except Exception:
            pass

    gpu_by_pid = get_gpu_util_by_pid()
    total = len(snapshot)
    rows: List[Row] = []

    for i, (pid, name, path) in enumerate(snapshot, start=1):
        if progress_cb:
            progress_cb(i, total, path or name)

        try:
            proc = psutil.Process(pid)
            cpu = proc.cpu_percent(interval=0.1)
            gpu = float(gpu_by_pid.get(pid, 0.0))
            score = tier_points(cpu) + tier_points(gpu) + keyword_points(name) + folder_points(path)

            if path == "(unknown)":
                continue

            if score >= 2:
                cat = category(score)
                if not cat:
                    continue
                label = f"{cat} ({score})"
                rows.append((name, path, label, score))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    rows.sort(key=lambda r: (-r[3], r[0].lower()))
    return rows

# ===================== Tk App =====================

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Ant-Anti Virus - Monitor")
        root.geometry('1100x620')

        # Status label
        self.status_var = tk.StringVar(value="Ready.")
        self.status = ttk.Label(root, textvariable=self.status_var, anchor='w')

        # Progress bar
        self.progress = ttk.Progressbar(root, orient='horizontal', mode='determinate')
        self.progress['value'] = 0
        self.progress['maximum'] = 100

        # Table
        self.tree = ttk.Treeview(root, columns=("name", "path", "danger"), show='headings')
        self.tree.heading("name", text="Name")
        self.tree.heading("path", text="Path")
        self.tree.heading("danger", text="Danger")
        self.tree.column("name", width=240, anchor='w')
        self.tree.column("path", width=700, anchor='w')
        self.tree.column("danger", width=140, anchor='center')

        vsb = ttk.Scrollbar(root, orient='vertical', command=self.tree.yview)
        hsb = ttk.Scrollbar(root, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        # Controls
        self.btn = ttk.Button(root, text="Scan", command=self.on_scan)

        # Menus
        self._build_menubar()

        # Grid
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)
        self.status.grid(row=0, column=0, columnspan=2, sticky=(E, W), padx=8, pady=(8, 4))
        self.progress.grid(row=1, column=0, columnspan=2, sticky=(E, W), padx=8, pady=(0, 8))
        self.tree.grid(row=2, column=0, sticky=(N, S, E, W), padx=(8, 0), pady=(0, 8))
        vsb.grid(row=2, column=1, sticky=(N, S), pady=(0, 8))
        hsb.grid(row=3, column=0, columnspan=2, sticky=(E, W), padx=8)
        self.btn.grid(row=4, column=0, sticky=(E,), padx=8, pady=8)

        # Row styling
        self.tree.tag_configure('very', background="#ff0000")
        self.tree.tag_configure('danger', background="#ff4d00")
        self.tree.tag_configure('caution', background="#ff9900")
        self.tree.tag_configure('maybe', background="#ffffff")

        # Context menu
        self._build_context_menu()
        self.tree.bind("<Button-3>", self._on_right_click)  # Windows/Linux right-click
        self.tree.bind("<Control-Button-1>", self._on_right_click)  # mac alt/ctrl click fallback

        # Thread comms
        self.q = queue.Queue()
        self.root.after(100, self._poll_queue)

        # Track running scan & last results
        self._scan_thread = None
        self._scanning = False
        self.last_rows: List[Row] = []
        self.item_data: dict[str, dict[str, any]] = {}  # iid -> dict(name,path,label,score)

    # ---------- Menus ----------

    def _build_menubar(self):
        menubar = tk.Menu(self.root)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Scan", command=self.on_scan)
        filem.add_separator()
        filem.add_command(label="Download Log (JSON)", command=self.save_log_json)
        filem.add_command(label="Download Log (TXT)", command=self.save_log_txt)
        filem.add_command(label="Download Log (LOG)", command=self.save_log_log)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filem)

        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="About", command=self.menu_about)
        helpm.add_command(label="How to Scan", command=self.menu_how_scan)
        helpm.add_command(label="How to Delete", command=self.menu_how_delete)
        helpm.add_separator()
        helpm.add_command(label="Get Source Code", command=self.menu_get_source)
        helpm.add_command(label="Copy Download Link", command=self.menu_copy_download_link)
        menubar.add_cascade(label="Help", menu=helpm)

        self.root.config(menu=menubar)

    # ---------- Context menu ----------

    def _build_context_menu(self):
        self.ctx = tk.Menu(self.root, tearoff=0)
        self.ctx.add_command(label="Copy as Path", command=self.ctx_copy_path)
        self.ctx.add_command(label="Reveal in Explorer", command=self.ctx_reveal)
        self.ctx.add_separator()
        self.ctx.add_command(label="Copy as JSON", command=self.ctx_copy_json)
        self.ctx.add_separator()
        self.ctx.add_command(label='Delete (Experimental)', command=self.ctx_delete_experimental)

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.ctx.post(event.x_root, event.y_root)

    # ---------- Progress helpers ----------

    def _set_progress_total(self, total: int):
        self.progress['maximum'] = max(1, total)
        self.progress['value'] = 0

    def _update_progress(self, i: int, total: int, current_path: str):
        self.progress['maximum'] = max(1, total)
        self.progress['value'] = min(i, total)
        display = current_path if current_path else "(unknown)"
        if len(display) > 120:
            display = "..." + display[-117:]
        self.status_var.set(f"SCAN: {display}")

    # ---------- Actions ----------

    def on_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self.btn.config(state='disabled', text='Scanning…')
        self.status_var.set("Preparing scan …")
        # Clear table
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.item_data.clear()

        snapshot = collect_process_snapshot()
        self._set_progress_total(len(snapshot))

        self._scan_thread = threading.Thread(
            target=self._worker_scan, args=(snapshot,), daemon=True
        )
        self._scan_thread.start()

    def _worker_scan(self, snapshot):
        def progress_cb(i, total, current_path):
            self.q.put(("progress", i, total, current_path))
        rows = scan_processes_with_snapshot(snapshot, progress_cb)
        self.q.put(("done", rows))

    def _populate(self, rows: List[Row]):
        self.last_rows = rows[:]  # keep a copy for logging
        for name, path, label, score in rows:
            tag = 'maybe'
            if score >= 10:
                tag = 'very'
            elif score >= 7:
                tag = 'danger'
            elif score >= 4:
                tag = 'caution'
            iid = self.tree.insert('', END, values=(name, path, label), tags=(tag,))
            self.item_data[iid] = {"name": name, "path": path, "label": label, "score": score}

    def _poll_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, i, total, current_path = msg
                    self._update_progress(i, total, current_path)
                elif kind == "done":
                    _, rows = msg
                    self._populate(rows)
                    self.status_var.set(f"Done. Found {len(rows)} item(s).")
                    self.progress['value'] = self.progress['maximum']
                    self.btn.config(state='normal', text='Scan')
                    self._scanning = False
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._poll_queue)

    # ---------- Menu handlers ----------

    def _ensure_results(self) -> bool:
        if not self.last_rows:
            messagebox.showinfo("No data", "No results yet. Run Scan first.")
            return False
        return True

    def save_log_json(self):
        if not self._ensure_results(): return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")],
                                            title="Save Log as JSON")
        if not path: return
        payload = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "rows": [{"name": n, "path": p, "danger": l, "score": s} for (n, p, l, s) in self.last_rows]
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            self.status_var.set(f"Saved JSON log: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save JSON: {e}")

    def save_log_txt(self):
        if not self._ensure_results(): return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text", "*.txt")],
                                            title="Save Log as TXT")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Ant-Anti Monitor Log @ {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                for (n, p, l, s) in self.last_rows:
                    f.write(f"{l:>13} | {s:2d} | {n} | {p}\n")
            self.status_var.set(f"Saved TXT log: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save TXT: {e}")

    def save_log_log(self):
        if not self._ensure_results(): return
        path = filedialog.asksaveasfilename(defaultextension=".log",
                                            filetypes=[("Log", "*.log")],
                                            title="Save Log as LOG")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for (n, p, l, s) in self.last_rows:
                    f.write(f"[{l}] {n} ({s}) :: {p}\n")
            self.status_var.set(f"Saved LOG: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save LOG: {e}")

    def menu_about(self):
        messagebox.showinfo(
            "About",
            "Ant-Anti Virus Monitor\n"
            "Heuristic process monitor (educational).\n"
            "Scores CPU/GPU usage + keywords + folders.\n"
            "Not a real antivirus. Use carefully."
        )

    def menu_how_scan(self):
        messagebox.showinfo(
            "How to Scan",
            "Click 'Scan'. The bar shows progress and the status line shows the current process path.\n"
            "Only items with score ≥ 2 are listed."
        )

    def menu_how_delete(self):
        messagebox.showinfo(
            "How to Delete",
            "Right-click a row → 'Delete (Experimental)'.\n"
            "A confirm window appears with a text field prefilled with 'rem PATH'.\n"
            "Type exactly the shown text to enable the Delete button.\n"
            "This permanently deletes the file path shown. Requires appropriate permissions."
        )

    def menu_get_source(self):
        script = Path(sys.argv[0]).resolve()
        messagebox.showinfo(
            "Get Source Code",
            f"This program is a single Python file:\n{script}\n\n"
            "Open it in your editor to view/modify the source."
        )

    def menu_copy_download_link(self):
        # Copy a file:// URL to this script to clipboard (local 'download link')
        script = Path(sys.argv[0]).resolve().as_uri()
        self._copy_to_clipboard(script)
        self.status_var.set("Copied download link to clipboard.")

    # ---------- Context actions ----------

    def _get_selected_row(self) -> dict[str, any] | None:
        sel = self.tree.selection()
        if not sel:
            return None
        iid = sel[0]
        return self.item_data.get(iid)

    def _copy_to_clipboard(self, text: str):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()  # keep on clipboard after app closes
        except Exception:
            pass

    def ctx_copy_path(self):
        row = self._get_selected_row()
        if not row:
            return
        self._copy_to_clipboard(row["path"])
        self.status_var.set("Path copied to clipboard.")

    def ctx_reveal(self):
        row = self._get_selected_row()
        if not row:
            return
        path = row["path"]
        if not path or not os.path.exists(path):
            messagebox.showwarning("Reveal", "Path not found on disk.")
            return
        try:
            if os.name == "nt":
                subprocess.Popen(["explorer", "/select,", path])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            else:
                # Best-effort: open containing folder
                folder = os.path.dirname(path) or "."
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            messagebox.showerror("Reveal", f"Failed to reveal: {e}")

    def ctx_copy_json(self):
        row = self._get_selected_row()
        if not row:
            return
        payload = json.dumps(row, indent=2)
        self._copy_to_clipboard(payload)
        self.status_var.set("Row JSON copied to clipboard.")

    def ctx_delete_experimental(self):
        row = self._get_selected_row()
        if not row:
            return
        path = row["path"]
        if not path or not os.path.exists(path):
            messagebox.showwarning("Delete", "Path not found on disk.")
            return
        ConfirmDelete(self.root, path, self._do_delete)

    def _do_delete(self, path: str):
        try:
            # Attempt to terminate any process using this path first (best-effort)
            for p in psutil.process_iter(['pid', 'exe']):
                try:
                    if p.info.get('exe') and os.path.samefile(p.info['exe'], path):
                        p.terminate()
                except Exception:
                    continue
            time.sleep(0.2)
            # Delete the file (PERMANENT). No recycle bin.
            os.remove(path)
            self.status_var.set(f"Deleted: {path}")
        except PermissionError:
            messagebox.showerror("Delete", "Permission denied. Try running as Admin.")
        except FileNotFoundError:
            messagebox.showinfo("Delete", "File already removed.")
        except IsADirectoryError:
            messagebox.showerror("Delete", "Path is a directory; deletion aborted.")
        except Exception as e:
            messagebox.showerror("Delete", f"Failed to delete: {e}")

    # ---------- End App ----------


class ConfirmDelete(tk.Toplevel):
    """
    Small confirm window. Shows text prompt with 'rem PATH'.
    User must type exactly the shown text to enable Delete.
    """
    def __init__(self, master: tk.Misc, path: str, on_confirm):
        super().__init__(master)
        self.title("Confirm Delete (Experimental)")
        self.resizable(False, False)
        self.path = path
        self.on_confirm = on_confirm
        self.prompt = f"rem {path}"

        ttk.Label(self, text="Type the line below EXACTLY to confirm permanent deletion:", wraplength=500).grid(
            row=0, column=0, columnspan=2, padx=10, pady=(10, 6), sticky=W
        )
        prompt_box = tk.Text(self, height=2, width=70)
        prompt_box.insert("1.0", self.prompt)
        prompt_box.configure(state="disabled")
        prompt_box.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 6), sticky=(W, E))

        ttk.Label(self, text="Your input:").grid(row=2, column=0, padx=10, pady=(0, 6), sticky=W)
        self.var = tk.StringVar()
        entry = ttk.Entry(self, textvariable=self.var, width=68)
        entry.grid(row=2, column=1, padx=10, pady=(0, 6), sticky=(W, E))
        entry.focus_set()

        self.btn_delete = ttk.Button(self, text="Delete", command=self._confirm, state="disabled")
        self.btn_cancel = ttk.Button(self, text="Cancel", command=self.destroy)
        self.btn_delete.grid(row=3, column=0, padx=10, pady=10, sticky=E)
        self.btn_cancel.grid(row=3, column=1, padx=10, pady=10, sticky=W)

        self.var.trace_add("write", self._on_change)

        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _on_change(self, *_):
        ok = self.var.get() == self.prompt
        self.btn_delete.config(state=("normal" if ok else "disabled"))

    def _confirm(self):
        if self.var.get() != self.prompt:
            return
        self.destroy()
        self.on_confirm(self.path)


# ===================== Main =====================

def main():
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == '__main__':
    main()