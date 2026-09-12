import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import io
import tempfile
import contextlib

from gui_profile import ProfileGUI
import client as client_core


class MainGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EazyConnect")
        self.geometry("720x460")

        self.create_widgets()

    def create_widgets(self):
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        # Profile tab: embed existing ProfileGUI in a toplevel-like frame
        frame_profile = ttk.Frame(nb)
        nb.add(frame_profile, text="Profile")
        btn_open_profile = ttk.Button(frame_profile, text="Open Profile Editor", command=self.open_profile)
        btn_open_profile.pack(padx=12, pady=12, anchor="nw")

        # Transfer tab
        frame_transfer = ttk.Frame(nb)
        nb.add(frame_transfer, text="Transfer")
        ttk.Label(frame_transfer, text="Discover peers and upload/download files").grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(12,6))
        ttk.Button(frame_transfer, text="Discover", command=self.do_discover).grid(row=1, column=0, padx=12, pady=6, sticky="w")
        self.discover_out = tk.Text(frame_transfer, height=6, width=60)
        self.discover_out.grid(row=2, column=0, columnspan=3, padx=12, pady=(0,12))

        ttk.Button(frame_transfer, text="Choose file to upload", command=self.choose_file).grid(row=3, column=0, padx=12, pady=6, sticky="w")
        self.upload_path_var = tk.StringVar()
        ttk.Entry(frame_transfer, textvariable=self.upload_path_var, width=48).grid(row=3, column=1, padx=6, pady=6)
        ttk.Button(frame_transfer, text="Upload", command=self.upload_file).grid(row=3, column=2, padx=12, pady=6)

        ttk.Label(frame_transfer, text="Download (owner/filename):").grid(row=4, column=0, padx=12, pady=6, sticky="w")
        self.down_owner = tk.StringVar()
        self.down_file = tk.StringVar()
        ttk.Entry(frame_transfer, textvariable=self.down_owner, width=18).grid(row=4, column=1, sticky="w", padx=(6,0))
        ttk.Entry(frame_transfer, textvariable=self.down_file, width=20).grid(row=4, column=1, sticky="e", padx=(0,6))
        ttk.Button(frame_transfer, text="Download to...", command=self.download_file).grid(row=4, column=2, padx=12, pady=6)

        # Messages tab (placeholder)
        frame_messages = ttk.Frame(nb)
        nb.add(frame_messages, text="Messages")
        ttk.Label(frame_messages, text="Send instant messages - coming soon").pack(padx=12, pady=12)

        # Config tab
        frame_config = ttk.Frame(nb)
        nb.add(frame_config, text="Config")
        ttk.Label(frame_config, text="Edit config files and settings").pack(padx=12, pady=12)

        # Diagnostics tab
        frame_diag = ttk.Frame(nb)
        nb.add(frame_diag, text="Diagnostics")
        ttk.Button(frame_diag, text="Run Diagnostics", command=self.run_diag).pack(padx=12, pady=12, anchor="nw")
        self.diag_out = tk.Text(frame_diag, height=12)
        self.diag_out.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0,12))

        # Git tab
        frame_git = ttk.Frame(nb)
        nb.add(frame_git, text="Git")
        ttk.Label(frame_git, text="Commit / Push local repo").grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(12,6))
        ttk.Label(frame_git, text="Repo path (relative to client):").grid(row=1, column=0, sticky="w", padx=12)
        self.git_repo = tk.StringVar(value="..")
        ttk.Entry(frame_git, textvariable=self.git_repo, width=40).grid(row=1, column=1, padx=6, pady=6)
        ttk.Label(frame_git, text="Commit message:").grid(row=2, column=0, sticky="w", padx=12)
        self.git_msg = tk.StringVar(value="Auto commit from client")
        ttk.Entry(frame_git, textvariable=self.git_msg, width=40).grid(row=2, column=1, padx=6, pady=6)
        ttk.Button(frame_git, text="Push", command=self.git_push).grid(row=3, column=1, sticky="e", padx=12, pady=6)
        self.git_out = tk.Text(frame_git, height=8)
        self.git_out.grid(row=4, column=0, columnspan=3, padx=12, pady=(6,12), sticky="nsew")

        frame_git.rowconfigure(4, weight=1)

    def open_profile(self):
        # Launch the profile editor as a separate window
        ProfileGUI().mainloop()

    def run_diag(self):
        self.diag_out.delete("1.0", tk.END)
        self.diag_out.insert(tk.END, "Running diagnostics...\n")
        def work():
            try:
                # Prefer client.diagnose which writes a report file; capture that
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.close()
                client_core.diagnose(output_path=tmp.name)
                with open(tmp.name, "r", encoding="utf-8") as f:
                    out = f.read()
            except Exception as e:
                out = f"Diagnostics failed: {e}"
            self.diag_out.insert(tk.END, out + "\n")
        threading.Thread(target=work, daemon=True).start()

    # --- Transfer helpers ------------------------------------------------
    def do_discover(self):
        self.discover_out.delete("1.0", tk.END)
        self.discover_out.insert(tk.END, "Discovering...\n")
        def work():
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    client_core.discover(timeout=3)
                out = buf.getvalue()
            except Exception as e:
                out = f"Discovery failed: {e}\n"
            self.discover_out.insert(tk.END, out)
        threading.Thread(target=work, daemon=True).start()

    def choose_file(self):
        p = filedialog.askopenfilename(title="Select file to upload")
        if p:
            self.upload_path_var.set(p)

    def upload_file(self):
        p = self.upload_path_var.get().strip()
        if not p or not os.path.exists(p):
            messagebox.showwarning("No file", "Please choose a valid file to upload.")
            return
        def work():
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    client_core.upload(p)
                out = buf.getvalue()
            except Exception as e:
                out = f"Upload failed: {e}\n"
            messagebox.showinfo("Upload", out or "Upload finished")
        threading.Thread(target=work, daemon=True).start()

    def download_file(self):
        owner = self.down_owner.get().strip()
        fname = self.down_file.get().strip()
        if not owner or not fname:
            messagebox.showwarning("Missing", "Provide owner and filename to download")
            return
        dest = filedialog.asksaveasfilename(title="Save downloaded file as", initialfile=fname)
        if not dest:
            return
        def work():
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    client_core.download(owner, fname, dest)
                out = buf.getvalue()
            except Exception as e:
                out = f"Download failed: {e}\n"
            messagebox.showinfo("Download", out or "Download finished")
        threading.Thread(target=work, daemon=True).start()

    # --- Git helpers -----------------------------------------------------
    def git_push(self):
        repo = self.git_repo.get().strip() or ".."
        msg = self.git_msg.get().strip() or "Auto commit from client"
        self.git_out.delete("1.0", tk.END)
        self.git_out.insert(tk.END, "Running git push...\n")
        def work():
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    client_core.git_push(repo_path=repo, message=msg)
                out = buf.getvalue()
            except Exception as e:
                out = f"Git push failed: {e}\n"
            self.git_out.insert(tk.END, out)
        threading.Thread(target=work, daemon=True).start()


def main():
    app = MainGUI()
    app.mainloop()


if __name__ == '__main__':
    main()
