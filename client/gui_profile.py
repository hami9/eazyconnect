import os
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False


def get_config_path():
    appdata = os.environ.get("APPDATA")
    if appdata:
        cfg_dir = os.path.join(appdata, "eazyconnect")
        try:
            os.makedirs(cfg_dir, exist_ok=True)
        except Exception:
            pass
        return os.path.join(cfg_dir, "config.json")
    return os.path.join(os.path.dirname(__file__), "config.json")

CONFIG_PATH = get_config_path()


def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    local = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        if os.path.exists(local):
            with open(local, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            return
    except Exception:
        pass
    local = os.path.join(os.path.dirname(__file__), "config.json")
    with open(local, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


class ProfileGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EazyConnect — Profile")
        self.geometry("420x260")
        self.resizable(False, False)

        self.cfg = load_config()
        self.profile = self.cfg.get("profile", {})
        self.language = self.cfg.get("language", self.profile.get("language", "en"))

        self.create_widgets()
        self.load_values()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # Photo display
        self.photo_label = ttk.Label(frm, text="No image", width=18)
        self.photo_label.grid(row=0, column=0, rowspan=3, sticky="nw")

        btn_photo = ttk.Button(frm, text="Choose Photo", command=self.choose_photo)
        btn_photo.grid(row=3, column=0, sticky="nw", pady=(6,0))

        # Name
        ttk.Label(frm, text="Name:").grid(row=0, column=1, sticky="w")
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(frm, textvariable=self.name_var, width=38)
        self.name_entry.grid(row=0, column=2, columnspan=2, sticky="w")

        # Photo path
        ttk.Label(frm, text="Photo path:").grid(row=1, column=1, sticky="w")
        self.photo_var = tk.StringVar()
        self.photo_entry = ttk.Entry(frm, textvariable=self.photo_var, width=38)
        self.photo_entry.grid(row=1, column=2, columnspan=2, sticky="w")

        # Language
        ttk.Label(frm, text="Language:").grid(row=2, column=1, sticky="w")
        self.lang_var = tk.StringVar()
        self.lang_combo = ttk.Combobox(frm, textvariable=self.lang_var, values=("en","fa"), width=6)
        self.lang_combo.grid(row=2, column=2, sticky="w")

        # Save button
        btn_save = ttk.Button(frm, text="Save", command=self.save)
        btn_save.grid(row=4, column=2, sticky="e", pady=(12,0))
        btn_close = ttk.Button(frm, text="Close", command=self.destroy)
        btn_close.grid(row=4, column=3, sticky="w", padx=(6,0), pady=(12,0))

    def load_values(self):
        self.name_var.set(self.profile.get("name", ""))
        self.photo_var.set(self.profile.get("photo", ""))
        self.lang_var.set(self.language or "en")
        self._render_image(self.photo_var.get())

    def choose_photo(self):
        p = filedialog.askopenfilename(title="Select photo", filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp"), ("All files","*")])
        if p:
            self.photo_var.set(p)
            self._render_image(p)

    def _render_image(self, path):
        if not path or not os.path.exists(path):
            self.photo_label.config(text="No image", image="")
            return
        if PIL_AVAILABLE:
            try:
                img = Image.open(path)
                img.thumbnail((128,128))
                self.photo_tk = ImageTk.PhotoImage(img)
                self.photo_label.config(image=self.photo_tk, text="")
            except Exception as e:
                self.photo_label.config(text=f"Cannot load image\n{os.path.basename(path)}")
        else:
            # PIL not available — show filename only
            self.photo_label.config(text=os.path.basename(path), image="")

    def save(self):
        name = self.name_var.get().strip()
        photo = self.photo_var.get().strip()
        lang = self.lang_var.get().strip() or "en"
        if "profile" not in self.cfg:
            self.cfg["profile"] = {}
        self.cfg["profile"]["name"] = name
        self.cfg["profile"]["photo"] = photo
        self.cfg["profile"]["language"] = lang
        self.cfg["language"] = lang
        save_config(self.cfg)
        messagebox.showinfo("Saved", "Profile saved")


if __name__ == '__main__':
    app = ProfileGUI()
    app.mainloop()
