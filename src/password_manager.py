#!/usr/bin/env python3
"""
Password Manager — Single-File App
====================================
All screens and backend logic in one file.

Run with:
    python password_manager_app.py

Dependencies:
    pip install customtkinter cryptography
"""

# ══════════════════════════════════════════════════════════════════════════════
# Imports
# ══════════════════════════════════════════════════════════════════════════════

import os
import json
import base64
import secrets
import string
import sys
import webbrowser

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Missing dependency. Install with:  pip install cryptography")
    sys.exit(1)

try:
    import customtkinter as ctk
    from tkinter import messagebox
except ImportError:
    print("Missing dependency. Install with:  pip install customtkinter")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# Config
# ══════════════════════════════════════════════════════════════════════════════

APP_DIR = os.path.join(os.path.expanduser("~"), ".password_manager")
LEGACY_VAULT_FILE = os.path.join("data", "vault.enc")
VAULT_FILE = os.path.join(APP_DIR, "vault.enc")
ITERATIONS = 480_000
SYMBOLS    = "!@#$%^&*()_+-=[]{}|;:,.<>?"


# ══════════════════════════════════════════════════════════════════════════════
# Design tokens
# ══════════════════════════════════════════════════════════════════════════════

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# Palette
BLUE        = "#4A90D9"
BLUE_DARK   = "#3A7BC8"
BLUE_LIGHT  = "#EBF3FC"
WHITE       = "#FFFFFF"
OFF_WHITE   = "#F7F9FC"
LIGHT_GREY  = "#EEF1F5"
MID_GREY    = "#A0AABB"
DARK_TEXT   = "#1C2333"
DIVIDER     = "#E3E8EF"
ROW_HOVER   = "#EBF3FC"
GREEN       = "#34C759"
GREEN_DIM   = "#D4F5DF"
RED_HOVER   = "#FFE5E5"

# Typography
FONT_FAMILY   = "Inter"
FONT_FALLBACK = "Helvetica"

FONT_HERO      = (FONT_FAMILY, 30, "bold")
FONT_TITLE     = (FONT_FAMILY, 24, "bold")
FONT_TITLE_SM  = (FONT_FAMILY, 19, "bold")
FONT_SECTION   = (FONT_FAMILY, 12, "bold")
FONT_BODY      = (FONT_FAMILY, 15)
FONT_BODY_SM   = (FONT_FAMILY, 12)
FONT_LABEL     = (FONT_FAMILY, 13, "bold")
FONT_FIELD     = (FONT_FAMILY, 15)
FONT_BTN       = (FONT_FAMILY, 14, "bold")
FONT_BTN_LG    = (FONT_FAMILY, 16, "bold")
FONT_MONO      = ("Courier New", 14, "bold")
FONT_ICON_LG   = (FONT_FAMILY, 42, "bold")
FONT_NUMERIC   = (FONT_FAMILY, 12, "bold")


# ══════════════════════════════════════════════════════════════════════════════
# Backend
# ══════════════════════════════════════════════════════════════════════════════

def ensure_storage_ready() -> None:
    os.makedirs(APP_DIR, exist_ok=True)


def migrate_legacy_vault_if_needed() -> None:
    if os.path.exists(VAULT_FILE):
        return
    if os.path.exists(LEGACY_VAULT_FILE):
        ensure_storage_ready()
        try:
            with open(LEGACY_VAULT_FILE, "rb") as src, open(VAULT_FILE, "wb") as dst:
                dst.write(src.read())
        except OSError:
            pass


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def load_vault(master_password: str) -> dict:
    migrate_legacy_vault_if_needed()
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    salt, token = data[:16], data[16:]
    key = derive_key(master_password, salt)
    try:
        return json.loads(Fernet(key).decrypt(token))
    except Exception:
        raise ValueError("Wrong master password or corrupted vault.")


def save_vault(master_password: str, vault: dict, salt: bytes) -> None:
    ensure_storage_ready()
    key   = derive_key(master_password, salt)
    token = Fernet(key).encrypt(json.dumps(vault).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + token)


def get_vault_salt() -> bytes:
    migrate_legacy_vault_if_needed()
    with open(VAULT_FILE, "rb") as f:
        return f.read()[:16]


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in string.punctuation for c in pwd)):
            return pwd


def normalize_website_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def open_website(url: str) -> bool:
    normalized = normalize_website_url(url)
    if not normalized:
        return False
    return webbrowser.open(normalized)


# ══════════════════════════════════════════════════════════════════════════════
# Shared UI helpers
# ══════════════════════════════════════════════════════════════════════════════

def make_section_label(parent, text: str, pady=(16, 4), padx=20):
    ctk.CTkLabel(
        parent, text=text,
        font=FONT_SECTION, text_color=MID_GREY,
        fg_color="transparent", anchor="w",
    ).pack(fill="x", padx=padx, pady=pady)


def make_soft_card(parent, *, fg_color=WHITE, corner_radius=18, **kwargs):
    return ctk.CTkFrame(parent, fg_color=fg_color, corner_radius=corner_radius, **kwargs)


def make_modern_entry(parent, variable=None, *, placeholder="", height=46,
                      show=None, state="normal"):
    return ctk.CTkEntry(
        parent,
        textvariable=variable,
        placeholder_text=placeholder,
        fg_color=LIGHT_GREY,
        text_color=DARK_TEXT,
        border_width=0,
        corner_radius=12,
        height=height,
        font=FONT_FIELD,
        show=show,
        state=state,
    )


def center_window(window, width: int, height: int):
    window.update_idletasks()
    sw = window.winfo_screenwidth()
    sh = window.winfo_screenheight()
    x = max((sw - width) // 2, 0)
    y = max((sh - height) // 2, 0)
    window.geometry(f"{width}x{height}+{x}+{y}")


def center_to_parent(window, parent, width: int, height: int):
    window.update_idletasks()
    parent.update_idletasks()
    try:
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
    except Exception:
        center_window(window, width, height)
        return

    if pw <= 1 or ph <= 1:
        center_window(window, width, height)
        return

    x = max(px + (pw - width) // 2, 0)
    y = max(py + max((ph - height) // 2, 24), 0)
    window.geometry(f"{width}x{height}+{x}+{y}")

def bring_to_front(window):
    """Keep dialogs on top of their parent briefly so they don't appear behind."""
    try:
        window.lift()
        window.focus_force()
        window.attributes("-topmost", True)
        window.after(250, lambda: window.attributes("-topmost", False))
    except Exception:
        pass


def ask_yes_no(title: str, message: str, parent=None) -> bool:
    return messagebox.askyesno(title, message, parent=parent)


def show_error(title: str, message: str, parent=None):
    return messagebox.showerror(title, message, parent=parent)


def show_info(title: str, message: str, parent=None):
    return messagebox.showinfo(title, message, parent=parent)



# ══════════════════════════════════════════════════════════════════════════════
# Screen 3 — Entry Detail
# ══════════════════════════════════════════════════════════════════════════════

class EntryDetailScreen(ctk.CTkToplevel):
    def __init__(self, parent, entry_name: str, entry_data: dict, on_back=None):
        super().__init__(parent)
        self.entry_name = entry_name
        self.entry_data = entry_data
        self.on_back    = on_back
        self.show_pw    = False

        self.title("Password Manager")
        self.resizable(True, True)
        self.geometry("560x660")
        self.transient(parent)
        center_to_parent(self, parent, 560, 660)
        self._build()
        self.after(20, lambda: bring_to_front(self))

    def _build(self):
        bg = ctk.CTkFrame(self, fg_color=BLUE, corner_radius=0)
        bg.pack(fill="both", expand=True)

        # Nav bar
        nav = ctk.CTkFrame(bg, fg_color="transparent")
        nav.pack(fill="x", padx=16, pady=(16, 0))
        ctk.CTkButton(
            nav, text="← Back",
            width=88, height=34, corner_radius=8,
            fg_color=BLUE_DARK, hover_color="#2e6ab0",
            text_color=WHITE, font=FONT_BTN,
            command=self._on_back,
        ).pack(side="left")

        # Hero
        ctk.CTkLabel(bg, text="Vault Entry", font=FONT_TITLE_SM, text_color="#D9E8F7", fg_color="transparent").pack(pady=(18, 0))
        ctk.CTkLabel(
            bg, text=self.entry_name,
            font=FONT_HERO, text_color=WHITE, fg_color="transparent",
        ).pack()
        ctk.CTkLabel(
            bg, text=self.entry_data.get("username", ""),
            font=FONT_BODY, text_color="#C8DDEE", fg_color="transparent",
        ).pack(pady=(2, 16))

        # White card
        card = ctk.CTkFrame(bg, fg_color=WHITE, corner_radius=20)
        card.pack(fill="x", padx=20, pady=(0, 12))

        website = self.entry_data.get("website", "")
        if website:
            self._link_field(card, "WEBSITE", website, button_text="Open Website")
        self._ro_field(card, "ACCOUNT", self.entry_name)
        self._ro_field(card, "USERNAME", self.entry_data.get("username", ""))

        # Password row
        make_section_label(card, "PASSWORD", pady=(10, 0))
        pw_wrap = ctk.CTkFrame(card, fg_color="transparent")
        pw_wrap.pack(fill="x", padx=20, pady=(4, 2))

        self.pw_var   = ctk.StringVar(value=self.entry_data.get("password", ""))
        self.pw_field = ctk.CTkEntry(
            pw_wrap,
            textvariable=self.pw_var,
            fg_color=LIGHT_GREY, text_color=DARK_TEXT,
            border_width=0, corner_radius=10, height=42,
            font=FONT_FIELD, show="•", state="readonly",
        )
        self.pw_field.pack(side="left", fill="x", expand=True)

        self.toggle_pw_btn = ctk.CTkButton(
            pw_wrap, text="Show", width=74, height=42, corner_radius=10,
            fg_color=WHITE, hover_color=BLUE_LIGHT, text_color=BLUE,
            border_width=1, border_color=DIVIDER,
            font=FONT_BTN, command=self._toggle_pw,
        )
        self.toggle_pw_btn.pack(side="left", padx=(8, 0))

        notes = self.entry_data.get("notes", "")
        if notes:
            self._ro_field(card, "NOTES", notes)

        ctk.CTkFrame(card, fg_color="transparent", height=12).pack()

        actions = ctk.CTkFrame(bg, fg_color="transparent")
        actions.pack(fill="x", padx=20, pady=(0, 8))
        self.copy_user_btn = ctk.CTkButton(
            actions, text="Copy Username",
            height=48, corner_radius=14,
            fg_color=WHITE, hover_color=LIGHT_GREY,
            text_color=BLUE, font=FONT_BTN,
            command=self._copy_username,
        )
        self.copy_user_btn.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.copy_btn = ctk.CTkButton(
            actions, text="Copy Password",
            height=48, corner_radius=14,
            fg_color=WHITE, hover_color=LIGHT_GREY,
            text_color=BLUE, font=FONT_BTN,
            command=self._copy_password,
        )
        self.copy_btn.pack(side="left", fill="x", expand=True)

    def _ro_field(self, parent, label: str, value: str):
        make_section_label(parent, label, pady=(10, 0))
        ctk.CTkEntry(
            parent,
            textvariable=ctk.StringVar(value=value),
            fg_color=LIGHT_GREY, border_width=0,
            corner_radius=10, height=42,
            font=FONT_FIELD, state="readonly",
        ).pack(fill="x", padx=20, pady=(4, 0))

    def _link_field(self, parent, label: str, value: str, button_text: str = "Open"):
        make_section_label(parent, label, pady=(10, 0))
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(4, 0))
        ctk.CTkEntry(
            row,
            textvariable=ctk.StringVar(value=value),
            fg_color=LIGHT_GREY, border_width=0,
            corner_radius=10, height=42,
            font=FONT_FIELD, state="readonly",
        ).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(
            row, text=button_text, width=108, height=42, corner_radius=10,
            fg_color=WHITE, hover_color=BLUE_LIGHT, text_color=BLUE,
            border_width=1, border_color=DIVIDER, font=FONT_BTN,
            command=lambda: open_website(value),
        ).pack(side="left", padx=(8, 0))

    def _toggle_pw(self):
        self.show_pw = not self.show_pw
        self.pw_field.configure(show="" if self.show_pw else "•")
        self.toggle_pw_btn.configure(text="Hide" if self.show_pw else "Show")

    def _copy_username(self):
        self.clipboard_clear()
        self.clipboard_append(self.entry_data.get("username", ""))
        self.update()
        self.copy_user_btn.configure(text="Copied", fg_color=GREEN_DIM, text_color=GREEN)
        self.after(1800, lambda: self.copy_user_btn.configure(
            text="Copy Username", fg_color=WHITE, text_color=BLUE))

    def _copy_password(self):
        self.clipboard_clear()
        self.clipboard_append(self.entry_data.get("password", ""))
        self.update()
        self.copy_btn.configure(text="Copied", fg_color=GREEN_DIM, text_color=GREEN)
        self.after(1800, lambda: self.copy_btn.configure(
            text="Copy Password", fg_color=WHITE, text_color=BLUE))

    def _on_back(self):
        self.destroy()
        if self.on_back:
            self.on_back()


# ══════════════════════════════════════════════════════════════════════════════
# Screen 2b — Add / Edit Dialog
# ══════════════════════════════════════════════════════════════════════════════

class AddEntryDialog(ctk.CTkToplevel):
    def __init__(self, parent, on_save, entry_name: str = "", entry_data: dict = None):
        super().__init__(parent)
        self.parent = parent
        self.on_save = on_save
        self.edit_mode = bool(entry_name)
        entry_data = entry_data or {}

        screen_h = self.winfo_screenheight()
        dialog_h = min(640, max(540, screen_h - 120))
        self._dialog_size = (560, dialog_h)

        self.title("Edit Entry" if self.edit_mode else "New Entry")
        self.resizable(False, False)
        self.configure(fg_color=OFF_WHITE)
        self.transient(parent)
        self.grab_set()
        center_to_parent(self, parent, *self._dialog_size)
        self._build(entry_name, entry_data)
        self.after(50, lambda: center_to_parent(self, parent, *self._dialog_size))
        self.after(80, lambda: bring_to_front(self))
        self.after(120, self._focus_first_field)

    def _build(self, name: str, data: dict):
        root = ctk.CTkFrame(self, fg_color=OFF_WHITE, corner_radius=0)
        root.pack(fill="both", expand=True)
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)

        shell = ctk.CTkFrame(root, fg_color="transparent")
        shell.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)
        shell.grid_rowconfigure(1, weight=1)
        shell.grid_columnconfigure(0, weight=1)

        hdr = make_soft_card(shell, fg_color=BLUE, corner_radius=22, height=110)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)

        title = "Edit Entry" if self.edit_mode else "Add New Password"
        subtitle = (
            "Update the saved details below."
            if self.edit_mode else
            "Save a new login without changing how the vault works."
        )
        ctk.CTkLabel(
            hdr, text="Edit" if self.edit_mode else "New",
            font=(FONT_FAMILY, 17, "bold"), text_color="#D9E8F7", fg_color="transparent",
        ).pack(anchor="w", padx=22, pady=(16, 0))
        ctk.CTkLabel(
            hdr, text=title,
            font=FONT_TITLE, text_color=WHITE, fg_color="transparent",
        ).pack(anchor="w", padx=22, pady=(2, 0))
        ctk.CTkLabel(
            hdr, text=subtitle,
            font=FONT_BODY, text_color="#D9E8F7", fg_color="transparent",
        ).pack(anchor="w", padx=22, pady=(2, 0))

        body = ctk.CTkScrollableFrame(
            shell,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=DIVIDER,
            scrollbar_button_hover_color=MID_GREY,
        )
        body.grid(row=1, column=0, sticky="nsew", pady=(14, 12))

        card = make_soft_card(body, fg_color=WHITE, corner_radius=22)
        card.pack(fill="x", expand=True)

        make_section_label(card, "ACCOUNT NAME", pady=(18, 0), padx=22)
        self.var_name = ctk.StringVar(value=name)
        self.field_name = make_modern_entry(card, self.var_name, height=48)
        self.field_name.pack(fill="x", padx=22, pady=(6, 0))
        if self.edit_mode:
            self.field_name.configure(state="disabled")

        make_section_label(card, "USERNAME", pady=(14, 0), padx=22)
        self.var_user = ctk.StringVar(value=data.get("username", ""))
        self.field_user = make_modern_entry(card, self.var_user, height=48)
        self.field_user.pack(fill="x", padx=22, pady=(6, 0))

        make_section_label(card, "WEBSITE  (optional)", pady=(14, 0), padx=22)
        self.var_website = ctk.StringVar(value=data.get("website", ""))
        self.field_website = make_modern_entry(card, self.var_website, height=48, placeholder="example.com or https://example.com")
        self.field_website.pack(fill="x", padx=22, pady=(6, 0))

        make_section_label(card, "PASSWORD", pady=(14, 0), padx=22)
        pw_row = ctk.CTkFrame(card, fg_color="transparent")
        pw_row.pack(fill="x", padx=22, pady=(6, 0))

        self.var_pw = ctk.StringVar(value=data.get("password", ""))
        self.field_pw = make_modern_entry(pw_row, self.var_pw, show="•", height=48)
        self.field_pw.pack(side="left", fill="x", expand=True)

        self.toggle_pw_btn = ctk.CTkButton(
            pw_row, text="Show", width=86, height=48, corner_radius=12,
            fg_color=WHITE, hover_color=BLUE_LIGHT, text_color=BLUE,
            border_width=1, border_color=DIVIDER,
            font=FONT_BTN, command=self._toggle_pw,
        )
        self.toggle_pw_btn.pack(side="left", padx=(8, 0))
        ctk.CTkButton(
            pw_row, text="Generate", width=120, height=48, corner_radius=12,
            fg_color=BLUE_LIGHT, hover_color=DIVIDER, text_color=BLUE, font=FONT_BTN,
            command=self._gen_pw,
        ).pack(side="left", padx=(8, 0))

        make_section_label(card, "NOTES  (optional)", pady=(14, 0), padx=22)
        self.var_notes = ctk.StringVar(value=data.get("notes", ""))
        self.field_notes = make_modern_entry(card, self.var_notes, height=48)
        self.field_notes.pack(fill="x", padx=22, pady=(6, 0))

        btn_row = ctk.CTkFrame(shell, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew")
        btn_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(
            btn_row, text="Cancel",
            fg_color=LIGHT_GREY, hover_color=DIVIDER, text_color=DARK_TEXT,
            font=FONT_BTN, corner_radius=14, height=50,
            command=self.destroy,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="Save Entry",
            fg_color=BLUE, hover_color=BLUE_DARK, text_color=WHITE,
            font=FONT_BTN, corner_radius=14, height=50,
            command=self._save,
        ).grid(row=0, column=1, sticky="ew")

    def _focus_first_field(self):
        target = self.field_user if self.edit_mode else self.field_name
        target.focus()

    def _toggle_pw(self):
        is_hidden = self.field_pw.cget("show") == "•"
        self.field_pw.configure(show="" if is_hidden else "•")
        self.toggle_pw_btn.configure(text="Hide" if is_hidden else "Show")

    def _gen_pw(self):
        self.var_pw.set(generate_password(20))
        self.field_pw.configure(show="")
        self.toggle_pw_btn.configure(text="Hide")

    def _save(self):
        bring_to_front(self)
        name = self.var_name.get().strip()
        pw = self.var_pw.get()
        if not name:
            show_error("Missing Field", "Account name cannot be empty.", parent=self)
            bring_to_front(self)
            return
        if not pw:
            show_error("Missing Field", "Password cannot be empty.", parent=self)
            bring_to_front(self)
            return
        try:
            self.on_save(name, {
                "username": self.var_user.get().strip(),
                "website": normalize_website_url(self.var_website.get()),
                "password": pw,
                "notes": self.var_notes.get().strip(),
            })
        except Exception as exc:
            show_error("Save Error", f"Could not save entry:\n{exc}", parent=self)
            bring_to_front(self)
            return
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# Password Generator Panel  (collapsible, lives on the home screen)
# ══════════════════════════════════════════════════════════════════════════════

class PasswordGeneratorPanel(ctk.CTkFrame):
    """
    Collapsible panel. Click the header to expand/collapse.
    Lets the user tune length (slider 8–40) and character types,
    then generates and copies a password.
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=WHITE, corner_radius=16, **kwargs)
        self._expanded = False
        self._build()

    def _build(self):
        # Toggle header button
        self.toggle_btn = ctk.CTkButton(
            self,
            text="Password Generator  ▾",
            height=46, corner_radius=12,
            fg_color=BLUE_LIGHT, hover_color=DIVIDER,
            text_color=BLUE, font=FONT_BTN, anchor="w",
            command=self._toggle,
        )
        self.toggle_btn.pack(fill="x")

        # Body (hidden by default)
        self.body = ctk.CTkFrame(self, fg_color="transparent")

        # Output display row
        out_row = ctk.CTkFrame(self.body, fg_color=LIGHT_GREY, corner_radius=12)
        out_row.pack(fill="x", pady=(10, 0))

        self.gen_var = ctk.StringVar(value="Click Generate below")
        ctk.CTkLabel(
            out_row,
            textvariable=self.gen_var,
            font=FONT_MONO,
            text_color=DARK_TEXT,
            fg_color="transparent",
            anchor="w",
            wraplength=310,
        ).pack(side="left", fill="x", expand=True, padx=14, pady=12)

        self.copy_btn = ctk.CTkButton(
            out_row,
            text="Copy",
            width=72, height=36, corner_radius=8,
            fg_color=DIVIDER, hover_color=MID_GREY,
            text_color=DARK_TEXT, font=FONT_BTN,
            command=self._copy,
        )
        self.copy_btn.pack(side="right", padx=8)

        # Length slider
        slider_row = ctk.CTkFrame(self.body, fg_color="transparent")
        slider_row.pack(fill="x", pady=(12, 0))

        ctk.CTkLabel(
            slider_row, text="Length:",
            font=FONT_LABEL, text_color=DARK_TEXT, fg_color="transparent",
        ).pack(side="left")

        self.len_var = ctk.IntVar(value=20)
        ctk.CTkSlider(
            slider_row,
            from_=8, to=40,
            variable=self.len_var,
            number_of_steps=32,
            button_color=BLUE,
            button_hover_color=BLUE_DARK,
            progress_color=BLUE,
        ).pack(side="left", fill="x", expand=True, padx=10)

        self.len_label = ctk.CTkLabel(
            slider_row, text="20",
            font=FONT_BTN, text_color=BLUE,
            fg_color="transparent", width=28,
        )
        self.len_label.pack(side="left")
        self.len_var.trace_add("write", lambda *_: self.len_label.configure(
            text=str(self.len_var.get())))

        # Character type checkboxes
        opts_row = ctk.CTkFrame(self.body, fg_color="transparent")
        opts_row.pack(fill="x", pady=(10, 0))

        self.use_symbols = ctk.BooleanVar(value=True)
        self.use_numbers = ctk.BooleanVar(value=True)
        self.use_upper   = ctk.BooleanVar(value=True)

        for label, var in [("Symbols", self.use_symbols),
                            ("Numbers", self.use_numbers),
                            ("Uppercase", self.use_upper)]:
            ctk.CTkCheckBox(
                opts_row, text=label, variable=var,
                font=FONT_BODY_SM, text_color=DARK_TEXT,
                fg_color=BLUE, hover_color=BLUE_DARK,
                checkmark_color=WHITE, corner_radius=4,
            ).pack(side="left", padx=(0, 16))

        # Generate button
        ctk.CTkButton(
            self.body,
            text="Generate Password",
            height=44, corner_radius=12,
            fg_color=BLUE, hover_color=BLUE_DARK,
            text_color=WHITE, font=FONT_BTN,
            command=self._generate,
        ).pack(fill="x", pady=(12, 4))

    def _toggle(self):
        self._expanded = not self._expanded
        if self._expanded:
            self.body.pack(fill="x", padx=6, pady=(0, 10))
            self.toggle_btn.configure(text="Password Generator  ▴")
        else:
            self.body.pack_forget()
            self.toggle_btn.configure(text="Password Generator  ▾")

    def _build_alphabet(self) -> str:
        alpha = string.ascii_lowercase
        if self.use_upper.get():
            alpha += string.ascii_uppercase
        if self.use_numbers.get():
            alpha += string.digits
        if self.use_symbols.get():
            alpha += string.punctuation
        return alpha or (string.ascii_letters + string.digits)

    def _generate(self):
        length   = self.len_var.get()
        alphabet = self._build_alphabet()
        for _ in range(1000):
            pwd = "".join(secrets.choice(alphabet) for _ in range(length))
            ok  = True
            if self.use_upper.get()   and not any(c.isupper() for c in pwd): ok = False
            if self.use_numbers.get() and not any(c.isdigit() for c in pwd): ok = False
            if self.use_symbols.get() and not any(c in string.punctuation for c in pwd): ok = False
            if ok:
                self.gen_var.set(pwd)
                self.copy_btn.configure(text="Copy", fg_color=DIVIDER, text_color=DARK_TEXT)
                return

    def _copy(self):
        val = self.gen_var.get()
        if val.startswith("Click"):
            return
        self.clipboard_clear()
        self.clipboard_append(val)
        self.update()
        self.copy_btn.configure(text="Copied", fg_color=GREEN_DIM, text_color=GREEN)
        self.after(1800, lambda: self.copy_btn.configure(
            text="Copy", fg_color=DIVIDER, text_color=DARK_TEXT))


# ══════════════════════════════════════════════════════════════════════════════
# Screen 2 — Vault Home
# ══════════════════════════════════════════════════════════════════════════════

class VaultHomeScreen(ctk.CTkToplevel):
    def __init__(self, parent, vault: dict, master_password: str,
                 salt: bytes, on_lock=None):
        super().__init__(parent)
        self.parent          = parent
        self.vault           = vault
        self.master_password = master_password
        self.salt            = salt
        self.on_lock         = on_lock

        self.title("Password Manager")
        self.resizable(True, True)
        self.geometry("860x760")
        self.minsize(700, 620)
        self.configure(fg_color=OFF_WHITE)
        center_window(self, 860, 760)

        self._build()
        self._render_rows()

    def _build(self):
        shell = ctk.CTkFrame(self, fg_color=OFF_WHITE, corner_radius=0)
        shell.pack(fill="both", expand=True, padx=18, pady=18)

        header = make_soft_card(shell, fg_color=BLUE, corner_radius=24, height=148)
        header.pack(fill="x")
        header.pack_propagate(False)

        header_left = ctk.CTkFrame(header, fg_color="transparent")
        header_left.pack(side="left", fill="both", expand=True, padx=24, pady=22)

        ctk.CTkLabel(
            header_left, text="Password Manager",
            font=FONT_HERO, text_color=WHITE, fg_color="transparent",
        ).pack(anchor="w")
        meta = ctk.CTkFrame(header_left, fg_color="transparent")
        meta.pack(anchor="w", pady=(12, 0))
        self.count_pill = ctk.CTkLabel(
            meta,
            text=self._count_text(),
            font=FONT_BODY_SM,
            text_color=WHITE,
            fg_color=BLUE_DARK,
            corner_radius=999,
            padx=14,
            pady=6,
        )
        self.count_pill.pack(side="left")

        header_actions = ctk.CTkFrame(header, fg_color="transparent")
        header_actions.pack(side="right", padx=22, pady=22)
        ctk.CTkButton(
            header_actions, text="Lock",
            width=102, height=40, corner_radius=12,
            fg_color=BLUE_DARK, hover_color="#2E6AB0",
            text_color=WHITE, font=FONT_BTN,
            command=self._lock,
        ).pack()

        toolbar = ctk.CTkFrame(shell, fg_color="transparent")
        toolbar.pack(fill="x", pady=(16, 14))

        search_card = make_soft_card(toolbar, fg_color=WHITE, corner_radius=20)
        search_card.pack(side="left", fill="x", expand=True)
        search_inner = ctk.CTkFrame(search_card, fg_color="transparent")
        search_inner.pack(fill="x", padx=16, pady=14)
        ctk.CTkLabel(
            search_inner, text="Search your vault",
            font=FONT_SECTION, text_color=MID_GREY, fg_color="transparent",
        ).pack(anchor="w")

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._render_rows())
        self.search_entry = make_modern_entry(
            search_inner,
            self.search_var,
            placeholder="Search by account or username…",
            height=44,
        )
        self.search_entry.pack(fill="x", pady=(6, 0))

        ctk.CTkButton(
            toolbar, text="Add Entry",
            width=156, height=76, corner_radius=20,
            fg_color=BLUE, hover_color=BLUE_DARK,
            text_color=WHITE, font=FONT_BTN_LG,
            command=self._open_add_dialog,
        ).pack(side="left", padx=(14, 0))

        content = ctk.CTkFrame(shell, fg_color="transparent")
        content.pack(fill="both", expand=True)
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=0)
        content.grid_rowconfigure(0, weight=1)

        list_card = make_soft_card(content, fg_color=WHITE, corner_radius=22)
        list_card.grid(row=0, column=0, sticky="nsew", padx=(0, 14))

        list_header = ctk.CTkFrame(list_card, fg_color="transparent", height=54)
        list_header.pack(fill="x", padx=18, pady=(14, 0))
        list_header.pack_propagate(False)
        ctk.CTkLabel(
            list_header, text="Saved Accounts",
            font=FONT_TITLE_SM, text_color=DARK_TEXT, fg_color="transparent",
        ).pack(side="left")
        self.list_meta = ctk.CTkLabel(
            list_header, text="",
            font=FONT_BODY_SM, text_color=MID_GREY, fg_color="transparent",
        )
        self.list_meta.pack(side="right")

        col_hdr = ctk.CTkFrame(list_card, fg_color="transparent", height=28)
        col_hdr.pack(fill="x", padx=18, pady=(0, 8))
        col_hdr.pack_propagate(False)
        ctk.CTkLabel(
            col_hdr, text="ACCOUNT",
            font=FONT_SECTION, text_color=MID_GREY, fg_color="transparent",
        ).place(x=18, rely=0.5, anchor="w")
        ctk.CTkLabel(
            col_hdr, text="USERNAME",
            font=FONT_SECTION, text_color=MID_GREY, fg_color="transparent",
        ).place(relx=0.56, rely=0.5, anchor="w")

        self.list_frame = ctk.CTkScrollableFrame(
            list_card,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=DIVIDER,
            scrollbar_button_hover_color=MID_GREY,
        )
        self.list_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        side = ctk.CTkFrame(content, fg_color="transparent", width=270)
        side.grid(row=0, column=1, sticky="ns")
        side.grid_propagate(False)

        helper_card = make_soft_card(side, fg_color=WHITE, corner_radius=22)
        helper_card.pack(fill="x")
        ctk.CTkLabel(
            helper_card, text="Quick tools",
            font=FONT_TITLE_SM, text_color=DARK_TEXT, fg_color="transparent",
        ).pack(anchor="w", padx=18, pady=(18, 6))
        ctk.CTkLabel(
            helper_card,
            text="Generate strong passwords or search saved logins without changing the encryption flow.",
            font=FONT_BODY_SM,
            text_color=MID_GREY,
            fg_color="transparent",
            justify="left",
            wraplength=220,
        ).pack(anchor="w", padx=18, pady=(0, 14))

        self.gen_panel = PasswordGeneratorPanel(helper_card)
        self.gen_panel.pack(fill="x", padx=16, pady=(0, 16))

    def _render_rows(self):
        for w in self.list_frame.winfo_children():
            w.destroy()

        query = self.search_var.get().lower().strip()
        entries = sorted(
            (
                (n, d) for n, d in self.vault.items()
                if query in n.lower() or query in d.get("username", "").lower() or query in d.get("website", "").lower()
            ),
            key=lambda x: x[0].lower(),
        )

        self.count_pill.configure(text=self._count_text())
        self.list_meta.configure(text=f"{len(entries)} shown")

        if not entries:
            msg = (
                "No entries yet.\nUse Add Entry to save your first password."
                if not self.vault else
                "No results match your search."
            )
            empty = ctk.CTkFrame(self.list_frame, fg_color="transparent")
            empty.pack(fill="both", expand=True, pady=70)
            ctk.CTkLabel(
                empty, text="Search",
                font=(FONT_FAMILY, 36), text_color="#B7C4D4", fg_color="transparent",
            ).pack()
            ctk.CTkLabel(
                empty, text=msg,
                font=FONT_BODY, text_color=MID_GREY, fg_color="transparent",
                justify="center",
            ).pack(pady=(8, 0))
            return

        for i, (name, data) in enumerate(entries):
            self._make_row(name, data, i)

    def _make_row(self, name: str, data: dict, index: int):
        row = make_soft_card(self.list_frame, fg_color=OFF_WHITE, corner_radius=16, height=68)
        row.pack(fill="x", padx=8, pady=5)
        row.pack_propagate(False)

        accent = ctk.CTkLabel(
            row,
            text=f"{index + 1}",
            width=34,
            height=34,
            font=FONT_NUMERIC,
            text_color=BLUE,
            fg_color=BLUE_LIGHT,
            corner_radius=999,
        )
        accent.place(x=16, rely=0.5, anchor="w")

        text_wrap = ctk.CTkFrame(row, fg_color="transparent")
        text_wrap.place(x=58, rely=0.5, anchor="w")
        website = data.get("website", "")
        if website:
            name_widget = ctk.CTkButton(
                text_wrap, text=name,
                font=FONT_BTN, text_color=BLUE,
                fg_color="transparent", hover_color=BLUE_LIGHT,
                anchor="w", width=10, height=24,
                command=lambda url=website: open_website(url),
            )
            name_widget.pack(anchor="w")
        else:
            ctk.CTkLabel(
                text_wrap, text=name,
                font=FONT_BTN, text_color=DARK_TEXT,
                fg_color="transparent", anchor="w",
            ).pack(anchor="w")
        subtitle = data.get("username", "—")
        if website:
            subtitle = f"{subtitle}   •   {website.replace('https://', '').replace('http://', '')}"
        ctk.CTkLabel(
            text_wrap, text=subtitle,
            font=FONT_BODY_SM, text_color=MID_GREY,
            fg_color="transparent", anchor="w",
        ).pack(anchor="w", pady=(2, 0))

        actions = ctk.CTkFrame(row, fg_color="transparent")
        actions.place(relx=1.0, rely=0.5, anchor="e", x=-14)

        if website:
            ctk.CTkButton(
                actions, text="Website", width=78, height=36,
                corner_radius=10, fg_color=WHITE, hover_color=BLUE_LIGHT,
                text_color=BLUE, font=FONT_BODY_SM,
                command=lambda url=website: open_website(url),
            ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            actions, text="Open", width=62, height=36,
            corner_radius=10, fg_color=WHITE, hover_color=DIVIDER,
            text_color=DARK_TEXT, font=FONT_BODY_SM,
            command=lambda n=name, d=data: self._open_detail(n, d),
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            actions, text="Edit", width=56, height=36,
            corner_radius=10, fg_color=WHITE, hover_color=DIVIDER,
            text_color=DARK_TEXT, font=FONT_BODY_SM,
            command=lambda n=name, d=data: self._open_edit_dialog(n, d),
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            actions, text="Delete", width=68, height=36,
            corner_radius=10, fg_color=WHITE, hover_color=RED_HOVER,
            text_color=DARK_TEXT, font=FONT_BODY_SM,
            command=lambda n=name: self._delete_entry(n),
        ).pack(side="left")

        row.bind("<Button-1>", lambda e, n=name, d=data: self._open_detail(n, d))
        row.bind("<Enter>", lambda e, r=row: r.configure(fg_color=ROW_HOVER))
        row.bind("<Leave>", lambda e, r=row: r.configure(fg_color=OFF_WHITE))

    def _open_detail(self, name, data):
        EntryDetailScreen(parent=self, entry_name=name, entry_data=data)

    def _open_add_dialog(self):
        AddEntryDialog(parent=self, on_save=self._save_new_entry)

    def _open_edit_dialog(self, name, data):
        AddEntryDialog(
            parent=self,
            on_save=lambda n, d: self._update_entry(name, d),
            entry_name=name, entry_data=data,
        )

    def _save_new_entry(self, name: str, data: dict):
        if name in self.vault:
            if not ask_yes_no("Overwrite?",
                              f"'{name}' already exists. Overwrite it?", parent=self):
                return
        self.vault[name] = data
        self._persist()
        self._refresh()

    def _update_entry(self, name: str, data: dict):
        self.vault[name] = data
        self._persist()
        self._refresh()

    def _delete_entry(self, name: str):
        if ask_yes_no("Delete Entry", f"Permanently delete '{name}'?", parent=self):
            del self.vault[name]
            self._persist()
            self._refresh()

    def _persist(self):
        save_vault(self.master_password, self.vault, self.salt)

    def _refresh(self):
        self._render_rows()

    def _count_text(self):
        n = len(self.vault)
        return f"{n} stored password{'s' if n != 1 else ''}"

    def _lock(self):
        self.destroy()
        if self.on_lock:
            self.on_lock()


# ══════════════════════════════════════════════════════════════════════════════
# Screen 1 — Master Password / Login
# ══════════════════════════════════════════════════════════════════════════════

class MasterPasswordScreen(ctk.CTk):
    def __init__(self):
        super().__init__()
        migrate_legacy_vault_if_needed()
        self.is_new_vault = not os.path.exists(VAULT_FILE)
        self.title("Password Manager")
        self.resizable(False, False)
        self.configure(fg_color=OFF_WHITE)
        self._center_window(width=470, height=690 if self.is_new_vault else 540)
        self._build()
        self.bind("<Return>", lambda e: self._on_submit())

    def _build(self):
        shell = ctk.CTkFrame(self, fg_color=OFF_WHITE, corner_radius=0)
        shell.pack(fill="both", expand=True, padx=18, pady=18)

        outer = make_soft_card(shell, fg_color=WHITE, corner_radius=26)
        outer.pack(fill="both", expand=True)

        hero = ctk.CTkFrame(outer, fg_color=BLUE, corner_radius=26)
        hero.pack(fill="x", padx=14, pady=14)

        ctk.CTkLabel(hero, text="Secure", font=FONT_ICON_LG, fg_color="transparent").pack(pady=(30, 6))
        ctk.CTkLabel(
            hero,
            text="Create Your Vault" if self.is_new_vault else "Welcome Back",
            font=FONT_HERO, text_color=WHITE, fg_color="transparent",
        ).pack()
        ctk.CTkLabel(
            hero,
            text=("Set a strong master password to protect your vault."
                  if self.is_new_vault
                  else "Enter your master password to unlock your vault."),
            font=FONT_BODY, text_color="#D9E8F7", fg_color="transparent",
            wraplength=360, justify="center",
        ).pack(pady=(6, 26))

        inner = ctk.CTkFrame(outer, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=30, pady=(6, 26))

        if self.is_new_vault:
            hint = ctk.CTkFrame(inner, fg_color=BLUE_LIGHT, corner_radius=14)
            hint.pack(fill="x", pady=(0, 18))
            ctk.CTkLabel(
                hint,
                text="Must include: 8+ chars · uppercase · lowercase · number · symbol",
                font=FONT_BODY_SM, text_color=BLUE, fg_color="transparent",
                wraplength=340,
            ).pack(padx=14, pady=10)

        ctk.CTkLabel(
            inner, text="MASTER PASSWORD",
            font=FONT_SECTION, text_color=MID_GREY,
            fg_color="transparent", anchor="w",
        ).pack(fill="x", pady=(0, 6))

        self.password_var = ctk.StringVar()
        self.field_pw = make_modern_entry(inner, self.password_var, height=52, show="•")
        self.field_pw.pack(fill="x")

        self.confirm_var = ctk.StringVar()
        if self.is_new_vault:
            ctk.CTkLabel(
                inner, text="CONFIRM PASSWORD",
                font=FONT_SECTION, text_color=MID_GREY,
                fg_color="transparent", anchor="w",
            ).pack(fill="x", pady=(16, 6))
            self.field_confirm = make_modern_entry(inner, self.confirm_var, height=52, show="•")
            self.field_confirm.pack(fill="x")
        else:
            self.field_confirm = ctk.CTkEntry(inner, textvariable=self.confirm_var, show="•")

        if self.is_new_vault:
            self.strength_label = ctk.CTkLabel(
                inner, text="",
                font=FONT_BODY_SM, fg_color="transparent",
                text_color=MID_GREY, anchor="w",
            )
            self.strength_label.pack(fill="x", pady=(8, 0))
            self.password_var.trace_add("write", self._update_strength)

        self.show_pw = False
        self.toggle_btn = ctk.CTkButton(
            inner, text="Show password",
            height=34, corner_radius=10,
            fg_color="transparent", hover_color=LIGHT_GREY,
            text_color=MID_GREY, font=FONT_BODY_SM, anchor="w",
            command=self._toggle_visibility,
        )
        self.toggle_btn.pack(fill="x", pady=(8, 0))

        ctk.CTkButton(
            inner,
            text="Create Vault" if self.is_new_vault else "Unlock Vault",
            height=52, corner_radius=14,
            fg_color=BLUE, hover_color=BLUE_DARK,
            text_color=WHITE, font=FONT_BTN_LG,
            command=self._on_submit,
        ).pack(fill="x", pady=(18, 0))

        footer = ctk.CTkLabel(
            inner,
            text="Encrypted locally on your device.",
            font=FONT_BODY_SM,
            text_color=MID_GREY,
            fg_color="transparent",
        )
        footer.pack(pady=(14, 0))

        self.after(350, self.field_pw.focus)

    def _update_strength(self, *_):
        pw = self.password_var.get()
        if not pw:
            self.strength_label.configure(text="")
            return
        score = sum([
            any(c.isupper() for c in pw),
            any(c.islower() for c in pw),
            any(c.isdigit() for c in pw),
            any(c in SYMBOLS for c in pw),
            len(pw) >= 8,
        ])
        if score <= 2:
            self.strength_label.configure(text="Strength: Weak ❌", text_color="#E05252")
        elif score == 3:
            self.strength_label.configure(text="Strength: Fair ⚠️", text_color="#D4930A")
        elif score == 4:
            self.strength_label.configure(text="Strength: Good ✅", text_color="#2A9D3C")
        else:
            self.strength_label.configure(text="Strength: Strong 💪", text_color="#2A9D3C")

    def _toggle_visibility(self):
        self.show_pw = not self.show_pw
        char = "" if self.show_pw else "•"
        self.field_pw.configure(show=char)
        self.field_confirm.configure(show=char)
        self.toggle_btn.configure(
            text="Hide password" if self.show_pw else "Show password")

    def _on_submit(self):
        master = self.password_var.get()
        if not master:
            show_error("Error", "Please enter a master password.", parent=self)
            return

        if self.is_new_vault:
            checks = [
                (len(master) >= 8,                  "at least 8 characters"),
                (any(c.isupper() for c in master),  "one uppercase letter"),
                (any(c.islower() for c in master),  "one lowercase letter"),
                (any(c.isdigit() for c in master),  "one number"),
                (any(c in SYMBOLS for c in master), "one symbol  (! @ # $ %)"),
            ]
            for ok, msg in checks:
                if not ok:
                    show_error("Weak Password",
                               f"Your password must include {msg}.", parent=self)
                    return
            if master != self.confirm_var.get():
                show_error("Mismatch",
                           "Passwords don't match — please try again.", parent=self)
                self.confirm_var.set("")
                return

            salt = os.urandom(16)
            vault = {}
            save_vault(master, vault, salt)
            show_info("Vault Created", "Your vault is ready!", parent=self)
            self._launch_home(vault, master, salt)

        else:
            try:
                salt = get_vault_salt()
                vault = load_vault(master)
                self._launch_home(vault, master, salt)
            except ValueError:
                show_error("Wrong Password",
                           "Incorrect master password — please try again.", parent=self)
                self.password_var.set("")
                self.after(250, self.field_pw.focus)

    def _launch_home(self, vault, master, salt):
        self.withdraw()
        VaultHomeScreen(
            parent=self,
            vault=vault,
            master_password=master,
            salt=salt,
            on_lock=self._on_lock,
        )

    def _on_lock(self):
        self.password_var.set("")
        self.confirm_var.set("")
        self.deiconify()
        self.after(250, self.field_pw.focus)

    def _center_window(self, width, height):
        center_window(self, width, height)


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = MasterPasswordScreen()
    app.mainloop()
