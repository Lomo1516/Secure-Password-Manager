#!/usr/bin/env python3
"""
Screen 1: Master Password Screen
=================================
This is the ENTRY POINT of the app — the first window the user sees.

It handles two situations:
  1. NEW USER  → vault.enc does NOT exist → ask them to create a master password
  2. RETURNING → vault.enc EXISTS         → ask them to enter their master password

How it connects to your backend (password_manager.py):
  - Calls load_vault(master_password)  to verify login
  - Calls save_vault(master, {}, salt) to create a new vault on first run

Dependencies:
    pip install customtkinter cryptography

Run this file directly to see the screen:
    python master_password_screen.py
"""

import os
import customtkinter as ctk
from tkinter import messagebox

# ── Import your existing backend functions ─────────────────────────────────────
from password_manager import load_vault, save_vault, VAULT_FILE

# ── App-wide theme ─────────────────────────────────────────────────────────────
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ── Design tokens ──────────────────────────────────────────────────────────────
BLUE       = "#5B9BD5"
WHITE      = "#FFFFFF"
LIGHT_GREY = "#F0F0F0"
DARK_TEXT  = "#1A1A1A"

FONT_TITLE       = ("Helvetica Neue", 22, "bold")
FONT_SUB         = ("Helvetica Neue", 13)
FONT_LABEL       = ("Helvetica Neue", 12)
FONT_FIELD_LABEL = ("Helvetica Neue", 12)
FONT_BTN         = ("Helvetica Neue", 15, "bold")
FONT_FIELD       = ("Helvetica Neue", 14)

# ── Symbols allowed in master password ────────────────────────────────────────
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


# ══════════════════════════════════════════════════════════════════════════════
# MasterPasswordScreen
# ══════════════════════════════════════════════════════════════════════════════

class MasterPasswordScreen(ctk.CTk):
    """
    The root application window shown at startup.

    After the user successfully logs in (or creates a new vault),
    on_success(vault, master_password, salt) is called so the rest
    of the app can receive the unlocked vault data.
    """

    def __init__(self, on_success=None):
        super().__init__()

        self.on_success = on_success
        self.is_new_vault = not os.path.exists(VAULT_FILE)

        # ── Window setup ───────────────────────────────────────────────────────
        self.title("Password Manager")
        self.resizable(False, False)
        self._center_window(width=440, height=580 if self.is_new_vault else 460)

        # ── Build UI ───────────────────────────────────────────────────────────
        self._build_ui()

        self.bind("<Return>", lambda e: self._on_submit())

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build_ui(self):

        # Outer blue card
        self.card = ctk.CTkFrame(self, fg_color=BLUE, corner_radius=0)
        self.card.pack(fill="both", expand=True)

        # ── Lock icon ──────────────────────────────────────────────────────────
        ctk.CTkLabel(
            self.card,
            text="🔐",
            font=("Helvetica Neue", 52),
            fg_color="transparent",
        ).pack(pady=(40, 8))

        # ── Title ──────────────────────────────────────────────────────────────
        title_text = "Create Your Vault" if self.is_new_vault else "Welcome Back"
        ctk.CTkLabel(
            self.card,
            text=title_text,
            font=FONT_TITLE,
            text_color=WHITE,
            fg_color="transparent",
        ).pack(pady=(0, 4))

        # ── Subtitle / instructions ────────────────────────────────────────────
        if self.is_new_vault:
            sub_text = (
                "Your password must include:\n\n"
                "•  At least 8 characters\n"
                "•  One uppercase letter\n"
                "•  One lowercase letter\n"
                "•  One number\n"
                "•  One symbol  ( ! @ # $ % )"
            )
        else:
            sub_text = "Enter your master password to unlock your vault."

        ctk.CTkLabel(
            self.card,
            text=sub_text,
            font=FONT_SUB,
            text_color=WHITE,
            fg_color="transparent",
            wraplength=360,
            justify="left",
        ).pack(pady=(0, 8))

        # ── Master Password label + field ──────────────────────────────────────
        ctk.CTkLabel(
            self.card,
            text="Master Password",
            font=FONT_FIELD_LABEL,
            text_color=WHITE,
            fg_color="transparent",
            anchor="center",
            width=360,
        ).pack()

        self.password_var = ctk.StringVar()
        self.field_pw = ctk.CTkEntry(
            self.card,
            textvariable=self.password_var,
            fg_color=WHITE,
            text_color=DARK_TEXT,
            border_width=0,
            corner_radius=14,
            height=52,
            font=FONT_FIELD,
            show="•",
            width=360,
        )
        self.field_pw.pack(pady=(2, 8))

        # ── Confirm Password label + field (new vault only) ────────────────────
        self.confirm_var = ctk.StringVar()
        if self.is_new_vault:
            ctk.CTkLabel(
                self.card,
                text="Confirm Password",
                font=FONT_FIELD_LABEL,
                text_color=WHITE,
                fg_color="transparent",
                anchor="center",
                width=360,
            ).pack()

            self.field_confirm = ctk.CTkEntry(
                self.card,
                textvariable=self.confirm_var,
                fg_color=WHITE,
                text_color=DARK_TEXT,
                border_width=0,
                corner_radius=14,
                height=52,
                font=FONT_FIELD,
                show="•",
                width=360,
            )
            self.field_confirm.pack(pady=(2, 4))
        else:
            # Hidden field so toggle doesn't break on login screen
            self.field_confirm = ctk.CTkEntry(
                self.card, textvariable=self.confirm_var, show="•"
            )

        # ── Password strength indicator (new vault only) ───────────────────────
        if self.is_new_vault:
            self.strength_label = ctk.CTkLabel(
                self.card,
                text="",
                font=FONT_LABEL,
                fg_color="transparent",
                text_color=WHITE,
            )
            self.strength_label.pack(pady=(0, 0))
            self.password_var.trace_add("write", self._update_strength)

        # ── Show/hide toggle ───────────────────────────────────────────────────
        self.show_pw = False
        self.toggle_btn = ctk.CTkButton(
            self.card,
            text="Show password",
            width=360,
            height=36,
            corner_radius=10,
            fg_color="transparent",
            hover_color="#4a89c4",
            text_color=WHITE,
            font=FONT_SUB,
            command=self._toggle_visibility,
        )
        self.toggle_btn.pack(pady=(0, 12))

        # ── Submit button ──────────────────────────────────────────────────────
        btn_label = "Create Vault" if self.is_new_vault else "Unlock"
        ctk.CTkButton(
            self.card,
            text=btn_label,
            width=360,
            height=54,
            corner_radius=16,
            fg_color=LIGHT_GREY,
            hover_color="#DCDCDC",
            text_color=DARK_TEXT,
            font=FONT_BTN,
            command=self._on_submit,
        ).pack()

        # ── Auto focus password field ──────────────────────────────────────────
        self.after(500, self.field_pw.focus)

    # ── Password strength checker ───────────────────────────────────────────────

    def _update_strength(self, *args):
        """
        Checks the password as the user types and shows live feedback.
        Now checks all 5 criteria: upper, lower, digit, symbol, length.
        """
        pw = self.password_var.get()

        if not pw:
            self.strength_label.configure(text="")
            return

        has_upper   = any(c.isupper() for c in pw)
        has_lower   = any(c.islower() for c in pw)
        has_digit   = any(c.isdigit() for c in pw)
        has_symbol  = any(c in SYMBOLS for c in pw)
        long_enough = len(pw) >= 8

        score = sum([has_upper, has_lower, has_digit, has_symbol, long_enough])

        if score <= 2:
            self.strength_label.configure(text="Strength: Weak ❌",   text_color="#FFAAAA")
        elif score == 3:
            self.strength_label.configure(text="Strength: Fair ⚠️",   text_color="#FFDD88")
        elif score == 4:
            self.strength_label.configure(text="Strength: Good ✅",   text_color="#AAFFAA")
        else:
            self.strength_label.configure(text="Strength: Strong 💪", text_color="#AAFFAA")

    # ── Handlers ───────────────────────────────────────────────────────────────

    def _toggle_visibility(self):
        """Switches password fields between hidden and visible."""
        self.show_pw = not self.show_pw
        char = "" if self.show_pw else "•"
        self.field_pw.configure(show=char)
        self.field_confirm.configure(show=char)
        self.toggle_btn.configure(
            text="Hide password" if self.show_pw else "Show password"
        )

    def _on_submit(self):
        """
        Called when user clicks the button or presses Enter.

        NEW VAULT  → validate all 5 criteria + match → create vault → on_success
        RETURNING  → try to decrypt vault → if wrong pw, show error
        """
        master = self.password_var.get()

        # ── Guard: empty password ──────────────────────────────────────────────
        if not master:
            messagebox.showerror("Error", "Please enter a master password.")
            return

        if self.is_new_vault:

            # ── Password strength checks ───────────────────────────────────────
            if len(master) < 8:
                messagebox.showerror(
                    "Weak Password",
                    "Your password must be at least 8 characters long."
                )
                return

            if not any(c.isupper() for c in master):
                messagebox.showerror(
                    "Weak Password",
                    "Your password must include at least one uppercase letter.\nExample: Password1!"
                )
                return

            if not any(c.islower() for c in master):
                messagebox.showerror(
                    "Weak Password",
                    "Your password must include at least one lowercase letter.\nExample: Password1!"
                )
                return

            if not any(c.isdigit() for c in master):
                messagebox.showerror(
                    "Weak Password",
                    "Your password must include at least one number.\nExample: Password1!"
                )
                return

            if not any(c in SYMBOLS for c in master):
                messagebox.showerror(
                    "Weak Password",
                    "Your password must include at least one symbol.\nExample: ! @ # $ %"
                )
                return

            # ── Confirmation match check ───────────────────────────────────────
            confirm = self.confirm_var.get()
            if master != confirm:
                messagebox.showerror(
                    "Passwords Don't Match",
                    "The passwords you entered don't match.\nPlease try again."
                )
                self.confirm_var.set("")
                return

            # ── Create vault ───────────────────────────────────────────────────
            salt = os.urandom(16)
            vault = {}
            save_vault(master, vault, salt)
            messagebox.showinfo(
                "Vault Created!",
                "Your vault has been created successfully!\nYou're all set."
            )
            self._launch_main_screen(vault, master, salt)

        else:
            # ── Returning user: try to decrypt ─────────────────────────────────
            try:
                salt = self._read_salt()
                vault = load_vault(master)
                self._launch_main_screen(vault, master, salt)

            except SystemExit:
                messagebox.showerror(
                    "Wrong Password",
                    "Incorrect master password.\nPlease try again."
                )
                self.password_var.set("")
                self.after(500, self.field_pw.focus)

    def _read_salt(self) -> bytes:
        """Reads the 16-byte salt stored at the start of the vault file."""
        with open(VAULT_FILE, "rb") as f:
            return f.read()[:16]

    def _launch_main_screen(self, vault: dict, master: str, salt: bytes):
        """
        Called after successful login.
        Replace the placeholder below with MainVaultScreen once built.
        """
        if self.on_success:
            self.on_success(vault, master, salt)
        else:
            messagebox.showinfo(
                "Logged In",
                f"Login successful!\nVault contains {len(vault)} entries.\n\n"
                "(Main vault screen coming next!)"
            )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _center_window(self, width: int, height: int):
        """Centers the window on the screen."""
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - width) // 2
        y = (sh - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = MasterPasswordScreen()
    app.mainloop()