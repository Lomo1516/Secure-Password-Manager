#!/usr/bin/env python3
"""
Password Manager
A simple, local, encrypted password manager using AES-256 encryption.

Dependencies:
    pip install cryptography

Usage:
    python password_manager.py
"""

import os
import json
import base64
import getpass
import secrets
import string
import sys

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Missing dependency. Install with: pip install cryptography")
    sys.exit(1)

VAULT_FILE = "vault.enc"
ITERATIONS = 480_000


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def load_vault(master_password: str) -> dict:
    """Load and decrypt the vault. Returns empty dict if vault doesn't exist."""
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    salt, token = data[:16], data[16:]
    key = derive_key(master_password, salt)
    try:
        decrypted = Fernet(key).decrypt(token)
        return json.loads(decrypted)
    except Exception:
        print("❌  Wrong master password or corrupted vault.")
        sys.exit(1)


def save_vault(master_password: str, vault: dict, salt: bytes) -> None:
    """Encrypt and save the vault."""
    key = derive_key(master_password, salt)
    token = Fernet(key).encrypt(json.dumps(vault).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + token)


def get_or_create_salt() -> bytes:
    """Return the salt stored in the vault file, or create a new one."""
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "rb") as f:
            return f.read()[:16]
    return os.urandom(16)


# ── Password generator ─────────────────────────────────────────────────────────

def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        # Ensure at least one of each required character type
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in string.punctuation for c in pwd)):
            return pwd


# ── CLI helpers ────────────────────────────────────────────────────────────────

def print_header():
    print("\n" + "═" * 42)
    print("         🔐  Password Manager")
    print("═" * 42)


def menu() -> str:
    print("""
  [1] List accounts
  [2] Add / update entry
  [3] Get password
  [4] Delete entry
  [5] Generate password
  [6] Change master password
  [0] Quit
""")
    return input("  Choose: ").strip()


# ── Actions ────────────────────────────────────────────────────────────────────

def list_accounts(vault: dict) -> None:
    if not vault:
        print("  (no entries yet)")
        return
    print(f"\n  {'#':<4} {'Account':<30} {'Username'}")
    print("  " + "-" * 55)
    for i, (name, data) in enumerate(sorted(vault.items()), 1):
        username = data.get("username", "")
        print(f"  {i:<4} {name:<30} {username}")


def add_entry(vault: dict) -> None:
    name = input("  Account name (e.g. github): ").strip()
    if not name:
        return
    username = input("  Username / email: ").strip()
    choice = input("  Generate password? [y/N]: ").strip().lower()
    if choice == "y":
        try:
            length = int(input("  Length [20]: ").strip() or "20")
        except ValueError:
            length = 20
        password = generate_password(length)
        print(f"  Generated: {password}")
    else:
        password = getpass.getpass("  Password: ")
        confirm = getpass.getpass("  Confirm password: ")
        if password != confirm:
            print("  ❌  Passwords don't match.")
            return
    notes = input("  Notes (optional): ").strip()
    vault[name] = {"username": username, "password": password, "notes": notes}
    print(f"  ✅  Saved '{name}'.")


def get_entry(vault: dict) -> None:
    name = input("  Account name: ").strip()
    entry = vault.get(name)
    if not entry:
        print(f"  ❌  No entry for '{name}'.")
        return
    print(f"\n  Account:  {name}")
    print(f"  Username: {entry.get('username', '')}")
    print(f"  Password: {entry['password']}")
    if entry.get("notes"):
        print(f"  Notes:    {entry['notes']}")


def delete_entry(vault: dict) -> None:
    name = input("  Account name to delete: ").strip()
    if name not in vault:
        print(f"  ❌  No entry for '{name}'.")
        return
    confirm = input(f"  Delete '{name}'? [Y/N]: ").strip().lower()
    if confirm == "y":
        del vault[name]
        print(f"  ✅  Deleted '{name}'.")


def generate_standalone() -> None:
    try:
        length = int(input("  Length [20]: ").strip() or "20")
    except ValueError:
        length = 20
    print(f"  {generate_password(length)}")


def change_master(vault: dict, old_password: str) -> tuple[dict, str, bytes]:
    """Returns (vault, new_password, new_salt)."""
    new_pw = getpass.getpass("  New master password: ")
    confirm = getpass.getpass("  Confirm new master password: ")
    if new_pw != confirm:
        print("  ❌  Passwords don't match.")
        return vault, old_password, get_or_create_salt()
    new_salt = os.urandom(16)
    print("  ✅  Master password updated.")
    return vault, new_pw, new_salt


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print_header()

    # First run: set master password
    is_new = not os.path.exists(VAULT_FILE)
    if is_new:
        print("\n  No vault found. Create a new one.")
        master = getpass.getpass("  Set master password: ")
        confirm = getpass.getpass("  Confirm master password: ")
        if master != confirm:
            print("  ❌  Passwords don't match. Exiting.")
            sys.exit(1)
        salt = os.urandom(16)
        vault: dict = {}
        save_vault(master, vault, salt)
        print("  ✅  Vault created.\n")
    else:
        master = getpass.getpass("\n  Master password: ")
        salt = get_or_create_salt()
        vault = load_vault(master)

    while True:
        choice = menu()

        if choice == "1":
            list_accounts(vault)
        elif choice == "2":
            add_entry(vault)
            save_vault(master, vault, salt)
        elif choice == "3":
            get_entry(vault)
        elif choice == "4":
            delete_entry(vault)
            save_vault(master, vault, salt)
        elif choice == "5":
            generate_standalone()
        elif choice == "6":
            vault, master, salt = change_master(vault, master)
            save_vault(master, vault, salt)
        elif choice == "0":
            print("  Goodbye! 👋\n")
            break
        else:
            print("  Invalid choice.")


if __name__ == "__main__":
    main()
