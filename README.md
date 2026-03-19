# Secure Local Password Manager

A desktop application built in Python that allows users to securely store, retrieve, and generate strong passwords locally without relying on cloud-based services.

---

## Project Overview

Most users manage multiple passwords across different platforms, making it difficult to remember secure and unique credentials. Cloud-based password managers raise security and privacy concerns, while manual methods such as notebooks are inconvenient and insecure.

This project aims to provide a **simple, secure, and local-only password manager** that allows users to store login credentials safely, generate strong passwords, and quickly retrieve them when needed — all without requiring internet access or external accounts.

---

## Requirements

### System Requirements

- **macOS**: 10.13 or later (tested on macOS Tahoe 26.3.1)
- **Windows**: Windows 10 or later
- **Python**: 3.13 or higher

### Python Dependencies

- `customtkinter` — graphical user interface
- `cryptography` — AES-256 vault encryption

---

## Installation

All commands should be run in the **VSCode terminal** (`Ctrl + ~` on Windows, `Ctrl + `` on Mac).

**1. Clone the repository**

```bash
git clone https://github.com/your-repo/Secure-Password-Manager.git
```

**2. Create and activate a virtual environment**

```bash
# macOS
python3.13 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

**3. Install dependencies**

```bash
# macOS
pip3 install customtkinter cryptography

# Windows
pip install customtkinter cryptography
```

**4. Run the app**

```bash
# macOS
python3 master_password_screen.py

# Windows
python master_password_screen.py
```

> **Note:** Every time you open a new VSCode terminal you must activate the virtual environment first before running the app.
