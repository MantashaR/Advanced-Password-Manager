# 🔐 Advanced Password Manager

A secure, **offline**, encrypted password manager for the terminal — written in pure Python.

Everything lives in a single encrypted vault file on your machine. Your passwords are
protected by a master password and never leave your computer.

---

## ✨ Features

- **Strong encryption** — vault encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
- **Master-password authentication** — the key is derived from your master password with
  PBKDF2-HMAC-SHA256 (600,000 iterations, random per-vault salt) and is *never stored*.
- **Cryptographically strong password generation** — uses Python's `secrets` CSPRNG with
  configurable length, character classes, and ambiguous-character avoidance.
- **Password strength meter** — instant heuristic feedback on any password.
- **Full credential management** — add, view, update, delete, and search entries.
- **Reveal-on-demand** — passwords are masked by default and only shown when you ask.
- **Clipboard support** — copy a password without it touching the screen (optional).
- **Atomic, crash-safe saves** — the vault is never left half-written.
- **Graceful UI** — a polished interface with [`rich`](https://github.com/Textualize/rich),
  and a plain-text fallback if `rich` isn't installed.

---

## 🔒 Security design

| Layer | Choice | Why |
|-------|--------|-----|
| Key derivation | PBKDF2-HMAC-SHA256, 600k iterations, 16-byte random salt | Slows brute-force; OWASP-recommended floor |
| Encryption | Fernet (AES-128-CBC + HMAC) | Authenticated encryption — detects tampering |
| Master-password check | Decrypt a stored verifier token | No password or hash stored in plaintext |
| Password generation | `secrets` module | True CSPRNG, never the predictable `random` |
| At rest | Single opaque encrypted file | Nothing readable on disk |

> The plaintext of your passwords only exists in memory while the program is running.

---

## 🚀 Getting started

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run it

```bash
python password_manager.py
```

On first run it offers to create a new vault and asks you to set a master password.
On later runs it asks for that master password to unlock the vault.

### 3. One-shot password generator (no vault needed)

```bash
python password_manager.py gen --length 24
python password_manager.py gen --length 16 --no-symbols
```

### Custom vault location

```bash
python password_manager.py --file ./my-vault.pm
```

---

## 🖥️ Menu

```
[1] List entries        [2] View / reveal entry
[3] Add entry           [4] Generate password
[5] Update entry        [6] Delete entry
[7] Search              [8] Change master password
[0] Quit
```

---

## 🧪 Testing

The project ships with a full [pytest](https://pytest.org) suite (36 tests) covering
generation, the strength meter, key derivation, vault auth, CRUD, encryption-at-rest,
and the CLI.

```bash
pip install -r requirements-dev.txt
pytest
```

In **VS Code**, the included `.vscode/` config enables the Test Explorer and one-click
Run/Debug — just open the folder and pick a configuration from the Run panel.

---

## ⚠️ Important

- **There is no password recovery.** If you forget your master password, the vault
  cannot be decrypted — by design. Keep a backup of the master password somewhere safe.
- **Never commit your vault file.** The included `.gitignore` already excludes `*.pm`
  and similar files.
- This is a learning/portfolio project. It is solid, but for protecting truly critical
  secrets prefer an audited manager (Bitwarden, KeePassXC, 1Password).

---

## 🛠️ Tech stack

- Python 3.10+
- [`cryptography`](https://cryptography.io/) — encryption & key derivation
- [`rich`](https://github.com/Textualize/rich) — terminal UI
- [`pyperclip`](https://github.com/asweigart/pyperclip) — clipboard (optional)

---

## 📄 License

[MIT](LICENSE)
