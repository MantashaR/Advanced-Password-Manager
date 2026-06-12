"""
Advanced Password Manager
==========================

A secure, offline password manager for the terminal.

Security design
---------------
* The vault is encrypted with Fernet (AES-128-CBC + HMAC-SHA256) from the
  `cryptography` library.
* The encryption key is derived from the user's master password using
  PBKDF2-HMAC-SHA256 with a random 16-byte salt and 600,000 iterations
  (OWASP-recommended floor), so the key is never stored on disk.
* Master-password authentication works by decrypting a "verifier" token that
  is written at vault-creation time. A wrong password fails to decrypt it.
* Generated passwords use the `secrets` module (CSPRNG), never `random`.

The plaintext of your passwords only ever exists in memory while the program
runs. On disk there is a single opaque, encrypted vault file.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import secrets
import string
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich import box

    _RICH = True
    console = Console()
except ImportError:  # pragma: no cover - graceful fallback if rich is missing
    _RICH = False
    console = None


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_VAULT = Path.home() / ".vault.pm"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
VERIFIER_PLAINTEXT = b"password-manager-verifier-v1"


# --------------------------------------------------------------------------- #
# Cryptography
# --------------------------------------------------------------------------- #

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a URL-safe base64 Fernet key from the master password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Entry:
    """A single stored credential."""

    name: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created: str = ""
    updated: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Vault
# --------------------------------------------------------------------------- #

class Vault:
    """
    Manages the encrypted vault file.

    On-disk layout (JSON, the only plaintext part is the salt + verifier so we
    can derive the key and authenticate the master password):

        {
            "version": 1,
            "salt": "<base64>",
            "verifier": "<fernet token>",
            "data": "<fernet token of the JSON entries blob>"
        }
    """

    VERSION = 1

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fernet: Fernet | None = None
        self.entries: dict[str, Entry] = {}

    # -- lifecycle --------------------------------------------------------- #

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, master_password: str) -> None:
        """Initialise a brand-new empty vault protected by `master_password`."""
        salt = os.urandom(SALT_BYTES)
        key = derive_key(master_password, salt)
        self._fernet = Fernet(key)
        self.entries = {}
        verifier = self._fernet.encrypt(VERIFIER_PLAINTEXT)
        self._write(salt, verifier)

    def unlock(self, master_password: str) -> bool:
        """Load the vault and verify the master password. Returns success."""
        blob = json.loads(self.path.read_text(encoding="utf-8"))
        salt = base64.b64decode(blob["salt"])
        key = derive_key(master_password, salt)
        fernet = Fernet(key)
        try:
            if fernet.decrypt(blob["verifier"].encode()) != VERIFIER_PLAINTEXT:
                return False
        except InvalidToken:
            return False

        self._fernet = fernet
        raw = fernet.decrypt(blob["data"].encode())
        records = json.loads(raw.decode("utf-8"))
        self.entries = {name: Entry(**rec) for name, rec in records.items()}
        return True

    # -- persistence ------------------------------------------------------- #

    def _write(self, salt: bytes, verifier: bytes) -> None:
        assert self._fernet is not None
        records = {name: e.to_dict() for name, e in self.entries.items()}
        data_token = self._fernet.encrypt(
            json.dumps(records).encode("utf-8")
        )
        blob = {
            "version": self.VERSION,
            "salt": base64.b64encode(salt).decode(),
            "verifier": verifier.decode(),
            "data": data_token.decode(),
        }
        # Write atomically so a crash never corrupts the vault.
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(blob), encoding="utf-8")
        os.replace(tmp, self.path)

    def save(self) -> None:
        """Re-encrypt and persist, preserving salt + verifier."""
        blob = json.loads(self.path.read_text(encoding="utf-8"))
        salt = base64.b64decode(blob["salt"])
        verifier = blob["verifier"].encode()
        self._write(salt, verifier)

    # -- operations -------------------------------------------------------- #

    def add(self, entry: Entry) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry.created = now
        entry.updated = now
        self.entries[entry.name] = entry
        self.save()

    def update(self, name: str, **fields) -> bool:
        entry = self.entries.get(name)
        if entry is None:
            return False
        for key, value in fields.items():
            if value is not None and hasattr(entry, key):
                setattr(entry, key, value)
        entry.updated = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.save()
        return True

    def delete(self, name: str) -> bool:
        if name in self.entries:
            del self.entries[name]
            self.save()
            return True
        return False

    def get(self, name: str) -> Entry | None:
        return self.entries.get(name)

    def search(self, term: str) -> list[Entry]:
        term = term.lower()
        return [
            e for e in self.entries.values()
            if term in e.name.lower()
            or term in e.username.lower()
            or term in e.url.lower()
        ]


# --------------------------------------------------------------------------- #
# Password generation & strength
# --------------------------------------------------------------------------- #

def generate_password(
    length: int = 20,
    *,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    """Generate a cryptographically strong password using `secrets`."""
    if length < 4:
        raise ValueError("Password length must be at least 4.")

    pools: list[str] = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?/")

    if not pools:
        raise ValueError("At least one character class must be enabled.")

    if avoid_ambiguous:
        ambiguous = set("Il1O0|`'\"")
        pools = ["".join(c for c in pool if c not in ambiguous) for pool in pools]

    # Guarantee at least one character from each selected class.
    password_chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    password_chars += [
        secrets.choice(all_chars) for _ in range(length - len(password_chars))
    ]

    # Fisher-Yates shuffle with a CSPRNG so positions aren't predictable.
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def password_strength(password: str) -> tuple[str, int]:
    """Return a (label, score-0-100) heuristic strength estimate."""
    score = 0
    length = len(password)
    score += min(length * 4, 40)
    if any(c.islower() for c in password):
        score += 10
    if any(c.isupper() for c in password):
        score += 10
    if any(c.isdigit() for c in password):
        score += 15
    if any(not c.isalnum() for c in password):
        score += 20
    if len(set(password)) > length * 0.7:
        score += 5
    score = min(score, 100)

    if score < 40:
        label = "Weak"
    elif score < 70:
        label = "Fair"
    elif score < 90:
        label = "Strong"
    else:
        label = "Very Strong"
    return label, score


# --------------------------------------------------------------------------- #
# Clipboard (optional)
# --------------------------------------------------------------------------- #

def copy_to_clipboard(text: str) -> bool:
    try:
        import pyperclip

        pyperclip.copy(text)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Pretty-print helpers (work with or without `rich`)
# --------------------------------------------------------------------------- #

def info(msg: str) -> None:
    if _RICH:
        console.print(msg)
    else:
        print(msg)


def success(msg: str) -> None:
    if _RICH:
        console.print(f"[bold green]✓[/] {msg}")
    else:
        print(f"[OK] {msg}")


def error(msg: str) -> None:
    if _RICH:
        console.print(f"[bold red]✗[/] {msg}")
    else:
        print(f"[ERROR] {msg}", file=sys.stderr)


def banner() -> None:
    title = "🔐  Advanced Password Manager"
    if _RICH:
        console.print(Panel.fit(title, style="bold cyan", box=box.DOUBLE))
    else:
        print("=" * 40)
        print(title)
        print("=" * 40)


def show_entry(entry: Entry, reveal: bool = False) -> None:
    label, score = password_strength(entry.password)
    pwd = entry.password if reveal else "•" * 12
    if _RICH:
        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Name", entry.name)
        table.add_row("Username", entry.username)
        table.add_row("Password", pwd)
        table.add_row("Strength", f"{label} ({score}/100)")
        if entry.url:
            table.add_row("URL", entry.url)
        if entry.notes:
            table.add_row("Notes", entry.notes)
        table.add_row("Updated", entry.updated or "-")
        console.print(table)
    else:
        print(f"  Name     : {entry.name}")
        print(f"  Username : {entry.username}")
        print(f"  Password : {pwd}")
        print(f"  Strength : {label} ({score}/100)")
        if entry.url:
            print(f"  URL      : {entry.url}")
        if entry.notes:
            print(f"  Notes    : {entry.notes}")
        print(f"  Updated  : {entry.updated or '-'}")


def list_entries(vault: Vault) -> None:
    if not vault.entries:
        info("Vault is empty. Add an entry to get started.")
        return
    if _RICH:
        table = Table(title="Stored Credentials", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Name", style="bold cyan")
        table.add_column("Username", style="white")
        table.add_column("URL", style="blue")
        table.add_column("Updated", style="dim")
        for i, e in enumerate(sorted(vault.entries.values(), key=lambda x: x.name), 1):
            table.add_row(str(i), e.name, e.username, e.url or "-", e.updated or "-")
        console.print(table)
    else:
        print("\nStored Credentials")
        print("-" * 60)
        for i, e in enumerate(sorted(vault.entries.values(), key=lambda x: x.name), 1):
            print(f"{i:>3}. {e.name:<20} {e.username:<20} {e.url}")


# --------------------------------------------------------------------------- #
# Prompts
# --------------------------------------------------------------------------- #

def ask(prompt: str, default: str = "") -> str:
    if _RICH:
        return Prompt.ask(prompt, default=default)
    raw = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return raw or default


def ask_secret(prompt: str) -> str:
    return getpass.getpass(f"{prompt}: ")


def confirm(prompt: str) -> bool:
    if _RICH:
        return Confirm.ask(prompt, default=False)
    return input(f"{prompt} [y/N]: ").strip().lower() in {"y", "yes"}


# --------------------------------------------------------------------------- #
# Authentication flow
# --------------------------------------------------------------------------- #

def open_vault(path: Path) -> Vault | None:
    """Create or unlock a vault, returning an unlocked Vault or None on failure."""
    vault = Vault(path)

    if not vault.exists():
        info(f"No vault found at [bold]{path}[/]." if _RICH else f"No vault found at {path}.")
        if not confirm("Create a new vault here?"):
            return None
        while True:
            pw1 = ask_secret("Choose a master password")
            if len(pw1) < 8:
                error("Master password must be at least 8 characters.")
                continue
            label, score = password_strength(pw1)
            info(f"Master password strength: {label} ({score}/100)")
            pw2 = ask_secret("Confirm master password")
            if pw1 != pw2:
                error("Passwords do not match. Try again.")
                continue
            break
        vault.create(pw1)
        success(f"Vault created at {path}")
        return vault

    # Existing vault: authenticate (3 attempts).
    for attempt in range(3):
        pw = ask_secret("Master password")
        if vault.unlock(pw):
            success("Vault unlocked.")
            return vault
        error(f"Incorrect master password ({2 - attempt} attempt(s) left).")
    error("Too many failed attempts. Exiting.")
    return None


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #

MENU = """
[1] List entries        [2] View / reveal entry
[3] Add entry           [4] Generate password
[5] Update entry        [6] Delete entry
[7] Search              [8] Change master password
[0] Quit
"""


def action_add(vault: Vault) -> None:
    name = ask("Entry name (e.g. github)")
    if not name:
        error("Name is required.")
        return
    if name in vault.entries and not confirm(f"'{name}' exists. Overwrite?"):
        return
    username = ask("Username / email")
    if confirm("Generate a strong password?"):
        length = int(ask("Length", "20") or "20")
        password = generate_password(length)
        info(f"Generated: [bold green]{password}[/]" if _RICH else f"Generated: {password}")
    else:
        password = ask_secret("Password")
    url = ask("URL (optional)")
    notes = ask("Notes (optional)")
    vault.add(Entry(name=name, username=username, password=password, url=url, notes=notes))
    success(f"Saved '{name}'.")


def action_view(vault: Vault) -> None:
    name = ask("Entry name to view")
    entry = vault.get(name)
    if not entry:
        error(f"No entry named '{name}'.")
        return
    reveal = confirm("Reveal password?")
    show_entry(entry, reveal=reveal)
    if reveal and confirm("Copy password to clipboard?"):
        if copy_to_clipboard(entry.password):
            success("Password copied to clipboard.")
        else:
            error("Clipboard unavailable (install 'pyperclip').")


def action_generate(_: Vault) -> None:
    length = int(ask("Length", "20") or "20")
    symbols = confirm("Include symbols?")
    pwd = generate_password(length, use_symbols=symbols)
    label, score = password_strength(pwd)
    if _RICH:
        console.print(Panel(f"[bold green]{pwd}[/]\n\nStrength: {label} ({score}/100)",
                            title="Generated Password", box=box.ROUNDED))
    else:
        print(f"\n{pwd}\nStrength: {label} ({score}/100)")
    if confirm("Copy to clipboard?"):
        if copy_to_clipboard(pwd):
            success("Copied to clipboard.")
        else:
            error("Clipboard unavailable (install 'pyperclip').")


def action_update(vault: Vault) -> None:
    name = ask("Entry name to update")
    if not vault.get(name):
        error(f"No entry named '{name}'.")
        return
    info("Leave a field blank to keep its current value.")
    username = ask("New username") or None
    change_pw = confirm("Change password?")
    password = None
    if change_pw:
        if confirm("Generate a new strong password?"):
            password = generate_password(int(ask("Length", "20") or "20"))
            info(f"Generated: [bold green]{password}[/]" if _RICH else f"Generated: {password}")
        else:
            password = ask_secret("New password")
    url = ask("New URL") or None
    notes = ask("New notes") or None
    vault.update(name, username=username, password=password, url=url, notes=notes)
    success(f"Updated '{name}'.")


def action_delete(vault: Vault) -> None:
    name = ask("Entry name to delete")
    if not vault.get(name):
        error(f"No entry named '{name}'.")
        return
    if confirm(f"Permanently delete '{name}'?"):
        vault.delete(name)
        success(f"Deleted '{name}'.")


def action_search(vault: Vault) -> None:
    term = ask("Search term")
    results = vault.search(term)
    if not results:
        info("No matches.")
        return
    for e in results:
        show_entry(e, reveal=False)


def action_change_master(vault: Vault) -> None:
    if not confirm("Change the master password for this vault?"):
        return
    current = ask_secret("Current master password")
    if not vault.unlock(current):
        error("Current master password is incorrect.")
        return
    while True:
        pw1 = ask_secret("New master password")
        if len(pw1) < 8:
            error("Must be at least 8 characters.")
            continue
        if pw1 != ask_secret("Confirm new master password"):
            error("Passwords do not match.")
            continue
        break
    # Re-create the crypto material with a fresh salt, keep the entries.
    entries = vault.entries
    vault.create(pw1)
    vault.entries = entries
    vault.save()
    success("Master password changed.")


ACTIONS = {
    "1": lambda v: list_entries(v),
    "2": action_view,
    "3": action_add,
    "4": action_generate,
    "5": action_update,
    "6": action_delete,
    "7": action_search,
    "8": action_change_master,
}


def interactive(vault: Vault) -> None:
    while True:
        info(MENU)
        choice = ask("Choose an option", "0").strip()
        if choice == "0":
            info("Locking vault. Goodbye! 👋")
            return
        action = ACTIONS.get(choice)
        if action is None:
            error("Invalid choice.")
            continue
        try:
            action(vault)
        except (ValueError, KeyboardInterrupt) as exc:
            error(str(exc) or "Cancelled.")


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Advanced Password Manager — secure, offline, encrypted.",
    )
    parser.add_argument(
        "-f", "--file", type=Path, default=DEFAULT_VAULT,
        help=f"Path to the vault file (default: {DEFAULT_VAULT})",
    )
    sub = parser.add_subparsers(dest="command")

    gen = sub.add_parser("gen", help="Generate a password and exit (no vault needed).")
    gen.add_argument("-l", "--length", type=int, default=20)
    gen.add_argument("--no-symbols", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Quick one-shot generator that doesn't require unlocking a vault.
    if args.command == "gen":
        pwd = generate_password(args.length, use_symbols=not args.no_symbols)
        label, score = password_strength(pwd)
        print(pwd)
        info(f"Strength: {label} ({score}/100)")
        return 0

    banner()
    try:
        vault = open_vault(args.file)
    except KeyboardInterrupt:
        print()
        return 130
    if vault is None:
        return 1

    try:
        interactive(vault)
    except KeyboardInterrupt:
        print()
        info("Locking vault. Goodbye! 👋")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
