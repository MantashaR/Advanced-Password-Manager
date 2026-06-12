"""
Render a terminal-style screenshot of the password manager UI to an SVG.

This drives the app's real `rich` rendering functions with sample (fake) data
and exports the result, so the screenshot always matches the actual interface.
Run:  python docs/generate_screenshot.py
"""

import io
import sys
from pathlib import Path

# Make the project root importable when run from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich import box

import password_manager as pm

# Route all of the app's output through a recording console whose output goes
# to an in-memory buffer (so it doesn't hit the real terminal's encoding).
rec = Console(
    record=True,
    width=78,
    file=io.StringIO(),
    force_terminal=True,
    legacy_windows=False,
)
pm.console = rec
pm._RICH = True

# 1. Banner
pm.banner()

# 2. A populated vault listing (sample data — not real credentials)
vault = pm.Vault(Path("demo.pm"))
vault.entries = {
    "github": pm.Entry("github", "mantasha", "x", "github.com", updated="2026-06-12"),
    "gmail": pm.Entry("gmail", "mantasha@gmail.com", "x", "mail.google.com", updated="2026-06-10"),
    "aws": pm.Entry("aws", "admin", "x", "console.aws.amazon.com", updated="2026-06-01"),
}
pm.list_entries(vault)

# 3. A generated-password panel
pwd = pm.generate_password(20)
label, score = pm.password_strength(pwd)
rec.print(Panel(f"[bold green]{pwd}[/]\n\nStrength: {label} ({score}/100)",
                title="Generated Password", box=box.ROUNDED))

# 4. The main menu
rec.print(pm.MENU)

out = Path(__file__).resolve().parent / "screenshot.svg"
rec.save_svg(str(out), title="Advanced Password Manager")
print(f"Wrote {out}")
