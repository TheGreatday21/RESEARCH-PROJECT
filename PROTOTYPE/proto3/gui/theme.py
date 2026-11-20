"""Teal color palette, font selection, and ttk style configuration for LAPA GUI."""

from __future__ import annotations

import contextlib
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

## COLOR DESIGNS FOR THE GUI (Teal range #1a81a3 to #2bc2c4)
PRIMARY = "#1a81a3"  # Headers and main action buttons
ACCENT = "#2bc2c4"  # Hover accent, progress bar, active tab
PRIMARY_HOVER = "#146a85"  # Button hover / pressed teal
BG_WINDOW = "#f2fafb"  # General window background
BG_FRAME = "#e3f4f6"  # Section / LabelFrame background
BG_ENTRY = "#ffffff"  # Text box, entry, and table background
TEXT_COLOR = "#0e3a47"  # Main text and headers
TEXT_MUTED = "#4a7380"  # Secondary description text
BORDER_COLOR = "#a9d8de"  # Frame and input borders
BUTTON_TEXT = "#ffffff"  # White text on primary buttons

## STATUS COLORS (Always paired with symbol + word: ✓ Passed, ▲ Warning, ✗ Failed, ● Running, ○ Not
## run)
STATUS_PASS = "#2f9e44"
STATUS_PASS_BG = "#e6f4ea"
STATUS_WARN = "#e8a317"
STATUS_WARN_BG = "#fef7e0"
STATUS_FAIL = "#c92a2a"
STATUS_FAIL_BG = "#fce8e6"
STATUS_RUNNING = "#1a81a3"
STATUS_RUNNING_BG = "#d9f2f7"
STATUS_IDLE = "#5b7c85"
STATUS_IDLE_BG = "#e8f1f3"

PREFERRED_FONTS = ("Calibri", "Segoe UI", "Helvetica Neue", "DejaVu Sans", "Helvetica")


## creating a function that picks the first installed font family from our preferred list
def pick_font_family(root: tk.Misc) -> str:
    try:
        available = set(tkfont.families(root))
    except tk.TclError:
        return "Helvetica"
    for family in PREFERRED_FONTS:
        if family in available:
            return family
    return "Helvetica"


## creating a function that configures all ttk widget styles using the clam theme and teal palette
def apply_theme(root: tk.Tk) -> tuple[ttk.Style, str]:
    root.configure(bg=BG_WINDOW)
    font_family = pick_font_family(root)

    style = ttk.Style(root)
    with contextlib.suppress(tk.TclError):
        style.theme_use("clam")

    font_regular = (font_family, 11)
    font_bold = (font_family, 11, "bold")
    font_small = (font_family, 10)
    font_title = (font_family, 12, "bold")

    # Global background and text defaults
    style.configure(".", background=BG_WINDOW, foreground=TEXT_COLOR, font=font_regular)
    style.configure("TFrame", background=BG_FRAME)
    style.configure("Window.TFrame", background=BG_WINDOW)
    style.configure("Card.TFrame", background=BG_ENTRY, relief="solid", borderwidth=1)

    # LabelFrame styling
    style.configure(
        "TLabelframe",
        background=BG_FRAME,
        bordercolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        relief="solid",
        borderwidth=1,
    )
    style.configure(
        "TLabelframe.Label",
        background=BG_FRAME,
        foreground=PRIMARY,
        font=font_bold,
    )

    # Label variants
    style.configure("TLabel", background=BG_FRAME, foreground=TEXT_COLOR, font=font_regular)
    style.configure("Window.TLabel", background=BG_WINDOW, foreground=TEXT_COLOR, font=font_regular)
    style.configure("Header.TLabel", background=BG_FRAME, foreground=PRIMARY, font=font_title)
    style.configure("Muted.TLabel", background=BG_FRAME, foreground=TEXT_MUTED, font=font_small)
    style.configure("Bold.TLabel", background=BG_FRAME, foreground=TEXT_COLOR, font=font_bold)

    # Primary Teal Button (#1a81a3) - solid flat appearance without borders
    style.configure(
        "Primary.TButton",
        background=PRIMARY,
        foreground=BUTTON_TEXT,
        font=font_bold,
        borderwidth=0,
        relief="flat",
        bordercolor=PRIMARY,
        lightcolor=PRIMARY,
        darkcolor=PRIMARY,
        focusthickness=0,
        focuscolor="none",
        padding=(12, 6),
    )
    style.map(
        "Primary.TButton",
        background=[("active", PRIMARY_HOVER), ("pressed", PRIMARY_HOVER), ("disabled", "#c5dce2")],
        foreground=[("disabled", "#6d8c94")],
        bordercolor=[("active", PRIMARY_HOVER), ("disabled", "#c5dce2")],
        lightcolor=[("active", PRIMARY_HOVER), ("disabled", "#c5dce2")],
        darkcolor=[("active", PRIMARY_HOVER), ("disabled", "#c5dce2")],
    )

    # Accent Cyan-Teal Button (#2bc2c4) - solid flat appearance for pipeline / primary CTAs
    style.configure(
        "Accent.TButton",
        background=ACCENT,
        foreground="#072b35",
        font=font_bold,
        borderwidth=0,
        relief="flat",
        bordercolor=ACCENT,
        lightcolor=ACCENT,
        darkcolor=ACCENT,
        focusthickness=0,
        focuscolor="none",
        padding=(12, 6),
    )
    style.map(
        "Accent.TButton",
        background=[("active", PRIMARY), ("pressed", PRIMARY_HOVER), ("disabled", "#c5dce2")],
        foreground=[("active", BUTTON_TEXT), ("pressed", BUTTON_TEXT), ("disabled", "#6d8c94")],
        bordercolor=[("active", PRIMARY), ("disabled", "#c5dce2")],
        lightcolor=[("active", PRIMARY), ("disabled", "#c5dce2")],
        darkcolor=[("active", PRIMARY), ("disabled", "#c5dce2")],
    )

    # Secondary Subtle Button
    style.configure(
        "Secondary.TButton",
        background="#cde9ed",
        foreground=TEXT_COLOR,
        font=font_regular,
        borderwidth=1,
        relief="flat",
        bordercolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        focusthickness=0,
        focuscolor="none",
        padding=(10, 5),
    )
    style.map(
        "Secondary.TButton",
        background=[("active", ACCENT), ("disabled", "#e1eff2")],
        foreground=[("active", "#072b35"), ("disabled", "#8aa4ab")],
    )

    # Danger Button (Cancel / Destructive)
    style.configure(
        "Danger.TButton",
        background=STATUS_FAIL,
        foreground=BUTTON_TEXT,
        font=font_bold,
        borderwidth=0,
        relief="flat",
        bordercolor=STATUS_FAIL,
        lightcolor=STATUS_FAIL,
        darkcolor=STATUS_FAIL,
        focusthickness=0,
        focuscolor="none",
        padding=(12, 6),
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#a61e1e"), ("disabled", "#d3d3d3")],
        foreground=[("disabled", "#808080")],
    )

    # Entry, Combobox & Spinbox styling
    style.configure(
        "TEntry",
        fieldbackground=BG_ENTRY,
        foreground=TEXT_COLOR,
        bordercolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        padding=4,
    )
    style.configure(
        "TCombobox",
        fieldbackground=BG_ENTRY,
        background=BG_ENTRY,
        foreground=TEXT_COLOR,
        arrowcolor=PRIMARY,
        bordercolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        padding=4,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", BG_ENTRY), ("disabled", "#e8f1f3")],
        selectbackground=[("readonly", PRIMARY)],
        selectforeground=[("readonly", BUTTON_TEXT)],
    )
    style.configure(
        "TSpinbox",
        fieldbackground=BG_ENTRY,
        background=BG_ENTRY,
        foreground=TEXT_COLOR,
        arrowcolor=PRIMARY,
        arrowsize=12,
        bordercolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        padding=4,
    )

    # Radiobutton & Checkbutton
    style.configure("TRadiobutton", background=BG_FRAME, foreground=TEXT_COLOR, font=font_regular)
    style.map("TRadiobutton", background=[("active", BG_FRAME)])
    style.configure("TCheckbutton", background=BG_FRAME, foreground=TEXT_COLOR, font=font_regular)
    style.map("TCheckbutton", background=[("active", BG_FRAME)])

    # Notebook tabs
    style.configure("TNotebook", background=BG_WINDOW, bordercolor=BORDER_COLOR, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background="#cde9ed",
        foreground=TEXT_COLOR,
        font=font_bold,
        padding=(16, 8),
        bordercolor=BORDER_COLOR,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", ACCENT), ("active", "#b6e2e8")],
        foreground=[("selected", "#072b35"), ("active", TEXT_COLOR)],
    )

    # Treeview tables
    style.configure(
        "Treeview",
        background=BG_ENTRY,
        fieldbackground=BG_ENTRY,
        foreground=TEXT_COLOR,
        rowheight=26,
        font=font_regular,
        bordercolor=BORDER_COLOR,
    )
    style.configure(
        "Treeview.Heading",
        background=PRIMARY,
        foreground=BUTTON_TEXT,
        font=font_bold,
        relief="flat",
        padding=(6, 5),
    )
    style.map(
        "Treeview.Heading",
        background=[("active", PRIMARY_HOVER)],
    )
    style.map(
        "Treeview",
        background=[("selected", ACCENT)],
        foreground=[("selected", "#072b35")],
    )

    # Progressbar
    style.configure(
        "Teal.Horizontal.TProgressbar",
        troughcolor=BG_FRAME,
        background=ACCENT,
        bordercolor=BORDER_COLOR,
        lightcolor=ACCENT,
        darkcolor=PRIMARY,
        thickness=16,
    )

    return style, font_family
