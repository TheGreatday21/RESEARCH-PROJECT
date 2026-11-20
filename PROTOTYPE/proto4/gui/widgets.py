"""Reusable Tkinter/ttk widgets for LAPA GUI: StatusChip, StepBlock,
JsonViewer, ResultTable, Tooltip."""

from __future__ import annotations

import json
import tkinter as tk
from collections.abc import Callable, Sequence
from tkinter import ttk
from typing import Any

from gui.runner import format_cell_value
from gui.theme import (
    BG_ENTRY,
    BG_WINDOW,
    PRIMARY,
    STATUS_FAIL,
    STATUS_FAIL_BG,
    STATUS_IDLE,
    STATUS_IDLE_BG,
    STATUS_PASS,
    STATUS_PASS_BG,
    STATUS_RUNNING,
    STATUS_RUNNING_BG,
    STATUS_WARN,
    STATUS_WARN_BG,
    TEXT_COLOR,
)

STATUS_SPECS: dict[str, tuple[str, str, str]] = {
    "idle": ("○ Not run", STATUS_IDLE, STATUS_IDLE_BG),
    "running": ("● Running…", STATUS_RUNNING, STATUS_RUNNING_BG),
    "pass": ("✓ Passed", STATUS_PASS, STATUS_PASS_BG),
    "warn": ("▲ Warning", STATUS_WARN, STATUS_WARN_BG),
    "fail": ("✗ Failed", STATUS_FAIL, STATUS_FAIL_BG),
    "cancelled": ("✗ Cancelled", STATUS_FAIL, STATUS_FAIL_BG),
}


class Tooltip:
    """Display a small hover tooltip near a widget."""

    def __init__(self, widget: tk.Widget, text: str, font_family: str = "Helvetica") -> None:
        self.widget = widget
        self.text = text
        self.font_family = font_family
        self._tip_window: tk.Toplevel | None = None
        widget.bind("<Enter>", self._on_enter, add="+")
        widget.bind("<Leave>", self._on_leave, add="+")

    ## creating a function that shows the tooltip window when the mouse enters the widget
    def _on_enter(self, _event: tk.Event[Any] | None = None) -> None:
        if self._tip_window is not None or not self.text:
            return
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            justify="left",
            background="#0e3a47",
            foreground="#ffffff",
            relief="solid",
            borderwidth=1,
            font=(self.font_family, 10),
            padx=8,
            pady=5,
            wraplength=420,
        )
        label.pack()
        self._tip_window = tw

    ## creating a function that hides the tooltip window when the mouse leaves the widget
    def _on_leave(self, _event: tk.Event[Any] | None = None) -> None:
        if self._tip_window is not None:
            self._tip_window.destroy()
            self._tip_window = None


class StatusChip(tk.Label):
    """Colored badge pairing a symbol and word (✓ Passed, ▲ Warning, ✗
    Failed, ● Running…, ○ Not run)."""

    def __init__(self, master: tk.Misc, font_family: str = "Helvetica") -> None:
        super().__init__(
            master,
            text="○ Not run",
            fg=STATUS_IDLE,
            bg=STATUS_IDLE_BG,
            font=(font_family, 10, "bold"),
            padx=10,
            pady=3,
            relief="solid",
            bd=1,
            highlightthickness=0,
        )
        self.set_status("idle")

    ## creating a function that updates the status chip symbol, word, and color pair
    def set_status(self, state: str, custom_text: str | None = None) -> None:
        text, fg, bg = STATUS_SPECS.get(state, STATUS_SPECS["idle"])
        self.configure(text=custom_text or text, fg=fg, bg=bg)


class ResultTable(ttk.Frame):
    """Treeview table with vertical and horizontal scrollbars and status color tags."""

    def __init__(
        self,
        master: tk.Misc,
        columns: Sequence[tuple[str, str, int]] = (),
        height: int = 6,
        on_select: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        super().__init__(master)
        self._on_select = on_select
        self._row_payloads: dict[str, dict[str, Any]] = {}

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        col_ids = [col[0] for col in columns]
        self.tree = ttk.Treeview(
            self,
            columns=col_ids,
            show="headings",
            height=height,
            selectmode="browse",
        )
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        self.hsb.grid(row=1, column=0, sticky="ew")

        self.tree.tag_configure("pass", foreground=STATUS_PASS)
        self.tree.tag_configure("warn", foreground="#9c6500", background=STATUS_WARN_BG)
        self.tree.tag_configure("fail", foreground=STATUS_FAIL, background=STATUS_FAIL_BG)

        if columns:
            self.set_columns(columns)

        if on_select is not None:
            self.tree.bind("<<TreeviewSelect>>", self._handle_select)

    ## creating a function that configures column headers and widths on the Treeview
    def set_columns(self, columns: Sequence[tuple[str, str, int]]) -> None:
        self.clear()
        col_ids = [col[0] for col in columns]
        self.tree.configure(columns=col_ids)
        for col_id, heading, width in columns:
            self.tree.heading(col_id, text=heading, anchor="w")
            self.tree.column(col_id, width=width, minwidth=60, anchor="w", stretch=True)

    ## creating a function that clears all rows from the table
    def clear(self) -> None:
        self._row_payloads.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

    ## creating a function that inserts one row with an optional status tag and attached payload
    def add_row(
        self,
        values: Sequence[Any],
        *,
        tag: str = "",
        payload: dict[str, Any] | None = None,
    ) -> str:
        formatted = [format_cell_value(v) for v in values]
        tags = (tag,) if tag else ()
        item_id = self.tree.insert("", "end", values=formatted, tags=tags)
        if payload is not None:
            self._row_payloads[item_id] = payload
        return item_id

    def _handle_select(self, _event: tk.Event[Any] | None = None) -> None:
        if self._on_select is None:
            return
        selected = self.tree.selection()
        if not selected:
            return
        payload = self._row_payloads.get(selected[0])
        if payload is not None:
            self._on_select(payload)


class JsonViewer(ttk.Frame):
    """Collapsible 'Show technical details' panel revealing raw JSON and a
    key/value tree fallback."""

    def __init__(self, master: tk.Misc, font_family: str = "Helvetica") -> None:
        super().__init__(master)
        self.font_family = font_family
        self._expanded = False
        self.columnconfigure(0, weight=1)

        self.toggle_btn = ttk.Button(
            self,
            text="▸ Show technical details (raw JSON)",
            style="Secondary.TButton",
            command=self.toggle,
        )
        self.toggle_btn.grid(row=0, column=0, sticky="w", pady=(4, 2))

        self.body = ttk.Frame(self)
        self.body.columnconfigure(0, weight=1)
        self.body.columnconfigure(1, weight=1)

        # Left: structured key/value tree for any JSON shape
        self.kv_tree = ttk.Treeview(
            self.body,
            columns=("value",),
            show="tree headings",
            height=7,
        )
        self.kv_tree.heading("#0", text="Key / Path", anchor="w")
        self.kv_tree.heading("value", text="Value", anchor="w")
        self.kv_tree.column("#0", width=220, anchor="w")
        self.kv_tree.column("value", width=320, anchor="w")
        self.kv_tree.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=2)

        # Right: raw JSON text box
        text_frame = ttk.Frame(self.body)
        text_frame.grid(row=0, column=1, sticky="nsew", pady=2)
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        self.text_box = tk.Text(
            text_frame,
            height=7,
            state=tk.DISABLED,
            font=("Menlo" if font_family != "Consolas" else "Consolas", 10),
            fg=TEXT_COLOR,
            bg=BG_ENTRY,
            relief="solid",
            bd=1,
            highlightthickness=0,
            wrap="none",
        )
        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=self.text_box.yview)
        self.text_box.configure(yscrollcommand=vsb.set)
        self.text_box.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

    ## creating a function that toggles the technical details drawer open or closed
    def toggle(self) -> None:
        self._expanded = not self._expanded
        if self._expanded:
            self.toggle_btn.configure(text="▾ Hide technical details (raw JSON)")
            self.body.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        else:
            self.toggle_btn.configure(text="▸ Show technical details (raw JSON)")
            self.body.grid_remove()

    ## creating a function that loads a JSON object or raw string into the technical details view
    def set_data(self, data: Any, raw_fallback: str = "") -> None:
        for item in self.kv_tree.get_children():
            self.kv_tree.delete(item)

        if data is not None:
            formatted = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
            self._populate_tree("", data)
        else:
            formatted = raw_fallback or "(No JSON output)"

        self.text_box.configure(state=tk.NORMAL)
        self.text_box.delete("1.0", tk.END)
        self.text_box.insert("1.0", formatted)
        self.text_box.configure(state=tk.DISABLED)

    def _populate_tree(self, parent: str, value: Any, key_name: str = "root") -> None:
        if isinstance(value, dict):
            node = (
                parent
                if parent == "" and key_name == "root"
                else self.kv_tree.insert(
                    parent, "end", text=key_name, values=("{...}",), open=(parent == "")
                )
            )
            for k, v in value.items():
                self._populate_tree(node, v, str(k))
        elif isinstance(value, list):
            node = self.kv_tree.insert(
                parent, "end", text=key_name, values=(f"[{len(value)} items]",), open=False
            )
            for idx, item in enumerate(value[:100]):
                self._populate_tree(node, item, f"[{idx}]")
        else:
            self.kv_tree.insert(parent, "end", text=key_name, values=(format_cell_value(value),))


class StepBlock(ttk.LabelFrame):
    """Standard visual block used for every pipeline step across all three pages."""

    def __init__(
        self,
        master: tk.Misc,
        title: str,
        description: str,
        on_run: Callable[[], None],
        *,
        run_label: str = "Run",
        font_family: str = "Helvetica",
    ) -> None:
        super().__init__(master, text=title, padding=10)
        self.font_family = font_family
        self._on_run = on_run
        self._busy = False
        self._locked = False

        self.columnconfigure(0, weight=1)

        # Top row: plain-English description on the left, status chip + Run button on the right
        top_bar = ttk.Frame(self)
        top_bar.grid(row=0, column=0, sticky="ew")
        top_bar.columnconfigure(0, weight=1)

        self.desc_label = ttk.Label(
            top_bar,
            text=description,
            style="TLabel",
            wraplength=680,
            justify="left",
        )
        self.desc_label.grid(row=0, column=0, sticky="w", padx=(0, 12))

        self.chip = StatusChip(top_bar, font_family=font_family)
        self.chip.grid(row=0, column=1, padx=(0, 10), sticky="e")

        self.run_btn = ttk.Button(
            top_bar,
            text=run_label,
            style="Primary.TButton",
            command=self._on_run,
            width=14,
        )
        self.run_btn.grid(row=0, column=2, sticky="e")

        # Optional controls bar (spinboxes, file pickers, checkboxes)
        self.controls_frame = ttk.Frame(self)
        self.controls_frame.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.controls_frame.grid_remove()

        # Status / error banner (hidden until set)
        self.banner = tk.Label(
            self,
            text="",
            anchor="w",
            justify="left",
            font=(font_family, 10, "bold"),
            padx=10,
            pady=5,
            relief="solid",
            bd=1,
            wraplength=860,
        )
        self.banner.grid(row=2, column=0, sticky="ew", pady=(6, 2))
        self.banner.grid_remove()

        # Result area (populated by each step)
        self.result_area = ttk.Frame(self)
        self.result_area.grid(row=3, column=0, sticky="ew", pady=(4, 2))
        self.result_area.columnconfigure(0, weight=1)

        # Collapsible technical details toggle
        self.json_viewer = JsonViewer(self, font_family=font_family)
        self.json_viewer.grid(row=4, column=0, sticky="ew", pady=(4, 0))

    ## creating a function that reveals the extra controls row inside a StepBlock
    def enable_controls_bar(self) -> ttk.Frame:
        self.controls_frame.grid()
        return self.controls_frame

    ## creating a function that shows a colored banner inside the step block
    def show_banner(self, message: str, kind: str = "info") -> None:
        if not message:
            self.banner.grid_remove()
            return
        palette = {
            "pass": (STATUS_PASS, STATUS_PASS_BG),
            "warn": ("#8a5a00", STATUS_WARN_BG),
            "fail": (STATUS_FAIL, STATUS_FAIL_BG),
            "info": (PRIMARY, STATUS_RUNNING_BG),
        }
        fg, bg = palette.get(kind, palette["info"])
        self.banner.configure(text=message, fg=fg, bg=bg)
        self.banner.grid()

    ## creating a function that hides the step banner
    def clear_banner(self) -> None:
        self.banner.grid_remove()

    ## creating a function that disables or re-enables the Run button when busy or locked
    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._refresh_button_state()

    ## creating a function that locks or unlocks the step based on verification gating
    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        self._refresh_button_state()

    def _refresh_button_state(self) -> None:
        if self._busy or self._locked:
            self.run_btn.configure(state=tk.DISABLED)
        else:
            self.run_btn.configure(state=tk.NORMAL)


class ScrollablePage(ttk.Frame):
    """Vertical scrollable container so multi-step pages fit comfortably at 1000x700."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, style="Window.TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.canvas = tk.Canvas(self, bg=BG_WINDOW, highlightthickness=0, bd=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")

        self.content = ttk.Frame(self.canvas, style="Window.TFrame", padding=10)
        self.content.columnconfigure(0, weight=1)
        self._window_id = self.canvas.create_window((0, 0), window=self.content, anchor="nw")

        self.content.bind("<Configure>", self._on_content_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

    def _on_content_configure(self, _event: tk.Event[Any]) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event: tk.Event[Any]) -> None:
        self.canvas.itemconfigure(self._window_id, width=event.width)
