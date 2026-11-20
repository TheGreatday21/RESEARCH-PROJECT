"""Docker lab target controls and lab-only command builders (never imported by EC2 tools)."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any

from gui.widgets import Tooltip


## creating a function that returns the command to start the local Docker lab
def build_start_lab_command() -> list[str]:
    return ["make", "lab-up"]


## creating a function that returns the command to generate seeded traffic inside the Docker lab
def build_generate_traffic_command() -> list[str]:
    return ["make", "traffic"]


class DockerLabPanel(ttk.Frame):
    """Target sub-panel shown only when 'Docker lab' is selected."""

    def __init__(
        self,
        master: tk.Misc,
        app: Any,
        font_family: str = "Helvetica",
    ) -> None:
        super().__init__(master)
        self.app = app
        self.font_family = font_family
        self.inventory_var = tk.StringVar(value="lab/inventory.ini")

        self.columnconfigure(1, weight=1)

        ttk.Label(self, text="Ansible inventory:", style="Bold.TLabel").grid(
            row=0, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        self.inv_entry = ttk.Entry(self, textvariable=self.inventory_var)
        self.inv_entry.grid(row=0, column=1, padx=(0, 8), pady=4, sticky="ew")

        self.browse_inv_btn = ttk.Button(
            self,
            text="Browse…",
            style="Secondary.TButton",
            command=self._browse_inventory,
        )
        self.browse_inv_btn.grid(row=0, column=2, padx=(0, 8), pady=4)

        self.start_lab_btn = ttk.Button(
            self,
            text="Start lab",
            style="Secondary.TButton",
            command=self.run_start_lab,
        )
        self.start_lab_btn.grid(row=0, column=3, padx=(0, 6), pady=4)
        Tooltip(self.start_lab_btn, "Runs 'make lab-up' in the project root.", self.font_family)

        self.gen_traffic_btn = ttk.Button(
            self,
            text="Generate traffic",
            style="Secondary.TButton",
            command=self.run_generate_traffic,
        )
        self.gen_traffic_btn.grid(row=0, column=4, pady=4)
        Tooltip(
            self.gen_traffic_btn,
            "Runs 'make traffic' inside Docker to generate lab requests and lab/out/labels.jsonl.",
            self.font_family,
        )

        ttk.Label(
            self,
            text=(
                "SSH key (server access): configured automatically "
                "via lab/target/id_ed25519 inside lab/inventory.ini."
            ),
            style="Muted.TLabel",
        ).grid(row=1, column=0, columnspan=5, sticky="w", pady=(2, 0))

    ## creating a function that opens a file picker for the Docker lab Ansible inventory
    def _browse_inventory(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select Ansible Inventory File",
            initialdir=str(self.app.working_folder),
            filetypes=[("INI / YAML files", "*.ini *.yml *.yaml"), ("All files", "*.*")],
        )
        if selected:
            self.inventory_var.set(selected)

    ## creating a function that resolves the configured Docker lab inventory path
    def resolve_inventory_path(self) -> Path:
        inv_text = self.inventory_var.get().strip() or "lab/inventory.ini"
        return Path(self.app.resolve_lab_path(inv_text))

    ## creating a function that starts the local Docker lab container
    def run_start_lab(self) -> None:
        self.app.run_aux_command(
            "Start Docker lab",
            build_start_lab_command(),
            cwd=self.app.project_root,
        )

    ## creating a function that runs the seeded Docker lab traffic generator
    def run_generate_traffic(self) -> None:
        self.app.run_aux_command(
            "Generate lab traffic",
            build_generate_traffic_command(),
            cwd=self.app.project_root,
        )

    ## creating a function that disables or re-enables lab buttons while a command runs
    def set_busy(self, busy: bool) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        for btn in (self.browse_inv_btn, self.start_lab_btn, self.gen_traffic_btn):
            btn.configure(state=state)
