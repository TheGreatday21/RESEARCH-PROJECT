"""My server (AWS EC2) target controls: IP lookup, SSH test, and read-only Check access."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from gui.aws import (
    build_acquire_aws_args,
    build_lookup_ip_command,
    build_preflight_command,
    build_test_ssh_command,
    check_pem_permissions,
    write_ec2_inventory,
)
from gui.runner import RunOutcome, format_preflight_checks
from gui.theme import (
    STATUS_FAIL,
    STATUS_FAIL_BG,
    STATUS_PASS,
    STATUS_PASS_BG,
)
from gui.widgets import ResultTable, Tooltip


class Ec2ServerPanel(ttk.Frame):
    """Target sub-panel shown only when 'My server (AWS EC2)' is selected.

    Read-only server controls only; never imports or triggers any traffic-generation or lab tools.
    """

    def __init__(
        self,
        master: tk.Misc,
        app: Any,
        font_family: str = "Helvetica",
    ) -> None:
        super().__init__(master)
        self.app = app
        self.font_family = font_family

        self.instance_var = tk.StringVar(value="")
        self.host_var = tk.StringVar(value="")
        self.user_var = tk.StringVar(value="ec2-user")
        self.pem_var = tk.StringVar(value="")
        self.profile_var = tk.StringVar(value="")
        self.region_var = tk.StringVar(value="")
        self.python_var = tk.StringVar(value="/usr/bin/python3")

        self.columnconfigure(1, weight=1)
        self.columnconfigure(3, weight=1)

        ttk.Label(self, text="Instance ID:", style="Bold.TLabel").grid(
            row=0, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self, textvariable=self.instance_var, width=22).grid(
            row=0, column=1, padx=(0, 8), pady=4, sticky="ew"
        )
        self.lookup_ip_btn = ttk.Button(
            self,
            text="Look up IP",
            style="Secondary.TButton",
            command=self.run_lookup_ip,
        )
        self.lookup_ip_btn.grid(row=0, column=2, padx=(0, 12), pady=4)

        ttk.Label(self, text="Public IP / Host:", style="Bold.TLabel").grid(
            row=0, column=3, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self, textvariable=self.host_var, width=22).grid(
            row=0, column=4, pady=4, sticky="ew"
        )

        ttk.Label(self, text="SSH user:", style="Bold.TLabel").grid(
            row=1, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self, textvariable=self.user_var, width=16).grid(
            row=1, column=1, padx=(0, 8), pady=4, sticky="ew"
        )

        ttk.Label(self, text="SSH key (server access) .pem:", style="Bold.TLabel").grid(
            row=1, column=2, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self, textvariable=self.pem_var).grid(
            row=1, column=3, padx=(0, 8), pady=4, sticky="ew"
        )
        self.browse_pem_btn = ttk.Button(
            self,
            text="Browse .pem…",
            style="Secondary.TButton",
            command=self._browse_pem_file,
        )
        self.browse_pem_btn.grid(row=1, column=4, pady=4, sticky="e")

        ttk.Label(self, text="AWS profile (opt):", style="TLabel").grid(
            row=2, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self, textvariable=self.profile_var, width=16).grid(
            row=2, column=1, padx=(0, 8), pady=4, sticky="ew"
        )

        ttk.Label(self, text="AWS region (opt):", style="TLabel").grid(
            row=2, column=2, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self, textvariable=self.region_var, width=16).grid(
            row=2, column=3, padx=(0, 8), pady=4, sticky="ew"
        )

        action_btns = ttk.Frame(self)
        action_btns.grid(row=2, column=4, pady=4, sticky="e")

        self.test_ssh_btn = ttk.Button(
            action_btns,
            text="Test SSH",
            style="Secondary.TButton",
            command=self.run_test_ssh,
        )
        self.test_ssh_btn.grid(row=0, column=0, padx=(0, 6))

        self.check_access_btn = ttk.Button(
            action_btns,
            text="Check access",
            style="Primary.TButton",
            command=self.run_check_access,
        )
        self.check_access_btn.grid(row=0, column=1)
        Tooltip(
            self.check_access_btn,
            (
                "Runs read-only 'lapa preflight' to check SSH, non-root user, adm group, "
                "nginx log readability, python3 >= 3.8, and nginx. Changes nothing on the server."
            ),
            self.font_family,
        )

        ttk.Label(self, text="Remote Python path (advanced):", style="Muted.TLabel").grid(
            row=3, column=0, columnspan=2, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self, textvariable=self.python_var, width=22).grid(
            row=3, column=2, columnspan=2, padx=(0, 8), pady=4, sticky="w"
        )

        # Preflight checklist results (shown after Check access runs)
        self.preflight_frame = ttk.Frame(self)
        self.preflight_frame.grid(row=4, column=0, columnspan=5, sticky="ew", pady=(6, 0))
        self.preflight_frame.columnconfigure(0, weight=1)
        self.preflight_frame.grid_remove()

        self.preflight_banner = tk.Label(
            self.preflight_frame,
            text="",
            anchor="w",
            justify="left",
            font=(self.font_family, 10, "bold"),
            padx=8,
            pady=4,
            relief="solid",
            bd=1,
            wraplength=840,
        )
        self.preflight_banner.grid(row=0, column=0, sticky="ew", pady=(0, 4))

        self.preflight_table = ResultTable(
            self.preflight_frame,
            columns=(
                ("check", "Check", 175),
                ("status", "Status", 95),
                ("message", "Result", 260),
                ("hint", "Admin Hint (if failed)", 320),
            ),
            height=6,
        )
        self.preflight_table.grid(row=1, column=0, sticky="ew")

    ## creating a function that lets the user browse for the SSH .pem key and warns if mode != 0600
    def _browse_pem_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select SSH Key (server access) .pem File",
            filetypes=[("PEM key files", "*.pem"), ("All files", "*.*")],
        )
        if selected:
            self.pem_var.set(selected)
            try:
                warn = check_pem_permissions(Path(selected))
                if warn:
                    self.app.log_message(warn, "warning")
                    messagebox.showwarning("SSH Key Permissions", warn)
            except OSError as error:
                self.app.log_message(str(error), "error")

    ## creating a function that writes a temporary mode-0600 inventory for preflight or acquire
    def build_temp_inventory(self) -> Path:
        pem_path = Path(self.pem_var.get().strip()).expanduser()
        warn = check_pem_permissions(pem_path)
        if warn:
            self.app.log_message(warn, "warning")
        return write_ec2_inventory(
            host=self.host_var.get(),
            ssh_user=self.user_var.get(),
            pem_path=pem_path,
            python_interpreter=self.python_var.get(),
        )

    ## creating a function that returns optional --aws-* CLI flags configured in the EC2 form
    def aws_acquire_args(self) -> list[str]:
        return build_acquire_aws_args(
            instance_id=self.instance_var.get(),
            profile=self.profile_var.get(),
            region=self.region_var.get(),
        )

    ## creating a function that looks up an EC2 public IP via the read-only AWS CLI
    def run_lookup_ip(self) -> None:
        try:
            cmd = build_lookup_ip_command(
                self.instance_var.get(),
                profile=self.profile_var.get(),
                region=self.region_var.get(),
            )
        except ValueError as error:
            messagebox.showerror("Invalid Instance ID", str(error))
            return

        def on_done(outcome: RunOutcome) -> None:
            ip = outcome.stdout.strip()
            if outcome.returncode == 0 and ip and ip != "None":
                self.host_var.set(ip)
                self.app.log_message(f"Resolved EC2 public IP: {ip}", "success")
            else:
                messagebox.showerror(
                    "EC2 IP Lookup Failed",
                    outcome.last_stderr_line or "Instance has no public IP or lookup failed.",
                )

        self.app.run_aux_command("Look up EC2 IP", cmd, on_done=on_done)

    ## creating a function that runs a simple SSH connectivity test to the configured EC2 host
    def run_test_ssh(self) -> None:
        try:
            pem_path = Path(self.pem_var.get().strip()).expanduser()
            warn = check_pem_permissions(pem_path)
            if warn:
                self.app.log_message(warn, "warning")
            cmd = build_test_ssh_command(
                self.host_var.get(),
                self.user_var.get(),
                pem_path,
            )
        except (ValueError, FileNotFoundError) as error:
            messagebox.showerror("SSH Configuration Error", str(error))
            return

        def on_done(outcome: RunOutcome) -> None:
            if outcome.returncode == 0:
                messagebox.showinfo("SSH Test Passed", "SSH connectivity check succeeded.")
            else:
                messagebox.showerror("SSH Test Failed", outcome.last_stderr_line)

        self.app.run_aux_command("Test EC2 SSH", cmd, on_done=on_done)

    ## creating a function that runs read-only lapa preflight and renders the pass/fail checklist
    def run_check_access(self) -> None:
        try:
            temp_inventory = self.build_temp_inventory()
        except (ValueError, FileNotFoundError, OSError) as error:
            messagebox.showerror("Server Configuration Error", str(error))
            return

        cmd = build_preflight_command(self.app.lapa_cmd(), temp_inventory)

        def on_done(outcome: RunOutcome) -> None:
            self.preflight_frame.grid()
            self.preflight_table.clear()
            data = outcome.parsed_json
            if not data or not isinstance(data.get("checks"), list):
                self.preflight_banner.configure(
                    text=f"✗ Check access failed: {outcome.last_stderr_line}",
                    fg=STATUS_FAIL,
                    bg=STATUS_FAIL_BG,
                )
                return

            rows = format_preflight_checks(data)
            for row in rows:
                passed = bool(row["passed"])
                self.preflight_table.add_row(
                    (
                        row["label"],
                        "✓ Passed" if passed else "✗ Failed",
                        row["message"],
                        row["hint"],
                    ),
                    tag="pass" if passed else "fail",
                )
            if bool(data.get("ok")) and outcome.returncode == 0:
                self.preflight_banner.configure(
                    text=(
                        f"✓ All {len(rows)} read-only preflight checks passed. "
                        "This server is ready for Acquire."
                    ),
                    fg=STATUS_PASS,
                    bg=STATUS_PASS_BG,
                )
            else:
                failed_count = sum(1 for row in rows if not row["passed"])
                self.preflight_banner.configure(
                    text=(
                        f"✗ {failed_count} of {len(rows)} preflight check(s) failed. "
                        "Review the admin hints below (LAPA never changes server settings)."
                    ),
                    fg=STATUS_FAIL,
                    bg=STATUS_FAIL_BG,
                )

        self.app.run_aux_command(
            "Check server access (preflight)",
            cmd,
            cleanup_path=temp_inventory,
            on_done=on_done,
        )

    ## creating a function that disables or re-enables EC2 controls while a command runs
    def set_busy(self, busy: bool) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        for btn in (
            self.lookup_ip_btn,
            self.browse_pem_btn,
            self.test_ssh_btn,
            self.check_access_btn,
        ):
            btn.configure(state=state)
