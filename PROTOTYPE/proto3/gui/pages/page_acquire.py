"""Page 1: Target configuration (Docker lab or AWS EC2), Acquire, Show manifest, and Verify."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from gui.aws import (
    build_lookup_ip_command,
    build_test_ssh_command,
    check_pem_permissions,
    write_ec2_inventory,
)
from gui.runner import RunOutcome, group_verify_checks
from gui.widgets import ResultTable, ScrollablePage, StepBlock, Tooltip


class AcquirePage(ScrollablePage):
    """Tab 1: Target server selection and Phase 1 steps (Acquire, Show manifest, Verify)."""

    def __init__(
        self,
        master: tk.Misc,
        app: Any,
        font_family: str = "Helvetica",
    ) -> None:
        super().__init__(master)
        self.app = app
        self.font_family = font_family

        self.target_mode = tk.StringVar(value="lab")
        self.lab_inventory_var = tk.StringVar(value="lab/inventory.ini")

        self.ec2_instance_var = tk.StringVar(value="")
        self.ec2_host_var = tk.StringVar(value="")
        self.ec2_user_var = tk.StringVar(value="ec2-user")
        self.ec2_pem_var = tk.StringVar(value="")
        self.ec2_profile_var = tk.StringVar(value="")
        self.ec2_region_var = tk.StringVar(value="")
        self.ec2_python_var = tk.StringVar(value="/usr/bin/python3")

        self._build_target_panel()
        self._build_acquire_step()
        self._build_show_step()
        self._build_verify_step()
        self._switch_target_mode()

    ## creating a function that builds the Target panel with Docker lab and AWS EC2 radio modes
    def _build_target_panel(self) -> None:
        panel = ttk.LabelFrame(self.content, text="Target Server Configuration", padding=10)
        panel.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        panel.columnconfigure(0, weight=1)

        radio_bar = ttk.Frame(panel)
        radio_bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        rb_lab = ttk.Radiobutton(
            radio_bar,
            text="Docker lab (default)",
            variable=self.target_mode,
            value="lab",
            command=self._switch_target_mode,
        )
        rb_lab.grid(row=0, column=0, padx=(0, 20), sticky="w")

        rb_ec2 = ttk.Radiobutton(
            radio_bar,
            text="AWS EC2 (untested)",
            variable=self.target_mode,
            value="ec2",
            command=self._switch_target_mode,
        )
        rb_ec2.grid(row=0, column=1, sticky="w")

        # Docker lab sub-frame
        self.lab_frame = ttk.Frame(panel)
        self.lab_frame.grid(row=1, column=0, sticky="ew")
        self.lab_frame.columnconfigure(1, weight=1)

        ttk.Label(self.lab_frame, text="Ansible inventory:", style="Bold.TLabel").grid(
            row=0, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        self.lab_inv_entry = ttk.Entry(self.lab_frame, textvariable=self.lab_inventory_var)
        self.lab_inv_entry.grid(row=0, column=1, padx=(0, 8), pady=4, sticky="ew")

        self.browse_inv_btn = ttk.Button(
            self.lab_frame,
            text="Browse…",
            style="Secondary.TButton",
            command=self._browse_lab_inventory,
        )
        self.browse_inv_btn.grid(row=0, column=2, padx=(0, 8), pady=4)

        self.start_lab_btn = ttk.Button(
            self.lab_frame,
            text="Start lab",
            style="Secondary.TButton",
            command=self.run_start_lab,
        )
        self.start_lab_btn.grid(row=0, column=3, padx=(0, 6), pady=4)
        Tooltip(self.start_lab_btn, "Runs 'make lab-up' in the working folder.", self.font_family)

        self.gen_traffic_btn = ttk.Button(
            self.lab_frame,
            text="Generate traffic",
            style="Secondary.TButton",
            command=self.run_generate_traffic,
        )
        self.gen_traffic_btn.grid(row=0, column=4, pady=4)
        Tooltip(
            self.gen_traffic_btn,
            "Runs 'make traffic' to send seeded requests and write lab/out/labels.jsonl.",
            self.font_family,
        )

        ttk.Label(
            self.lab_frame,
            text=(
                "SSH key (server access): configured automatically "
                "via lab/target/id_ed25519 inside lab/inventory.ini."
            ),
            style="Muted.TLabel",
        ).grid(row=1, column=0, columnspan=5, sticky="w", pady=(2, 0))

        # AWS EC2 sub-frame
        self.ec2_frame = ttk.Frame(panel)
        self.ec2_frame.grid(row=2, column=0, sticky="ew")
        self.ec2_frame.columnconfigure(1, weight=1)
        self.ec2_frame.columnconfigure(3, weight=1)

        ttk.Label(self.ec2_frame, text="Instance ID:", style="Bold.TLabel").grid(
            row=0, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self.ec2_frame, textvariable=self.ec2_instance_var, width=22).grid(
            row=0, column=1, padx=(0, 8), pady=4, sticky="ew"
        )
        self.lookup_ip_btn = ttk.Button(
            self.ec2_frame,
            text="Look up IP",
            style="Secondary.TButton",
            command=self.run_lookup_ip,
        )
        self.lookup_ip_btn.grid(row=0, column=2, padx=(0, 12), pady=4)

        ttk.Label(self.ec2_frame, text="Public IP / Host:", style="Bold.TLabel").grid(
            row=0, column=3, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self.ec2_frame, textvariable=self.ec2_host_var, width=22).grid(
            row=0, column=4, pady=4, sticky="ew"
        )

        ttk.Label(self.ec2_frame, text="SSH user:", style="Bold.TLabel").grid(
            row=1, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self.ec2_frame, textvariable=self.ec2_user_var, width=16).grid(
            row=1, column=1, padx=(0, 8), pady=4, sticky="ew"
        )

        ttk.Label(self.ec2_frame, text="SSH key (server access) .pem:", style="Bold.TLabel").grid(
            row=1, column=2, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self.ec2_frame, textvariable=self.ec2_pem_var).grid(
            row=1, column=3, padx=(0, 8), pady=4, sticky="ew"
        )
        self.browse_pem_btn = ttk.Button(
            self.ec2_frame,
            text="Browse .pem…",
            style="Secondary.TButton",
            command=self._browse_pem_file,
        )
        self.browse_pem_btn.grid(row=1, column=4, pady=4, sticky="e")

        ttk.Label(self.ec2_frame, text="AWS profile (opt):", style="TLabel").grid(
            row=2, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self.ec2_frame, textvariable=self.ec2_profile_var, width=16).grid(
            row=2, column=1, padx=(0, 8), pady=4, sticky="ew"
        )

        ttk.Label(self.ec2_frame, text="AWS region (opt):", style="TLabel").grid(
            row=2, column=2, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self.ec2_frame, textvariable=self.ec2_region_var, width=16).grid(
            row=2, column=3, padx=(0, 8), pady=4, sticky="ew"
        )

        self.test_ssh_btn = ttk.Button(
            self.ec2_frame,
            text="Test SSH",
            style="Secondary.TButton",
            command=self.run_test_ssh,
        )
        self.test_ssh_btn.grid(row=2, column=4, pady=4, sticky="e")

        ttk.Label(self.ec2_frame, text="Remote Python path (advanced):", style="Muted.TLabel").grid(
            row=3, column=0, columnspan=2, padx=(0, 8), pady=4, sticky="w"
        )
        ttk.Entry(self.ec2_frame, textvariable=self.ec2_python_var, width=22).grid(
            row=3, column=2, columnspan=2, padx=(0, 8), pady=4, sticky="w"
        )

    ## creating a function that switches visible fields between Docker lab and AWS EC2 target modes
    def _switch_target_mode(self) -> None:
        if self.target_mode.get() == "lab":
            self.ec2_frame.grid_remove()
            self.lab_frame.grid()
        else:
            self.lab_frame.grid_remove()
            self.ec2_frame.grid()
        self.app.on_target_mode_changed(self.target_mode.get())

    def _browse_lab_inventory(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select Ansible Inventory File",
            initialdir=str(self.app.working_folder),
            filetypes=[("INI / YAML files", "*.ini *.yml *.yaml"), ("All files", "*.*")],
        )
        if selected:
            self.lab_inventory_var.set(selected)

    def _browse_pem_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select SSH Key (server access) .pem File",
            filetypes=[("PEM key files", "*.pem"), ("All files", "*.*")],
        )
        if selected:
            self.ec2_pem_var.set(selected)
            try:
                warn = check_pem_permissions(Path(selected))
                if warn:
                    self.app.log_message(warn, "warning")
                    messagebox.showwarning("SSH Key Permissions", warn)
            except OSError as error:
                self.app.log_message(str(error), "error")

    ## creating a function that builds the Acquire step block
    def _build_acquire_step(self) -> None:
        self.step_acquire = StepBlock(
            self.content,
            title="Step 1 – Acquire",
            description=(
                "Connects to the web server over SSH and copies its nginx logs. "
                "The copy is read-only, hashed and digitally signed."
            ),
            on_run=lambda: self.run_acquire(),
            run_label="Run Acquire",
            font_family=self.font_family,
        )
        self.step_acquire.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        self.acquire_summary = ttk.Label(
            self.step_acquire.result_area,
            text="No acquisition run in this session yet.",
            style="Muted.TLabel",
        )
        self.acquire_summary.grid(row=0, column=0, sticky="w", pady=2)

    ## creating a function that builds the Show manifest step block
    def _build_show_step(self) -> None:
        self.step_show = StepBlock(
            self.content,
            title="Step 2 – Show manifest",
            description="Displays the signed record of exactly what was collected.",
            on_run=lambda: self.run_show(),
            run_label="Run Show",
            font_family=self.font_family,
        )
        self.step_show.grid(row=2, column=0, sticky="ew", pady=(0, 8))

        self.show_table = ResultTable(
            self.step_show.result_area,
            columns=(
                ("field", "Manifest Field", 210),
                ("value", "Recorded Value", 560),
            ),
            height=6,
        )
        self.show_table.grid(row=0, column=0, sticky="ew", pady=2)

    ## creating a function that builds the Verify step block with the 3-group checklist
    def _build_verify_step(self) -> None:
        self.step_verify = StepBlock(
            self.content,
            title="Step 3 – Verify",
            description=(
                "Re-checks the signature and hashes to prove the evidence "
                "has not changed since collection."
            ),
            on_run=lambda: self.run_verify(),
            run_label="Run Verify",
            font_family=self.font_family,
        )
        self.step_verify.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        self.verify_table = ResultTable(
            self.step_verify.result_area,
            columns=(
                ("group", "Group", 90),
                ("status", "Status", 105),
                ("label", "What Was Checked", 360),
                ("detail", "Details", 290),
            ),
            height=5,
        )
        self.verify_table.grid(row=0, column=0, sticky="ew", pady=2)

    ## creating a function that runs make lab-up in the project root folder
    def run_start_lab(self) -> None:
        self.app.run_aux_command(
            "Start Docker lab", ["make", "lab-up"], cwd=self.app.project_root
        )

    ## creating a function that runs make traffic in the project root folder
    def run_generate_traffic(self) -> None:
        self.app.run_aux_command(
            "Generate lab traffic", ["make", "traffic"], cwd=self.app.project_root
        )

    ## creating a function that looks up an EC2 public IP using the AWS CLI
    def run_lookup_ip(self) -> None:
        try:
            cmd = build_lookup_ip_command(
                self.ec2_instance_var.get(),
                profile=self.ec2_profile_var.get(),
                region=self.ec2_region_var.get(),
            )
        except ValueError as error:
            messagebox.showerror("Invalid Instance ID", str(error))
            return

        def on_done(outcome: RunOutcome) -> None:
            ip = outcome.stdout.strip()
            if outcome.returncode == 0 and ip and ip != "None":
                self.ec2_host_var.set(ip)
                self.app.log_message(f"Resolved EC2 public IP: {ip}", "success")
            else:
                messagebox.showerror(
                    "EC2 IP Lookup Failed",
                    outcome.last_stderr_line or "Instance has no public IP or lookup failed.",
                )

        self.app.run_aux_command("Look up EC2 IP", cmd, on_done=on_done)

    ## creating a function that tests SSH connectivity to the configured EC2 host
    def run_test_ssh(self) -> None:
        try:
            pem_path = Path(self.ec2_pem_var.get().strip()).expanduser()
            warn = check_pem_permissions(pem_path)
            if warn:
                self.app.log_message(warn, "warning")
            cmd = build_test_ssh_command(
                self.ec2_host_var.get(),
                self.ec2_user_var.get(),
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

    ## creating a function that resolves the inventory path (or creates a temp EC2 inventory) and
    ## runs lapa acquire
    def run_acquire(self, on_success: Callable[[], None] | None = None) -> None:
        case_id = self.app.case_id
        cleanup_path: Path | None = None

        if self.target_mode.get() == "lab":
            inv_text = self.lab_inventory_var.get().strip() or "lab/inventory.ini"
            inv_path = self.app.resolve_lab_path(inv_text)
            if not inv_path.is_file():
                self.step_acquire.chip.set_status("fail")
                self.step_acquire.show_banner(f"Inventory file not found: {inv_path}", "fail")
                return
            inventory_arg = str(inv_path)
        else:
            try:
                pem_path = Path(self.ec2_pem_var.get().strip()).expanduser()
                warn = check_pem_permissions(pem_path)
                if warn:
                    self.app.log_message(warn, "warning")
                cleanup_path = write_ec2_inventory(
                    host=self.ec2_host_var.get(),
                    ssh_user=self.ec2_user_var.get(),
                    pem_path=pem_path,
                    python_interpreter=self.ec2_python_var.get(),
                )
                inventory_arg = str(cleanup_path)
            except (ValueError, FileNotFoundError, OSError) as error:
                self.step_acquire.chip.set_status("fail")
                self.step_acquire.show_banner(str(error), "fail")
                return

        cmd = [
            *self.app.lapa_cmd(),
            "acquire",
            "--inventory",
            inventory_arg,
            "--case-id",
            case_id,
            "--store",
            "local",
        ]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_acquire.json_viewer.set_data(data, outcome.stdout)
            if "signing key not found" in outcome.stderr.lower():
                self.app.show_missing_key_banner()
                self.step_acquire.chip.set_status("fail")
                self.step_acquire.show_banner(
                    (
                        "Signing key (evidence) not found. Click "
                        "'Create signing keys' in the top bar first."
                    ),
                    "fail",
                )
                return False
            if outcome.cancelled:
                self.step_acquire.chip.set_status("cancelled")
                self.step_acquire.show_banner("Acquisition was cancelled.", "fail")
                return False
            if data and isinstance(data.get("evidence_id"), str):
                eid = str(data["evidence_id"])
                self.app.refresh_evidence_ids(select_id=eid)
                ok = bool(data.get("ok")) and outcome.returncode == 0
                unverified = data.get("unverified_artifacts", [])
                errors = data.get("collection_errors", [])
                self.acquire_summary.configure(
                    text=(
                        f"Evidence ID: {eid}  |  Store: {data.get('store', 'local')}  |  "
                        f"Unverified artifacts: {len(unverified)} "
                        f" |  Collection errors: {len(errors)}"
                    )
                )
                if ok:
                    self.step_acquire.chip.set_status("pass")
                    self.step_acquire.show_banner(
                        f"✓ Acquired and signed evidence package {eid}.", "pass"
                    )
                    if on_success:
                        on_success()
                    return True
                self.step_acquire.chip.set_status("fail")
                self.step_acquire.show_banner(
                    (
                        "✗ Acquisition completed with unverified "
                        f"artifacts or errors ({outcome.last_stderr_line})."
                    ),
                    "fail",
                )
                return False

            self.step_acquire.chip.set_status("fail")
            self.step_acquire.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
            return False

        self.app.execute_step(
            self.step_acquire,
            "Acquire",
            cmd,
            cleanup_path=cleanup_path,
            handler=handle,
        )

    ## creating a function that runs lapa show for the selected Evidence ID
    def run_show(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_show)
        if not eid:
            return
        cmd = [*self.app.lapa_cmd(), "show", self.app.case_id, "--evidence-id", eid]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_show.json_viewer.set_data(data, outcome.stdout)
            self.show_table.clear()
            if outcome.returncode != 0 or not data:
                self.step_show.chip.set_status("fail")
                self.step_show.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            manifests = data.get("evidence", [])
            if not isinstance(manifests, list) or not manifests:
                self.step_show.chip.set_status("fail")
                self.step_show.show_banner(
                    "✗ No manifest found for the selected Evidence ID.", "fail"
                )
                return False

            m = manifests[0] if isinstance(manifests[0], dict) else {}
            target = m.get("target", {}) if isinstance(m.get("target"), dict) else {}
            acquirer = m.get("acquirer", {}) if isinstance(m.get("acquirer"), dict) else {}
            timing = m.get("timing", {}) if isinstance(m.get("timing"), dict) else {}
            tz = m.get("timezone", {}) if isinstance(m.get("timezone"), dict) else {}
            sig = m.get("signature", {}) if isinstance(m.get("signature"), dict) else {}
            artifacts = m.get("artifacts", []) if isinstance(m.get("artifacts"), list) else []
            ctx = (
                m.get("context_artifacts", [])
                if isinstance(m.get("context_artifacts"), list)
                else []
            )

            summary_rows = [
                ("Case ID / Evidence ID", f"{m.get('case_id')}  /  {m.get('evidence_id')}"),
                (
                    "Target Host & Address",
                    f"{target.get('hostname', 'n/a')} ({target.get('address', 'n/a')})",
                ),
                (
                    "SSH User & Kernel",
                    f"{target.get('ssh_user', 'n/a')}  |  {target.get('kernel', 'n/a')}",
                ),
                (
                    "Target Timezone",
                    (
                        f"{tz.get('iana_name') or tz.get('abbreviation') or 'UTC'} "
                        f"({tz.get('utc_offset', '')})"
                    ),
                ),
                (
                    "Acquisition Window (UTC)",
                    f"{timing.get('started_utc', 'n/a')}  →  {timing.get('finished_utc', 'n/a')}",
                ),
                (
                    "Estimated Clock Offset",
                    (
                        f"{timing.get('estimated_offset_seconds', 'n/a')} s (± "
                        f"{timing.get('estimated_offset_uncertainty_seconds', 'n/a')} s)"
                    ),
                ),
                (
                    "Collected Files",
                    f"{len(artifacts)} log artifact(s), {len(ctx)} server context record(s)",
                ),
                (
                    "Acquirer & Signing Key ID",
                    (
                        f"{acquirer.get('tool', 'lapa')} v{acquirer.get('version', '')} by "
                        f"{acquirer.get('operator', '')}  |  key {str(sig.get('key_id', ''))[:16]}…"
                    ),
                ),
            ]
            for field, val in summary_rows:
                self.show_table.add_row((field, val))

            self.step_show.chip.set_status("pass")
            self.step_show.show_banner(
                (
                    f"✓ Loaded signed manifest (schema v{m.get('schema_version')}) "
                    f"with {len(artifacts)} log artifact(s)."
                ),
                "pass",
            )
            if on_success:
                on_success()
            return True

        self.app.execute_step(self.step_show, "Show manifest", cmd, handler=handle)

    ## creating a function that runs lapa verify and populates the 3-group checklist
    def run_verify(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_verify)
        if not eid:
            return
        cmd = [*self.app.lapa_cmd(), "verify", self.app.case_id, "--evidence-id", eid]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_verify.json_viewer.set_data(data, outcome.stdout)
            self.verify_table.clear()

            if not data or not isinstance(data.get("results"), list) or not data["results"]:
                self.step_verify.chip.set_status("fail")
                self.step_verify.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            entry = data["results"][0]
            grouped_rows = group_verify_checks(entry)
            for row in grouped_rows:
                passed = bool(row["passed"])
                status_text = "✓ Passed" if passed else "✗ Failed"
                tag = "pass" if passed else "fail"
                self.verify_table.add_row(
                    (row["group"], status_text, row["label"], row["detail"]),
                    tag=tag,
                )

            overall_ok = bool(data.get("ok")) and bool(entry.get("ok")) and outcome.returncode == 0
            if overall_ok:
                self.step_verify.chip.set_status("pass")
                self.step_verify.show_banner(
                    (
                        "✓ Passed: All signature, custody chain, and file hash "
                        f"checks verified for {eid}. Page 2 is now unlocked."
                    ),
                    "pass",
                )
                self.app.mark_evidence_verified(self.app.case_id, eid, True)
                if on_success:
                    on_success()
                return True

            failed_list = entry.get("failed_checks", [])
            failed_str = (
                ", ".join(str(x) for x in failed_list) if failed_list else outcome.last_stderr_line
            )
            self.step_verify.chip.set_status("fail")
            self.step_verify.show_banner(
                f"✗ Verification failed — failed checks: {failed_str}",
                "fail",
            )
            self.app.mark_evidence_verified(self.app.case_id, eid, False)
            return False

        self.app.execute_step(self.step_verify, "Verify", cmd, handler=handle)

    ## creating a function that disables or enables all buttons on Page 1 while a command is running
    def set_busy(self, busy: bool) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        for btn in (
            self.browse_inv_btn,
            self.start_lab_btn,
            self.gen_traffic_btn,
            self.lookup_ip_btn,
            self.browse_pem_btn,
            self.test_ssh_btn,
        ):
            btn.configure(state=state)
        self.step_acquire.set_busy(busy)
        self.step_show.set_busy(busy)
        self.step_verify.set_busy(busy)
