"""Page 1: Target selection (Docker lab or My server), Acquire, Show manifest, and Verify."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import ttk
from typing import Any

from gui.ec2_panel import Ec2ServerPanel
from gui.lab_tools import DockerLabPanel
from gui.runner import (
    RunOutcome,
    extract_manifest_display,
    format_acquire_outcome,
    group_verify_checks,
)
from gui.targets import (
    TARGET_DESCRIPTIONS,
    TARGET_EC2,
    TARGET_LAB,
    TARGET_LABELS,
)
from gui.widgets import ResultTable, ScrollablePage, StatusChip, StepBlock

_CLOUD_STATUS_CHIP: dict[str, tuple[str, str]] = {
    "match": ("pass", "✓ Match"),
    "mismatch": ("warn", "▲ Mismatch"),
    "unavailable": ("warn", "▲ Unavailable"),
    "not_checked": ("idle", "○ Not checked"),
}


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

        self.target_choice = tk.StringVar(value=TARGET_LAB)

        self._build_target_panel()
        self._build_acquire_step()
        self._build_show_step()
        self._build_verify_step()
        self._switch_target()

    ## creating a function that builds the Target panel with Docker lab and My server radio buttons
    def _build_target_panel(self) -> None:
        panel = ttk.LabelFrame(self.content, text="Target Server", padding=10)
        panel.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        panel.columnconfigure(0, weight=1)

        radio_bar = ttk.Frame(panel)
        radio_bar.grid(row=0, column=0, sticky="ew", pady=(0, 4))

        rb_lab = ttk.Radiobutton(
            radio_bar,
            text=TARGET_LABELS[TARGET_LAB],
            variable=self.target_choice,
            value=TARGET_LAB,
            command=self._switch_target,
        )
        rb_lab.grid(row=0, column=0, padx=(0, 20), sticky="w")

        rb_ec2 = ttk.Radiobutton(
            radio_bar,
            text=TARGET_LABELS[TARGET_EC2],
            variable=self.target_choice,
            value=TARGET_EC2,
            command=self._switch_target,
        )
        rb_ec2.grid(row=0, column=1, sticky="w")

        # One neutral line describing the selected target
        self.target_desc_label = ttk.Label(
            panel,
            text=TARGET_DESCRIPTIONS[TARGET_LAB],
            style="Muted.TLabel",
        )
        self.target_desc_label.grid(row=1, column=0, sticky="w", pady=(0, 6))

        self.lab_panel = DockerLabPanel(panel, app=self.app, font_family=self.font_family)
        self.lab_panel.grid(row=2, column=0, sticky="ew")

        self.ec2_panel = Ec2ServerPanel(panel, app=self.app, font_family=self.font_family)
        self.ec2_panel.grid(row=3, column=0, sticky="ew")

    ## creating a function that shows the panel matching the selected target
    def _switch_target(self) -> None:
        chosen = self.target_choice.get()
        self.target_desc_label.configure(
            text=TARGET_DESCRIPTIONS.get(chosen, TARGET_DESCRIPTIONS[TARGET_LAB])
        )
        if chosen == TARGET_LAB:
            self.ec2_panel.grid_remove()
            self.lab_panel.grid()
        else:
            self.lab_panel.grid_remove()
            self.ec2_panel.grid()
        self.app.on_target_changed(chosen)

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

    ## creating a function that builds the Show manifest step block with summary, files, and cloud
    ## identity comparison
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

        area = self.step_show.result_area
        area.columnconfigure(0, weight=1)

        self.show_table = ResultTable(
            area,
            columns=(
                ("field", "Manifest Field", 210),
                ("value", "Recorded Value", 560),
            ),
            height=7,
        )
        self.show_table.grid(row=0, column=0, sticky="ew", pady=(2, 6))

        ttk.Label(area, text="Collected Log Files:", style="Bold.TLabel").grid(
            row=1, column=0, sticky="w", pady=(2, 2)
        )
        self.files_table = ResultTable(
            area,
            columns=(
                ("file", "Stored Artifact", 240),
                ("size", "Size at Open (bytes)", 140),
                ("grew", "Grew During Read", 130),
                ("changed", "Changed During Read", 145),
                ("verified", "Verified", 105),
            ),
            height=4,
        )
        self.files_table.grid(row=2, column=0, sticky="ew", pady=(0, 2))

        self.grew_note_label = ttk.Label(
            area,
            text=(
                "Note: 'Grew during read' is normal on a live server because nginx keeps "
                "appending new log lines while the file is read."
            ),
            style="Muted.TLabel",
            wraplength=820,
        )
        self.grew_note_label.grid(row=3, column=0, sticky="w", pady=(0, 8))

        cloud_hdr = ttk.Frame(area)
        cloud_hdr.grid(row=4, column=0, sticky="ew", pady=(2, 2))
        ttk.Label(cloud_hdr, text="Cloud Identity Cross-Check:", style="Bold.TLabel").grid(
            row=0, column=0, padx=(0, 10), sticky="w"
        )
        self.cloud_status_chip = StatusChip(cloud_hdr, font_family=self.font_family)
        self.cloud_status_chip.set_status("idle", "○ Not checked")
        self.cloud_status_chip.grid(row=0, column=1, sticky="w")

        self.cloud_table = ResultTable(
            area,
            columns=(
                ("field", "Field", 150),
                ("target", "Reported by the server", 310),
                ("aws", "Reported by AWS", 310),
            ),
            height=5,
        )
        self.cloud_table.grid(row=5, column=0, sticky="ew", pady=(2, 2))

        self.cloud_details_label = ttk.Label(
            area,
            text="",
            style="Muted.TLabel",
            wraplength=820,
        )
        self.cloud_details_label.grid(row=6, column=0, sticky="w", pady=(2, 2))

    ## creating a function that builds the Verify step block with the grouped checklist
    def _build_verify_step(self) -> None:
        self.step_verify = StepBlock(
            self.content,
            title="Step 3 – Verify",
            description=(
                "Re-checks the signature, acquisition record, completeness and file hashes "
                "to prove the evidence is complete and unchanged since collection."
            ),
            on_run=lambda: self.run_verify(),
            run_label="Run Verify",
            font_family=self.font_family,
        )
        self.step_verify.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        self.verify_table = ResultTable(
            self.step_verify.result_area,
            columns=(
                ("group", "Group", 105),
                ("status", "Status", 105),
                ("label", "What Was Checked", 350),
                ("detail", "Details", 290),
            ),
            height=6,
        )
        self.verify_table.grid(row=0, column=0, sticky="ew", pady=2)

    ## creating a function that resolves the inventory path and runs lapa acquire
    def run_acquire(self, on_success: Callable[[], None] | None = None) -> None:
        case_id = self.app.case_id
        cleanup_path: Path | None = None
        extra_aws_args: list[str] = []

        if self.target_choice.get() == TARGET_LAB:
            inv_path = self.lab_panel.resolve_inventory_path()
            if not inv_path.is_file():
                self.step_acquire.chip.set_status("fail")
                self.step_acquire.show_banner(f"Inventory file not found: {inv_path}", "fail")
                return
            inventory_arg = str(inv_path)
        else:
            try:
                cleanup_path = self.ec2_panel.build_temp_inventory()
                inventory_arg = str(cleanup_path)
                extra_aws_args = self.ec2_panel.aws_acquire_args()
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
            *extra_aws_args,
        ]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_acquire.json_viewer.set_data(data, outcome.stdout)
            formatted = format_acquire_outcome(outcome)

            if formatted["missing_key"]:
                self.app.show_missing_key_banner()

            eid = formatted["evidence_id"]
            if isinstance(eid, str) and data:
                self.app.refresh_evidence_ids(select_id=eid)
                unverified = data.get("unverified_artifacts", [])
                errors = data.get("collection_errors", [])
                cross = (
                    data.get("cloud_cross_check", {})
                    if isinstance(data.get("cloud_cross_check"), dict)
                    else {}
                )
                cross_status = str(cross.get("status") or "not_checked")
                self.acquire_summary.configure(
                    text=(
                        f"Evidence ID: {eid}  |  Store: {data.get('store', 'local')}  |  "
                        f"Unverified: {len(unverified)}  |  Errors: {len(errors)}  |  "
                        f"Cloud cross-check: {cross_status}"
                    )
                )

            self.step_acquire.chip.set_status(str(formatted["chip_state"]))
            self.step_acquire.show_banner(
                str(formatted["banner_text"]),
                str(formatted["banner_kind"]),
            )
            if formatted["ok"]:
                if on_success:
                    on_success()
                return True
            return False

        self.app.execute_step(
            self.step_acquire,
            "Acquire",
            cmd,
            cleanup_path=cleanup_path,
            handler=handle,
        )

    ## creating a function that runs lapa show and populates summary, per-file, and cloud tables
    def run_show(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_show)
        if not eid:
            return
        cmd = [*self.app.lapa_cmd(), "show", self.app.case_id, "--evidence-id", eid]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_show.json_viewer.set_data(data, outcome.stdout)
            self.show_table.clear()
            self.files_table.clear()
            self.cloud_table.clear()
            self.cloud_details_label.configure(text="")

            if outcome.returncode != 0 or not data:
                self.step_show.chip.set_status("fail")
                self.step_show.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            manifests = data.get("evidence", [])
            if (
                not isinstance(manifests, list)
                or not manifests
                or not isinstance(manifests[0], dict)
            ):
                self.step_show.chip.set_status("fail")
                self.step_show.show_banner(
                    "✗ No manifest found for the selected Evidence ID.", "fail"
                )
                return False

            manifest = manifests[0]
            display = extract_manifest_display(manifest)

            for field, val in display["summary_rows"]:
                self.show_table.add_row((field, val))

            for file_row in display["file_rows"]:
                verified = bool(file_row["verified"])
                changed = bool(file_row["changed_during_read"])
                grew = bool(file_row["grew_during_read"])
                tag = "fail" if (not verified or changed) else ("warn" if grew else "pass")
                self.files_table.add_row(
                    (
                        file_row["file"],
                        file_row["size_at_open"],
                        "Yes (normal on live server)" if grew else "No",
                        "Yes" if changed else "No",
                        "✓ Yes" if verified else "✗ No",
                    ),
                    tag=tag,
                )
            self.grew_note_label.configure(text=str(display["grew_note"]))

            cloud = display["cloud_comparison"]
            cloud_status = str(cloud["status"])
            chip_state, chip_text = _CLOUD_STATUS_CHIP.get(
                cloud_status, ("idle", f"○ {cloud_status}")
            )
            self.cloud_status_chip.set_status(chip_state, chip_text)
            for row in cloud["rows"]:
                self.cloud_table.add_row(row)
            details = cloud["details"]
            self.cloud_details_label.configure(text=" | ".join(details) if details else "")

            self.step_show.chip.set_status("warn" if cloud_status == "mismatch" else "pass")
            banner_kind = "warn" if cloud_status == "mismatch" else "pass"
            extra_note = (
                " — ▲ Cloud identity mismatch detected; inspect the Cloud Identity table below."
                if cloud_status == "mismatch"
                else ""
            )
            self.step_show.show_banner(
                (
                    f"✓ Loaded signed manifest (schema v{manifest.get('schema_version')}) "
                    f"with {len(display['file_rows'])} log artifact(s) and "
                    f"{display['footprint_command_count']} recorded footprint command(s)"
                    f"{extra_note}"
                ),
                banner_kind,
            )
            if on_success:
                on_success()
            return True

        self.app.execute_step(self.step_show, "Show manifest", cmd, handler=handle)

    ## creating a function that runs lapa verify and populates the grouped checklist
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
                        "✓ Passed: All signature, acquisition record, completeness, and file hash "
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
        self.lab_panel.set_busy(busy)
        self.ec2_panel.set_busy(busy)
        self.step_acquire.set_busy(busy)
        self.step_show.set_busy(busy)
        self.step_verify.set_busy(busy)
