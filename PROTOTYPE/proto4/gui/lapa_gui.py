"""Main Tkinter/ttk window for LAPA (Log Acquisition with Provenance and Analysis)."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import tkinter as tk
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from gui.pages.page_acquire import AcquirePage
from gui.pages.page_analyze import AnalyzePage
from gui.pages.page_parse import ParsePage
from gui.runner import (
    CommandRunner,
    RunOutcome,
    list_case_evidence_ids,
    resolve_lapa_command,
)
from gui.targets import report_labels_path
from gui.theme import (
    BG_ENTRY,
    PRIMARY,
    STATUS_FAIL,
    STATUS_FAIL_BG,
    STATUS_PASS,
    TEXT_COLOR,
    apply_theme,
)
from gui.widgets import StepBlock, Tooltip


class LapaGUI:
    """Main desktop GUI window driving the lapa CLI across Phases 1 through 4."""

    def __init__(self, root: tk.Tk | None = None, *, start_mainloop: bool = True) -> None:
        self.root = root or tk.Tk()
        self.root.title("LAPA – Log Acquisition with Provenance and Analysis")
        self.root.minsize(1040, 740)
        self.root.geometry("1140x820")
        self.root.resizable(width=True, height=True)

        self.style, self.font_family = apply_theme(self.root)
        self.project_root = Path(__file__).resolve().parents[1]

        self.working_folder_var = tk.StringVar(value=str(self.project_root))
        self.case_id_var = tk.StringVar(value="C001")
        self.evidence_id_var = tk.StringVar(value="")

        # Session verification gates: set of (case_id, evidence_id) verified in this session
        self._verified_evidence: set[tuple[str, str]] = set()
        self._verified_derived: set[tuple[str, str]] = set()

        self.event_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.runner = CommandRunner(self.event_queue)
        self._pipeline_active = False

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=3)
        self.root.rowconfigure(2, weight=1)

        self._build_header()
        self._build_notebook()
        self._build_log_area()
        self._build_footer()

        self.case_id_var.trace_add("write", lambda *_: self.on_case_or_evidence_changed())
        self.evidence_id_var.trace_add("write", lambda *_: self._update_gating_state())

        self.refresh_evidence_ids()
        self.root.protocol("WM_DELETE_WINDOW", self.close_message)
        self.root.after(100, self._poll_event_queue)

        if start_mainloop:
            self.root.mainloop()

    @property
    def working_folder(self) -> Path:
        raw = self.working_folder_var.get().strip()
        return Path(raw).expanduser().resolve() if raw else self.project_root

    @property
    def case_id(self) -> str:
        return self.case_id_var.get().strip() or "C001"

    @property
    def evidence_id(self) -> str:
        return self.evidence_id_var.get().strip()

    ## creating a function that returns the configured lapa CLI command list
    def lapa_cmd(self) -> list[str]:
        return resolve_lapa_command(self.project_root)

    ## creating a function that resolves relative lab paths against working_folder first, then
    ## project_root
    def resolve_lab_path(self, raw_path: str) -> Path:
        candidate = Path(raw_path).expanduser()
        if candidate.is_absolute():
            return candidate
        in_working = self.working_folder / candidate
        if in_working.exists():
            return in_working
        return self.project_root / candidate

    ## creating a function that builds the persistent top header with Working folder, Case ID,
    ## Evidence ID, and Signing keys
    def _build_header(self) -> None:
        header = ttk.LabelFrame(
            self.root,
            text="Workspace, Case & Signing Key (Evidence)",
            padding=(12, 8),
        )
        header.grid(row=0, column=0, padx=12, pady=(10, 4), sticky="ew")
        header.columnconfigure(1, weight=1)
        header.columnconfigure(4, weight=1)

        # Row 0: Working folder + Browse | Case ID
        ttk.Label(header, text="Working folder:", style="Bold.TLabel").grid(
            row=0, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        self.working_entry = ttk.Entry(header, textvariable=self.working_folder_var)
        self.working_entry.grid(row=0, column=1, columnspan=2, padx=(0, 8), pady=4, sticky="ew")

        self.browse_work_btn = ttk.Button(
            header,
            text="Browse…",
            style="Secondary.TButton",
            command=self._browse_working_folder,
        )
        self.browse_work_btn.grid(row=0, column=3, padx=(0, 18), pady=4)

        ttk.Label(header, text="Case ID:", style="Bold.TLabel").grid(
            row=0, column=4, padx=(0, 8), pady=4, sticky="e"
        )
        self.case_entry = ttk.Entry(header, textvariable=self.case_id_var, width=10)
        self.case_entry.grid(row=0, column=5, padx=(0, 8), pady=4, sticky="w")

        self.pipeline_btn = ttk.Button(
            header,
            text="▶ Run full pipeline",
            style="Accent.TButton",
            command=self.run_full_pipeline,
        )
        self.pipeline_btn.grid(row=0, column=6, padx=(8, 0), pady=4, sticky="e")
        Tooltip(
            self.pipeline_btn,
            (
                "Chains: Acquire → Verify → Parse → Verify derived → Analyze → "
                "Detect → (Evaluate when a labels file is chosen) → Report. Stops at first failure."
            ),
            self.font_family,
        )

        # Row 1: Evidence ID combobox + Refresh | Signing key (evidence) button
        ttk.Label(header, text="Evidence ID:", style="Bold.TLabel").grid(
            row=1, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        self.evidence_combo = ttk.Combobox(
            header,
            textvariable=self.evidence_id_var,
        )
        self.evidence_combo.grid(row=1, column=1, padx=(0, 8), pady=4, sticky="ew")

        self.refresh_eid_btn = ttk.Button(
            header,
            text="↻ Refresh IDs",
            style="Secondary.TButton",
            command=lambda: self.refresh_evidence_ids(),
        )
        self.refresh_eid_btn.grid(row=1, column=2, padx=(0, 8), pady=4, sticky="w")

        ttk.Label(
            header,
            text="Signing key (evidence):",
            style="Bold.TLabel",
        ).grid(row=1, column=3, columnspan=2, padx=(0, 8), pady=4, sticky="e")

        self.keygen_btn = ttk.Button(
            header,
            text="Create signing keys",
            style="Primary.TButton",
            command=self.run_keygen,
        )
        self.keygen_btn.grid(row=1, column=5, columnspan=2, pady=4, sticky="ew")
        Tooltip(
            self.keygen_btn,
            (
                "Creates the Ed25519 Signing key (evidence) pair via "
                "'lapa keygen'. Distinct from the SSH key (server access)."
            ),
            self.font_family,
        )

        # Hidden banner when signing keys are missing
        self.missing_key_banner = tk.Label(
            header,
            text=(
                "⚠ Signing key (evidence) not found! Click 'Create signing keys' above "
                "to generate your Ed25519 key pair before running Acquire or Parse."
            ),
            fg=STATUS_FAIL,
            bg=STATUS_FAIL_BG,
            font=(self.font_family, 10, "bold"),
            padx=10,
            pady=5,
            relief="solid",
            bd=1,
            anchor="w",
        )
        self.missing_key_banner.grid(row=2, column=0, columnspan=7, sticky="ew", pady=(6, 0))
        self.missing_key_banner.grid_remove()

    ## creating a function that builds the 3-page ttk.Notebook for Phases 1–4
    def _build_notebook(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, padx=12, pady=4, sticky="nsew")

        self.page_acquire = AcquirePage(self.notebook, app=self, font_family=self.font_family)
        self.page_parse = ParsePage(self.notebook, app=self, font_family=self.font_family)
        self.page_analyze = AnalyzePage(self.notebook, app=self, font_family=self.font_family)

        self.notebook.add(self.page_acquire, text="  1. Acquire & Verify  ")
        self.notebook.add(self.page_parse, text="  2. Parse & Query (Locked)  ")
        self.notebook.add(self.page_analyze, text="  3. Analyze, Detect & Report (Locked)  ")

    ## creating a function that builds the always-visible live timestamped log frame
    def _build_log_area(self) -> None:
        log_frame = ttk.LabelFrame(self.root, text="Live Command & Forensic Log", padding=8)
        log_frame.grid(row=2, column=0, padx=12, pady=4, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_box = tk.Text(
            log_frame,
            height=7,
            state=tk.DISABLED,
            font=("Menlo" if self.font_family != "Consolas" else "Consolas", 10),
            fg=TEXT_COLOR,
            bg=BG_ENTRY,
            relief="solid",
            bd=1,
            highlightthickness=0,
        )
        vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=vsb.set)
        self.log_box.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self.log_box.tag_configure("info", foreground=PRIMARY)
        self.log_box.tag_configure("success", foreground=STATUS_PASS)
        self.log_box.tag_configure("warning", foreground="#9c6500")
        self.log_box.tag_configure("error", foreground=STATUS_FAIL)

    ## creating a function that builds the bottom progress bar, status label, Cancel button, and
    ## Open folder button
    def _build_footer(self) -> None:
        footer = ttk.Frame(self.root, padding=(12, 6, 12, 10))
        footer.grid(row=3, column=0, sticky="ew")
        footer.columnconfigure(1, weight=1)

        self.progress_bar = ttk.Progressbar(
            footer,
            style="Teal.Horizontal.TProgressbar",
            orient="horizontal",
            length=240,
            mode="determinate",
            maximum=100,
            value=0,
        )
        self.progress_bar.grid(row=0, column=0, padx=(0, 12), sticky="w")

        self.status_label = ttk.Label(
            footer,
            text="Ready – select or acquire an evidence package to begin.",
            style="Bold.TLabel",
        )
        self.status_label.grid(row=0, column=1, sticky="w")

        self.cancel_btn = ttk.Button(
            footer,
            text="Cancel",
            style="Danger.TButton",
            command=self.cancel_current_command,
            state=tk.DISABLED,
            width=12,
        )
        self.cancel_btn.grid(row=0, column=2, padx=(8, 8))

        self.open_folder_btn = ttk.Button(
            footer,
            text="Open working folder",
            style="Primary.TButton",
            command=lambda: self.open_path(self.working_folder),
            width=18,
        )
        self.open_folder_btn.grid(row=0, column=3, padx=(0, 8))

        self.clear_log_btn = ttk.Button(
            footer,
            text="Clear log",
            style="Secondary.TButton",
            command=self.clear_log,
            width=10,
        )
        self.clear_log_btn.grid(row=0, column=4)

    ## creating a function that browses for the working folder and refreshes discovered Evidence IDs
    def _browse_working_folder(self) -> None:
        folder = filedialog.askdirectory(
            title="Select Working Folder",
            initialdir=str(self.working_folder),
        )
        if folder:
            self.working_folder_var.set(folder)
            self.refresh_evidence_ids()

    ## creating a function that scans evidence/<case_id>/ for UUIDv4 subfolders and updates the
    ## Combobox
    def refresh_evidence_ids(self, select_id: str | None = None) -> None:
        ids = list_case_evidence_ids(self.working_folder, self.case_id)
        self.evidence_combo.configure(values=ids)
        if select_id:
            self.evidence_id_var.set(select_id)
        elif self.evidence_id not in ids:
            self.evidence_id_var.set(ids[-1] if ids else "")
        self._update_gating_state()

    def on_case_or_evidence_changed(self) -> None:
        self.refresh_evidence_ids()

    def on_target_changed(self, target_id: str) -> None:
        if hasattr(self, "page_analyze"):
            self.page_analyze.on_target_changed(target_id)

    ## creating a function that records whether Phase 1 Verify passed for (case_id, evidence_id) in
    ## this session
    def mark_evidence_verified(self, case_id: str, evidence_id: str, passed: bool) -> None:
        key = (case_id, evidence_id)
        if passed:
            self._verified_evidence.add(key)
        else:
            self._verified_evidence.discard(key)
            self._verified_derived.discard(key)
        self._update_gating_state()

    ## creating a function that records whether Phase 2 Verify derived passed for (case_id,
    ## evidence_id) in this session
    def mark_derived_verified(self, case_id: str, evidence_id: str, passed: bool) -> None:
        key = (case_id, evidence_id)
        if passed:
            self._verified_derived.add(key)
        else:
            self._verified_derived.discard(key)
        self._update_gating_state()

    ## creating a function that updates the lock banners and tab titles on Page 2 and Page 3
    def _update_gating_state(self) -> None:
        key = (self.case_id, self.evidence_id)
        ev_ok = bool(self.evidence_id) and key in self._verified_evidence
        der_ok = ev_ok and key in self._verified_derived

        self.page_parse.set_locked(not ev_ok)
        self.page_analyze.set_locked(not der_ok)

        tab1_label = (
            "  2. Parse & Query (✓ Unlocked)  " if ev_ok else "  2. Parse & Query (Locked)  "
        )
        tab2_label = (
            "  3. Analyze, Detect & Report (✓ Unlocked)  "
            if der_ok
            else "  3. Analyze, Detect & Report (Locked)  "
        )
        self.notebook.tab(1, text=tab1_label)  # type: ignore[no-untyped-call]
        self.notebook.tab(2, text=tab2_label)  # type: ignore[no-untyped-call]

    ## creating a function that ensures an Evidence ID is selected before running a step that
    ## requires one
    def require_evidence_id(self, step: StepBlock) -> str | None:
        eid = self.evidence_id
        if not eid:
            step.chip.set_status("fail")
            step.show_banner(
                "✗ Select an Evidence ID in the top bar (or run Acquire first).",
                "fail",
            )
            return None
        return eid

    def show_missing_key_banner(self) -> None:
        self.missing_key_banner.grid()

    ## creating a function that runs lapa keygen to generate the Ed25519 Signing key (evidence)
    def run_keygen(self) -> None:
        cmd = [*self.lapa_cmd(), "keygen"]

        def on_done(outcome: RunOutcome) -> None:
            data = outcome.parsed_json
            if outcome.returncode == 0 and data:
                self.missing_key_banner.grid_remove()
                priv = data.get("private_key", "")
                pub = data.get("public_key", "")
                self.log_message(
                    f"Created Signing key (evidence) pair: private={priv}, public={pub}",
                    "success",
                )
                messagebox.showinfo(
                    "Signing Keys Created",
                    (
                        "Ed25519 Signing key (evidence) pair "
                        f"created:\n\nPrivate key: {priv}\nPublic key: {pub}"
                    ),
                )
            else:
                msg = outcome.last_stderr_line
                if "exists" in msg.lower():
                    self.missing_key_banner.grid_remove()
                    self.log_message(f"Signing key (evidence) already exists ({msg}).", "info")
                    messagebox.showinfo(
                        "Signing Keys Already Exist",
                        f"Your Ed25519 Signing key (evidence) is already present:\n\n{msg}",
                    )
                else:
                    messagebox.showerror("Key Generation Failed", msg)

        self.run_aux_command("Create signing keys", cmd, on_done=on_done)

    ## creating a function that executes a StepBlock command in the worker thread and updates
    ## progress/chips
    def execute_step(
        self,
        step: StepBlock,
        step_name: str,
        command: list[str],
        *,
        cleanup_path: Path | None = None,
        handler: Callable[[RunOutcome], bool],
    ) -> None:
        if self.runner.is_running:
            return
        step.chip.set_status("running")
        step.show_banner(f"● Running {step_name}…", "info")
        self._set_busy_ui(True, status_text=f"● Running {step_name}…")

        if not self._pipeline_active:
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start(12)

        def on_complete(outcome: RunOutcome) -> None:
            if not self._pipeline_active:
                self.progress_bar.stop()
                self.progress_bar.configure(mode="determinate", value=0)
            self._set_busy_ui(False)
            if outcome.cancelled:
                step.chip.set_status("cancelled")
                step.show_banner(f"✗ {step_name} was cancelled by the user.", "fail")
                self.status_label.configure(text=f"✗ {step_name} cancelled.")
                self._pipeline_active = False
                return
            ok = handler(outcome)
            if ok:
                self.status_label.configure(text=f"✓ {step_name} completed.")
            else:
                self.status_label.configure(text=f"✗ {step_name} failed.")
                self._pipeline_active = False

        self.runner.start(
            step_name,
            command,
            self.working_folder,
            cleanup_path=cleanup_path,
            on_complete=on_complete,
        )

    ## creating a function that runs an auxiliary command (start lab, keygen, IP lookup, SSH test,
    ## preflight)
    def run_aux_command(
        self,
        label: str,
        command: list[str],
        *,
        cwd: Path | None = None,
        cleanup_path: Path | None = None,
        on_done: Callable[[RunOutcome], None] | None = None,
    ) -> None:
        if self.runner.is_running:
            return
        self._set_busy_ui(True, status_text=f"● Running {label}…")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start(12)

        def complete(outcome: RunOutcome) -> None:
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate", value=0)
            self._set_busy_ui(False)
            if outcome.cancelled:
                self.status_label.configure(text=f"✗ {label} cancelled.")
                return
            if outcome.returncode == 0:
                self.status_label.configure(text=f"✓ {label} completed.")
            else:
                self.status_label.configure(text=f"✗ {label} failed: {outcome.last_stderr_line}")
            if on_done:
                on_done(outcome)

        self.runner.start(
            label,
            command,
            cwd if cwd is not None else self.working_folder,
            cleanup_path=cleanup_path,
            on_complete=complete,
        )

    ## creating a function that chains the entire pipeline (Acquire -> Verify -> Parse -> Verify
    ## derived -> Analyze -> Detect -> [Evaluate] -> Report)
    def run_full_pipeline(self) -> None:
        if self.runner.is_running:
            return

        include_eval = (
            report_labels_path(
                self.page_analyze.labels_path_var.get(),
                self.working_folder,
                self.project_root,
            )
            is not None
        )

        steps: list[tuple[str, int, Callable[[Callable[[], None]], None]]] = [
            ("Acquire", 0, self.page_acquire.run_acquire),
            ("Verify", 0, self.page_acquire.run_verify),
            ("Parse", 1, self.page_parse.run_parse),
            ("Verify derived", 1, self.page_parse.run_verify_derived),
            ("Analyze", 2, self.page_analyze.run_analyze),
            ("Detect", 2, self.page_analyze.run_detect),
        ]
        if include_eval:
            steps.append(("Evaluate", 2, self.page_analyze.run_evaluate))
        steps.append(("Report", 2, self.page_analyze.run_report))

        total = len(steps)
        self._pipeline_active = True
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate", maximum=total, value=0)

        def run_index(idx: int) -> None:
            if not self._pipeline_active:
                return
            if idx >= total:
                self._pipeline_active = False
                self.progress_bar.configure(value=total)
                self.status_label.configure(
                    text=f"✓ Full pipeline completed ({total} of {total} steps passed)."
                )
                self.log_message(
                    f"Full pipeline finished successfully ({total}/{total} steps).",
                    "success",
                )
                return

            name, tab_idx, fn = steps[idx]
            self.notebook.select(tab_idx)  # type: ignore[no-untyped-call]
            self.progress_bar.configure(value=idx)
            step_msg = f"Step {idx + 1} of {total} – {name}…"
            self.status_label.configure(text=step_msg)
            self.log_message(f"=== Pipeline {step_msg} ===", "info")

            def next_step() -> None:
                self.progress_bar.configure(value=idx + 1)
                self.root.after(150, lambda: run_index(idx + 1))

            fn(next_step)

        run_index(0)

    ## creating a function that cancels the currently running subprocess
    def cancel_current_command(self) -> None:
        if self.runner.is_running:
            self._pipeline_active = False
            self.log_message("Cancelling active command…", "warning")
            self.runner.cancel()

    ## creating a function that polls the worker thread queue every 100ms and updates widgets on the
    ## main thread
    def _poll_event_queue(self) -> None:
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "cmd" or kind == "stdout":
                    self.log_message(str(payload), "info")
                elif kind == "stderr":
                    tag = "warning" if "warning:" in str(payload).lower() else "error"
                    self.log_message(str(payload), tag)
                elif kind == "done":
                    outcome, callback = payload
                    if outcome.cancelled:
                        self.log_message(f"[{outcome.step_name}] Cancelled.", "warning")
                    elif outcome.returncode == 0:
                        self.log_message(f"[{outcome.step_name}] Finished (exit 0).", "success")
                    else:
                        self.log_message(
                            (
                                f"[{outcome.step_name}] Exited with code "
                                f"{outcome.returncode}: {outcome.last_stderr_line}"
                            ),
                            "error",
                        )
                    if callback is not None:
                        callback(outcome)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_event_queue)

    ## creating a function that appends a timestamped, color-tagged line to the live log box
    def log_message(self, message: str, tag: str = "info") -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, f"[{stamp}] {message}\n", (tag,))
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    ## creating a function that clears the live log text box
    def clear_log(self) -> None:
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.delete("1.0", tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def _set_busy_ui(self, busy: bool, status_text: str | None = None) -> None:
        if status_text and not self._pipeline_active:
            self.status_label.configure(text=status_text)
        self.cancel_btn.configure(state=tk.NORMAL if busy else tk.DISABLED)
        header_state = tk.DISABLED if busy else tk.NORMAL
        for btn in (
            self.browse_work_btn,
            self.refresh_eid_btn,
            self.keygen_btn,
            self.pipeline_btn,
        ):
            btn.configure(state=header_state)
        self.page_acquire.set_busy(busy)
        self.page_parse.set_busy(busy)
        self.page_analyze.set_busy(busy)

    ## creating a function to open a folder or file using the platform file manager
    def open_path(self, target_path: Path) -> None:
        if not target_path.exists():
            messagebox.showerror("Error", f"Path does not exist:\n{target_path}")
            return
        try:
            if sys.platform == "win32":
                os.startfile(str(target_path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(target_path)])
            else:
                subprocess.Popen(["xdg-open", str(target_path)])
        except Exception as error:
            messagebox.showerror("Error", f"Could not open path: {error}")

    ## creating a function to show a confirmation dialog when the user closes the window
    def close_message(self) -> None:
        if self.runner.is_running:
            if messagebox.askyesno(
                title="Command Running – Quit?",
                message="A command is currently running. Cancel it and quit LAPA?",
            ):
                self.runner.cancel()
                self.root.destroy()
            return
        if messagebox.askyesno(title="Quit?", message="Do you really want to quit LAPA?"):
            self.root.destroy()


def main() -> None:
    LapaGUI()


if __name__ == "__main__":
    main()
