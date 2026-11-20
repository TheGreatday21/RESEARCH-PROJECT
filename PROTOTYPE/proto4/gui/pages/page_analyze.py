"""Page 3: Analyze consistency & timeline, Detect attacks, Evaluate against
lab labels, and Generate Report."""

from __future__ import annotations

import json
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any

from gui.runner import RunOutcome, format_cell_value, friendly_consistency_label
from gui.targets import (
    DEFAULT_LAB_LABELS_RELATIVE,
    TARGET_LAB,
    can_run_evaluate,
    default_labels_path_for_target,
    evaluate_idle_status,
    report_labels_path,
    resolve_selected_labels_path,
)
from gui.theme import (
    BG_ENTRY,
    STATUS_PASS,
    STATUS_PASS_BG,
    STATUS_WARN_BG,
    TEXT_COLOR,
)
from gui.widgets import ResultTable, ScrollablePage, StepBlock

ATTACK_CLASSES = ("path_scan", "sqli_like", "traversal", "brute_force", "low_slow")


class AnalyzePage(ScrollablePage):
    """Tab 3: Phase 3 & Phase 4 steps (Analyze, Detect, Evaluate, Report)."""

    def __init__(
        self,
        master: tk.Misc,
        app: Any,
        font_family: str = "Helvetica",
    ) -> None:
        super().__init__(master)
        self.app = app
        self.font_family = font_family
        self._locked = True
        self._busy = False
        self._labels_expanded = False
        self._evaluate_has_run = False

        self.gap_threshold_var = tk.StringVar(value="60")
        initial_labels = default_labels_path_for_target(
            TARGET_LAB, self.app.working_folder, self.app.project_root
        )
        self.labels_path_var = tk.StringVar(value=initial_labels)
        self._last_detections_file: Path | None = None
        self._last_report_md: Path | None = None
        self._last_report_dir: Path | None = None

        # Lock status banner at top of Page 3
        self.lock_banner = tk.Label(
            self.content,
            text="🔒 Locked: run Verify derived on Page 2 first for the selected Evidence ID.",
            anchor="w",
            font=(font_family, 11, "bold"),
            fg="#8a5a00",
            bg=STATUS_WARN_BG,
            padx=12,
            pady=7,
            relief="solid",
            bd=1,
        )
        self.lock_banner.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self._build_analyze_step()
        self._build_detect_step()
        self._build_evaluate_step()
        self._build_report_step()
        self.labels_path_var.trace_add("write", lambda *_: self._refresh_evaluate_state())
        self.set_locked(True)

    ## creating a function that locks or unlocks Page 3 based on whether Page 2 Verify derived
    ## passed
    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        if locked:
            self.lock_banner.configure(
                text="🔒 Locked: run Verify derived on Page 2 first for the selected Evidence ID.",
                fg="#8a5a00",
                bg=STATUS_WARN_BG,
            )
        else:
            self.lock_banner.configure(
                text=(
                    "✓ Unlocked: Derived dataset verified. You can "
                    "now run Analyze, Detect, Evaluate, and Report."
                ),
                fg=STATUS_PASS,
                bg=STATUS_PASS_BG,
            )
        self.step_analyze.set_locked(locked)
        self.step_detect.set_locked(locked)
        self.step_report.set_locked(locked)
        self._refresh_evaluate_state()
        self._refresh_aux_buttons()

    ## creating a function that pre-fills or clears the default Docker lab labels file when the
    ## target choice changes
    def on_target_changed(self, target_id: str) -> None:
        current = self.labels_path_var.get().strip()
        if target_id == TARGET_LAB:
            if not current:
                default_val = default_labels_path_for_target(
                    target_id, self.app.working_folder, self.app.project_root
                )
                if default_val:
                    self.labels_path_var.set(default_val)
        elif current == DEFAULT_LAB_LABELS_RELATIVE:
            self.labels_path_var.set("")
        self._refresh_evaluate_state()

    ## creating a function that enables Evaluate whenever a labels file is chosen (any target)
    def _refresh_evaluate_state(self) -> None:
        labels_text = self.labels_path_var.get()
        enabled = can_run_evaluate(self._locked, labels_text)
        self.step_evaluate.set_locked(not enabled)
        if not labels_text.strip():
            self._evaluate_has_run = False
            self.step_evaluate.chip.set_status("idle", evaluate_idle_status(""))
        elif not self._evaluate_has_run:
            self.step_evaluate.chip.set_status("idle", evaluate_idle_status(labels_text))
        if hasattr(self, "labels_selected_summary"):
            cleaned = labels_text.strip()
            self.labels_selected_summary.configure(
                text=(
                    f"Selected labels file: {cleaned}"
                    if cleaned
                    else "No labels file selected (Evaluate is optional)."
                )
            )

    ## creating a function that builds the Phase 3 Analyze step block (7 consistency checks +
    ## timeline gaps + preview)
    def _build_analyze_step(self) -> None:
        self.step_analyze = StepBlock(
            self.content,
            title="Step 1 – Analyze",
            description=(
                "Checks the logs for gaps, clock drift and "
                "out-of-order times, and builds one timeline."
            ),
            on_run=lambda: self.run_analyze(),
            run_label="Run Analyze",
            font_family=self.font_family,
        )
        self.step_analyze.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        ctrl = self.step_analyze.enable_controls_bar()
        ttk.Label(ctrl, text="Silence gap threshold (seconds):", style="Bold.TLabel").grid(
            row=0, column=0, padx=(0, 8), pady=2, sticky="w"
        )
        self.gap_spin = ttk.Spinbox(
            ctrl,
            from_=1,
            to=86400,
            textvariable=self.gap_threshold_var,
            width=10,
        )
        self.gap_spin.grid(row=0, column=1, padx=(0, 16), pady=2, sticky="w")

        self.preview_timeline_btn = ttk.Button(
            ctrl,
            text="Preview timeline (first 200 events)",
            style="Secondary.TButton",
            command=self.run_timeline_preview,
        )
        self.preview_timeline_btn.grid(row=0, column=2, pady=2, sticky="w")

        area = self.step_analyze.result_area
        area.columnconfigure(0, weight=3)
        area.columnconfigure(1, weight=2)

        # Left: 7 consistency checks table
        checks_box = ttk.Frame(area)
        checks_box.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        checks_box.columnconfigure(0, weight=1)

        ttk.Label(checks_box, text="Consistency Checks (7 checks):", style="Bold.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 2)
        )
        self.consistency_table = ResultTable(
            checks_box,
            columns=(
                ("check", "Check", 250),
                ("result", "Result", 95),
                ("details", "Details", 230),
            ),
            height=7,
        )
        self.consistency_table.grid(row=1, column=0, sticky="ew")

        # Right: Timeline summary + silence gaps table
        tl_box = ttk.Frame(area)
        tl_box.grid(row=0, column=1, sticky="nsew")
        tl_box.columnconfigure(0, weight=1)

        self.timeline_totals_label = ttk.Label(
            tl_box,
            text="Timeline totals: not run yet",
            style="Bold.TLabel",
        )
        self.timeline_totals_label.grid(row=0, column=0, sticky="w", pady=(0, 2))

        self.gaps_table = ResultTable(
            tl_box,
            columns=(
                ("start", "Gap Start (UTC)", 140),
                ("end", "Gap End (UTC)", 140),
                ("seconds", "Seconds", 75),
                ("logs", "Before → After", 105),
            ),
            height=7,
        )
        self.gaps_table.grid(row=1, column=0, sticky="ew")

        # Collapsible timeline preview table (shown when Preview timeline is clicked)
        self.timeline_preview_frame = ttk.Frame(area)
        self.timeline_preview_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.timeline_preview_frame.columnconfigure(0, weight=1)
        self.timeline_preview_frame.grid_remove()

        ttk.Label(
            self.timeline_preview_frame,
            text=(
                "Merged Timeline Preview (first 200 timestamped "
                "access & error events in UTC order):"
            ),
            style="Bold.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 2))

        self.timeline_preview_table = ResultTable(
            self.timeline_preview_frame,
            columns=(
                ("ts_utc", "Timestamp (UTC)", 165),
                ("source", "Log", 65),
                ("summary", "Method / Level & Path / Message", 340),
                ("status", "Status", 65),
                ("ref", "Artifact & Line", 170),
            ),
            height=6,
        )
        self.timeline_preview_table.grid(row=1, column=0, sticky="ew")

    ## creating a function that builds the Phase 4 Detect step block with View detections &
    ## provenance inspector
    def _build_detect_step(self) -> None:
        self.step_detect = StepBlock(
            self.content,
            title="Step 2 – Detect",
            description=(
                "Looks for five attack patterns using clear rules, plus an anomaly detector."
            ),
            on_run=lambda: self.run_detect(),
            run_label="Run Detect",
            font_family=self.font_family,
        )
        self.step_detect.grid(row=2, column=0, sticky="ew", pady=(0, 8))

        ctrl = self.step_detect.enable_controls_bar()
        self.detect_totals_label = ttk.Label(
            ctrl,
            text="Scored requests: 0  |  Rule detections: 0  |  Isolation Forest anomalies: 0",
            style="Bold.TLabel",
        )
        self.detect_totals_label.grid(row=0, column=0, padx=(0, 16), sticky="w")

        self.view_detections_btn = ttk.Button(
            ctrl,
            text="View detections",
            style="Secondary.TButton",
            command=self._load_detections_table,
            state=tk.DISABLED,
        )
        self.view_detections_btn.grid(row=0, column=1, sticky="w")

        area = self.step_detect.result_area
        area.columnconfigure(0, weight=1)
        area.columnconfigure(1, weight=2)

        self.class_table = ResultTable(
            area,
            columns=(
                ("attack_class", "Attack Class", 140),
                ("count", "Detections", 100),
            ),
            height=5,
        )
        self.class_table.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        det_right = ttk.Frame(area)
        det_right.grid(row=0, column=1, sticky="nsew")
        det_right.columnconfigure(0, weight=1)

        self.detections_table = ResultTable(
            det_right,
            columns=(
                ("ts_utc", "Time (UTC)", 150),
                ("attack_class", "Class", 95),
                ("detector", "Rule", 125),
                ("remote_addr", "Client IP", 100),
                ("status", "HTTP", 55),
                ("uri_raw", "Request URI", 200),
            ),
            height=5,
            on_select=self._on_detection_row_selected,
        )
        self.detections_table.grid(row=0, column=0, sticky="ew")

        self.detection_detail_label = ttk.Label(
            det_right,
            text=(
                "Select a detection row above to inspect its exact "
                "log provenance (artifact_path, line_no, byte_offset)."
            ),
            style="Muted.TLabel",
            wraplength=560,
        )
        self.detection_detail_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

    ## creating a function that builds the Phase 4 Evaluate step block with a collapsed
    ## ground-truth labels picker
    def _build_evaluate_step(self) -> None:
        self.step_evaluate = StepBlock(
            self.content,
            title="Step 3 – Evaluate",
            description="Scores the detectors against a ground-truth labels file.",
            on_run=lambda: self.run_evaluate(),
            run_label="Run Evaluate",
            font_family=self.font_family,
        )
        self.step_evaluate.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        ctrl = self.step_evaluate.enable_controls_bar()
        ctrl.columnconfigure(1, weight=1)

        self.labels_toggle_btn = ttk.Button(
            ctrl,
            text="▸ Advanced: ground-truth labels (testing only)",
            style="Secondary.TButton",
            command=self._toggle_labels_section,
        )
        self.labels_toggle_btn.grid(row=0, column=0, sticky="w", pady=(0, 2))

        self.labels_selected_summary = ttk.Label(
            ctrl,
            text="",
            style="Muted.TLabel",
        )
        self.labels_selected_summary.grid(row=0, column=1, padx=(12, 0), sticky="w", pady=(0, 2))

        self.labels_drawer = ttk.Frame(ctrl)
        self.labels_drawer.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 2))
        self.labels_drawer.columnconfigure(1, weight=1)
        self.labels_drawer.grid_remove()

        ttk.Label(
            self.labels_drawer,
            text=(
                "Labels tell LAPA which requests are known attacks so it can score itself. "
                "Real servers do not have them."
            ),
            style="Muted.TLabel",
            wraplength=780,
        ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 4))

        ttk.Label(self.labels_drawer, text="Labels file:", style="Bold.TLabel").grid(
            row=1, column=0, padx=(0, 8), pady=2, sticky="w"
        )
        self.labels_entry = ttk.Entry(self.labels_drawer, textvariable=self.labels_path_var)
        self.labels_entry.grid(row=1, column=1, padx=(0, 8), pady=2, sticky="ew")

        self.browse_labels_btn = ttk.Button(
            self.labels_drawer,
            text="Browse…",
            style="Secondary.TButton",
            command=self._browse_labels_file,
        )
        self.browse_labels_btn.grid(row=1, column=2, padx=(0, 6), pady=2)

        self.clear_labels_btn = ttk.Button(
            self.labels_drawer,
            text="Clear",
            style="Secondary.TButton",
            command=self._clear_labels_file,
        )
        self.clear_labels_btn.grid(row=1, column=3, pady=2)

        self.evaluate_table = ResultTable(
            self.step_evaluate.result_area,
            columns=(
                ("class", "Class / Scope", 160),
                ("precision", "Precision", 100),
                ("recall", "Recall", 100),
                ("f1", "F1 Score", 100),
                ("tp", "True Pos", 90),
                ("fp", "False Pos", 90),
                ("fn", "False Neg", 90),
            ),
            height=6,
        )
        self.evaluate_table.grid(row=0, column=0, sticky="ew", pady=2)

    ## creating a function that collapses or expands the Advanced ground-truth labels drawer
    def _toggle_labels_section(self) -> None:
        self._labels_expanded = not self._labels_expanded
        if self._labels_expanded:
            self.labels_toggle_btn.configure(text="▾ Advanced: ground-truth labels (testing only)")
            self.labels_drawer.grid()
        else:
            self.labels_toggle_btn.configure(text="▸ Advanced: ground-truth labels (testing only)")
            self.labels_drawer.grid_remove()

    def _browse_labels_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select Ground-Truth Labels JSONL File",
            initialdir=str(self.app.working_folder),
            filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")],
        )
        if selected:
            self.labels_path_var.set(selected)

    def _clear_labels_file(self) -> None:
        self.labels_path_var.set("")

    ## creating a function that builds the Phase 4 Report step block with Open report / Open folder
    ## buttons and preview
    def _build_report_step(self) -> None:
        self.step_report = StepBlock(
            self.content,
            title="Step 4 – Report",
            description="Re-verifies everything and writes the forensic report.",
            on_run=lambda: self.run_report(),
            run_label="Run Report",
            font_family=self.font_family,
        )
        self.step_report.grid(row=4, column=0, sticky="ew", pady=(0, 8))

        ctrl = self.step_report.enable_controls_bar()
        self.report_summary_label = ttk.Label(
            ctrl,
            text="Report not generated yet.",
            style="Bold.TLabel",
        )
        self.report_summary_label.grid(row=0, column=0, padx=(0, 16), sticky="w")

        self.open_report_btn = ttk.Button(
            ctrl,
            text="Open report",
            style="Secondary.TButton",
            command=self._open_report_file,
            state=tk.DISABLED,
        )
        self.open_report_btn.grid(row=0, column=1, padx=(0, 8))

        self.open_report_folder_btn = ttk.Button(
            ctrl,
            text="Open folder",
            style="Secondary.TButton",
            command=self._open_report_folder,
            state=tk.DISABLED,
        )
        self.open_report_folder_btn.grid(row=0, column=2)

        self.report_preview = tk.Text(
            self.step_report.result_area,
            height=9,
            state=tk.DISABLED,
            font=(self.font_family, 10),
            fg=TEXT_COLOR,
            bg=BG_ENTRY,
            relief="solid",
            bd=1,
            highlightthickness=0,
            wrap="word",
        )
        self.report_preview.grid(row=0, column=0, sticky="ew", pady=2)

    ## creating a function that runs lapa analyze and displays the 7 consistency checks and timeline
    ## gaps
    def run_analyze(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_analyze)
        if not eid:
            return
        gap_val = self.gap_threshold_var.get().strip() or "60"
        cmd = [
            *self.app.lapa_cmd(),
            "analyze",
            self.app.case_id,
            "--evidence-id",
            eid,
            "--gap-threshold",
            gap_val,
        ]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_analyze.json_viewer.set_data(data, outcome.stdout)
            self.consistency_table.clear()
            self.gaps_table.clear()

            if not data or not isinstance(data.get("results"), list) or not data["results"]:
                self.step_analyze.chip.set_status("fail")
                self.step_analyze.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            entry = data["results"][0]
            checks = entry.get("checks", [])
            has_warn = False
            has_fail = bool(entry.get("has_failures"))

            for chk in checks:
                if not isinstance(chk, dict):
                    continue
                name = str(chk.get("name", ""))
                status = str(chk.get("status", "pass")).lower()
                if status == "fail":
                    badge = "✗ Failed"
                    tag = "fail"
                    has_fail = True
                elif status == "warn":
                    badge = "▲ Warning"
                    tag = "warn"
                    has_warn = True
                else:
                    badge = "✓ Passed"
                    tag = "pass"
                self.consistency_table.add_row(
                    (friendly_consistency_label(name), badge, chk.get("message", "")),
                    tag=tag,
                )

            total_events = entry.get("total_events", 0)
            unparsed_count = entry.get("unparsed_count", 0)
            gaps_count = entry.get("gaps", 0)
            self.timeline_totals_label.configure(
                text=(
                    f"Timeline: {total_events} events  |  Unparsed: "
                    f"{unparsed_count}  |  Gaps: {gaps_count}"
                )
            )

            # Read detailed gap list from timeline_report.json
            tl_path_str = entry.get("timeline_report")
            if isinstance(tl_path_str, str):
                tl_path = Path(tl_path_str)
                if not tl_path.is_absolute():
                    tl_path = self.app.working_folder / tl_path
                if tl_path.is_file():
                    try:
                        tl_doc = json.loads(tl_path.read_text(encoding="utf-8"))
                        for g in tl_doc.get("gaps", []):
                            if isinstance(g, dict):
                                self.gaps_table.add_row(
                                    (
                                        g.get("after_ts_utc", ""),
                                        g.get("before_ts_utc", ""),
                                        g.get("gap_seconds", ""),
                                        (
                                            f"{g.get('after_source', '')} → "
                                            f"{g.get('before_source', '')}"
                                        ),
                                    )
                                )
                    except (OSError, json.JSONDecodeError):
                        pass

            if has_fail:
                self.step_analyze.chip.set_status("fail")
                self.step_analyze.show_banner(
                    "✗ One or more consistency checks failed. Inspect the table below.",
                    "fail",
                )
                return False
            if has_warn:
                self.step_analyze.chip.set_status("warn")
                self.step_analyze.show_banner(
                    (
                        "▲ Consistency checks completed with warnings "
                        f"({total_events} events, {gaps_count} silence gap(s))."
                    ),
                    "warn",
                )
                if on_success:
                    on_success()
                return True

            self.step_analyze.chip.set_status("pass")
            self.step_analyze.show_banner(
                (
                    f"✓ All 7 consistency checks passed ({total_events} "
                    f"timeline events, {gaps_count} silence gap(s))."
                ),
                "pass",
            )
            if on_success:
                on_success()
            return True

        self.app.execute_step(self.step_analyze, "Analyze", cmd, handler=handle)

    ## creating a function that previews the first 200 merged timeline events via a read-only lapa
    ## sql query
    def run_timeline_preview(self) -> None:
        eid = self.app.require_evidence_id(self.step_analyze)
        if not eid:
            return
        query = (
            "SELECT ts_utc, 'access' AS source, "
            "coalesce(method, '') || ' ' || coalesce(path, raw_line) AS summary, "
            "CAST(status AS VARCHAR) AS status, "
            "artifact_path || ' L' || CAST(line_no AS VARCHAR) AS ref "
            "FROM access WHERE ts_utc IS NOT NULL "
            "UNION ALL "
            "SELECT ts_utc, 'error' AS source, "
            "'[' || coalesce(level, 'error') || '] ' || coalesce(message, raw_line) AS summary, "
            "'' AS status, "
            "artifact_path || ' L' || CAST(line_no AS VARCHAR) AS ref "
            "FROM error WHERE ts_utc IS NOT NULL "
            "ORDER BY ts_utc, source, ref LIMIT 200"
        )
        cmd = [*self.app.lapa_cmd(), "sql", self.app.case_id, eid, query]

        def on_done(outcome: RunOutcome) -> None:
            data = outcome.parsed_json
            self.timeline_preview_table.clear()
            if outcome.returncode == 0 and data and isinstance(data.get("rows"), list):
                self.timeline_preview_frame.grid()
                for row in data["rows"]:
                    if isinstance(row, list):
                        self.timeline_preview_table.add_row(row)

        self.app.run_aux_command("Preview timeline (200 events)", cmd, on_done=on_done)

    ## creating a function that runs lapa detect and displays rule detections and Isolation Forest
    ## anomalies
    def run_detect(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_detect)
        if not eid:
            return
        cmd = [*self.app.lapa_cmd(), "detect", self.app.case_id, "--evidence-id", eid]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_detect.json_viewer.set_data(data, outcome.stdout)
            self.class_table.clear()
            self.detections_table.clear()

            if outcome.returncode != 0 or not data or not data.get("results"):
                self.step_detect.chip.set_status("fail")
                self.step_detect.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            entry = data["results"][0]
            scored = entry.get("scored_requests", 0)
            total_det = entry.get("total_detections", 0)
            if_anom = entry.get("isolation_forest_anomalies", 0)
            if_max = entry.get("isolation_forest_max_score", 0.0)
            by_class = entry.get("by_class", {}) if isinstance(entry.get("by_class"), dict) else {}

            self.detect_totals_label.configure(
                text=(
                    f"Scored requests: {scored}  |  Rule detections: {total_det}  |  "
                    f"Isolation Forest anomalies: {if_anom} (max score: {if_max})"
                )
            )
            for cls_name in ATTACK_CLASSES:
                self.class_table.add_row((cls_name, by_class.get(cls_name, 0)))

            det_file = entry.get("detections_file")
            if isinstance(det_file, str):
                p = Path(det_file)
                self._last_detections_file = p if p.is_absolute() else (self.app.working_folder / p)
                self.view_detections_btn.configure(state=tk.NORMAL)
                self._load_detections_table()

            self.step_detect.chip.set_status("pass")
            self.step_detect.show_banner(
                (
                    f"✓ Detection complete: {total_det} rule detection(s) and "
                    f"{if_anom} Isolation Forest anomaly(ies) across {scored} requests."
                ),
                "pass",
            )
            if on_success:
                on_success()
            return True

        self.app.execute_step(self.step_detect, "Detect", cmd, handler=handle)

    ## creating a function that loads detections.json into the detections table and wires provenance
    ## selection
    def _load_detections_table(self) -> None:
        self.detections_table.clear()
        if self._last_detections_file is None or not self._last_detections_file.is_file():
            return
        try:
            doc = json.loads(self._last_detections_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for d in doc.get("detections", []):
            if not isinstance(d, dict):
                continue
            self.detections_table.add_row(
                (
                    d.get("ts_utc", ""),
                    d.get("attack_class", ""),
                    d.get("detector", ""),
                    d.get("remote_addr", ""),
                    d.get("status", ""),
                    d.get("uri_raw", ""),
                ),
                payload=d,
            )

    def _on_detection_row_selected(self, payload: dict[str, Any]) -> None:
        self.detection_detail_label.configure(
            text=(
                f"Provenance: artifact_path={payload.get('artifact_path')}  |  "
                f"line_no={payload.get('line_no')}  |  "
                f"byte_offset={payload.get('byte_offset')}  |  "
                f"confidence={payload.get('confidence')}  |  "
                f"trace_id={payload.get('trace_id') or 'n/a'}\n"
                f"Reason: {payload.get('reason')}"
            )
        )

    ## creating a function that runs lapa evaluate against the selected ground-truth labels file
    def run_evaluate(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_evaluate)
        if not eid:
            return
        labels_str = self.labels_path_var.get().strip()
        labels_path = resolve_selected_labels_path(
            labels_str, self.app.working_folder, self.app.project_root
        )
        if labels_path is None or not labels_path.is_file():
            self.step_evaluate.chip.set_status("idle", evaluate_idle_status(""))
            self.step_evaluate.show_banner(
                "No labels file selected or file not found. Choose one under Advanced above.",
                "info",
            )
            return

        cmd = [
            *self.app.lapa_cmd(),
            "evaluate",
            self.app.case_id,
            "--evidence-id",
            eid,
            "--labels",
            str(labels_path),
        ]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_evaluate.json_viewer.set_data(data, outcome.stdout)
            self.evaluate_table.clear()

            if outcome.returncode != 0 or not data or not data.get("results"):
                self.step_evaluate.chip.set_status("fail")
                self.step_evaluate.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            entry = data["results"][0]
            overall = entry.get("overall_attack_vs_benign", {})
            if isinstance(overall, dict):
                self.evaluate_table.add_row(
                    (
                        "Overall (Attack vs Benign)",
                        format_cell_value(overall.get("precision")),
                        format_cell_value(overall.get("recall")),
                        format_cell_value(overall.get("f1")),
                        overall.get("true_positives", 0),
                        overall.get("false_positives", 0),
                        overall.get("false_negatives", 0),
                    ),
                    tag="pass",
                )

            per_class = entry.get("per_class", {})
            if isinstance(per_class, dict):
                for cls_name in ATTACK_CLASSES:
                    m = per_class.get(cls_name, {})
                    if isinstance(m, dict):
                        self.evaluate_table.add_row(
                            (
                                cls_name,
                                format_cell_value(m.get("precision")),
                                format_cell_value(m.get("recall")),
                                format_cell_value(m.get("f1")),
                                m.get("true_positives", 0),
                                m.get("false_positives", 0),
                                m.get("false_negatives", 0),
                            )
                        )

            self._evaluate_has_run = True
            unlabelled_det = entry.get("unlabelled_detections_count")
            unlabelled_note = (
                f"; {unlabelled_det} unlabelled detection(s) not scored"
                if isinstance(unlabelled_det, int) and unlabelled_det > 0
                else ""
            )
            self.step_evaluate.chip.set_status("pass")
            self.step_evaluate.show_banner(
                (
                    f"✓ Evaluated {entry.get('labelled_rows', 0)} "
                    f"labelled requests (overall F1={overall.get('f1')}{unlabelled_note})."
                ),
                "pass",
            )
            if on_success:
                on_success()
            return True

        self.app.execute_step(self.step_evaluate, "Evaluate", cmd, handler=handle)

    ## creating a function that runs lapa report and previews the generated Markdown report
    def run_report(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_report)
        if not eid:
            return
        gap_val = self.gap_threshold_var.get().strip() or "60"
        cmd = [
            *self.app.lapa_cmd(),
            "report",
            self.app.case_id,
            "--evidence-id",
            eid,
            "--gap-threshold",
            gap_val,
        ]
        chosen_labels = report_labels_path(
            self.labels_path_var.get(),
            self.app.working_folder,
            self.app.project_root,
        )
        if chosen_labels is not None:
            cmd.extend(["--labels", str(chosen_labels)])

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_report.json_viewer.set_data(data, outcome.stdout)

            if outcome.returncode != 0 or not data or not data.get("results"):
                self.step_report.chip.set_status("fail")
                self.step_report.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            entry = data["results"][0]
            md_str = str(entry.get("report_markdown", ""))
            md_path = Path(md_str)
            if not md_path.is_absolute():
                md_path = self.app.working_folder / md_path

            self._last_report_md = md_path
            self._last_report_dir = md_path.parent
            self.open_report_btn.configure(state=tk.NORMAL)
            self.open_report_folder_btn.configure(state=tk.NORMAL)

            total_det = entry.get("total_detections", 0)
            cons_ok = entry.get("consistency_ok", False)
            self.report_summary_label.configure(
                text=(
                    f"Total detections: {total_det}  |  Consistency "
                    f"passed: {cons_ok}  |  File: {md_str}"
                )
            )

            if md_path.is_file():
                try:
                    md_text = md_path.read_text(encoding="utf-8")
                    self.report_preview.configure(state=tk.NORMAL)
                    self.report_preview.delete("1.0", tk.END)
                    self.report_preview.insert("1.0", md_text)
                    self.report_preview.configure(state=tk.DISABLED)
                except OSError:
                    pass

            self.step_report.chip.set_status("pass")
            self.step_report.show_banner(
                (
                    f"✓ Forensic report written to {md_str} "
                    f"(consistency_ok={cons_ok}, detections={total_det})."
                ),
                "pass",
            )
            if on_success:
                on_success()
            return True

        self.app.execute_step(self.step_report, "Report", cmd, handler=handle)

    def _open_report_file(self) -> None:
        if self._last_report_md and self._last_report_md.exists():
            self.app.open_path(self._last_report_md)

    def _open_report_folder(self) -> None:
        if self._last_report_dir and self._last_report_dir.is_dir():
            self.app.open_path(self._last_report_dir)

    def _refresh_aux_buttons(self) -> None:
        can_use = not self._busy and not self._locked
        self.preview_timeline_btn.configure(state=tk.NORMAL if can_use else tk.DISABLED)
        self.browse_labels_btn.configure(state=tk.NORMAL if can_use else tk.DISABLED)
        self.clear_labels_btn.configure(state=tk.NORMAL if can_use else tk.DISABLED)

    ## creating a function that disables or enables Page 3 controls while a command runs
    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.step_analyze.set_busy(busy)
        self.step_detect.set_busy(busy)
        self.step_evaluate.set_busy(busy)
        self.step_report.set_busy(busy)
        self._refresh_aux_buttons()
