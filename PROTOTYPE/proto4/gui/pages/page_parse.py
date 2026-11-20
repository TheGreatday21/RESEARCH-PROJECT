"""Page 2: Parse logs into Parquet tables, Verify derived dataset, and run DuckDB SQL queries."""

from __future__ import annotations

import json
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import ttk
from typing import Any

from gui.runner import (
    RunOutcome,
    format_cell_value,
    format_verify_derived_checks,
    validate_and_wrap_sql,
)
from gui.theme import (
    BG_ENTRY,
    STATUS_FAIL,
    STATUS_FAIL_BG,
    STATUS_PASS,
    STATUS_PASS_BG,
    STATUS_WARN_BG,
    TEXT_COLOR,
)
from gui.widgets import ResultTable, ScrollablePage, StepBlock, Tooltip

SQL_PRESETS: tuple[tuple[str, str], ...] = (
    (
        "Requests per HTTP status code",
        "SELECT status, count(*) AS requests FROM access GROUP BY status ORDER BY requests DESC",
    ),
    (
        "Top 10 requested paths",
        (
            "SELECT path, status, count(*) AS hits FROM access "
            "GROUP BY path, status ORDER BY hits DESC LIMIT 10"
        ),
    ),
    (
        "Error log counts by severity level",
        "SELECT level, count(*) AS errors FROM error GROUP BY level ORDER BY errors DESC",
    ),
    (
        "Lines that failed to parse",
        "SELECT count(*) AS unparsed_lines FROM access WHERE NOT parse_ok",
    ),
    (
        "Sample 20 access requests with timestamps",
        (
            "SELECT ts_utc, remote_addr, method, path, status, "
            "request_time, line_no FROM access ORDER BY line_no LIMIT 20"
        ),
    ),
)

SQL_COLUMNS_HELP = (
    "Available tables:\n"
    "• access: ts_utc, artifact_path, line_no, byte_offset, byte_length, method, status, path, "
    "path_decoded, query_decoded, request_time, remote_addr, "
    "user_agent, trace_id, raw_line, parse_ok, beyond_prefix\n"
    "• error: ts_utc, artifact_path, line_no, byte_offset, level, pid, tid, cid, "
    "message, client, server, request, upstream, host, raw_line, parse_ok\n\n"
    "Note: The single-statement SELECT/WITH guard is a "
    "convenience for demo users and not a security boundary."
)


class ParsePage(ScrollablePage):
    """Tab 2: Phase 2 steps (Parse, Verify derived, and interactive DuckDB SQL query)."""

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
        self.allow_unverified_var = tk.BooleanVar(value=False)
        self._adv_expanded = False
        self.preset_var = tk.StringVar(value=SQL_PRESETS[0][0])

        # Lock status banner at top of Page 2
        self.lock_banner = tk.Label(
            self.content,
            text="🔒 Locked: run Verify on Page 1 first for the selected Evidence ID.",
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

        self._build_parse_step()
        self._build_verify_derived_step()
        self._build_sql_step()
        self.set_locked(True)

    ## creating a function that locks or unlocks Page 2 depending on whether Page 1 Verify passed
    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        if locked:
            self.lock_banner.configure(
                text="🔒 Locked: run Verify on Page 1 first for the selected Evidence ID.",
                fg="#8a5a00",
                bg=STATUS_WARN_BG,
            )
        else:
            self.lock_banner.configure(
                text=(
                    "✓ Unlocked: Evidence verified in this session. You can "
                    "now parse, verify derived tables, and run SQL queries."
                ),
                fg=STATUS_PASS,
                bg=STATUS_PASS_BG,
            )
        self.step_parse.set_locked(locked)
        self.step_verify_derived.set_locked(locked)
        self.step_sql.set_locked(locked)

    ## creating a function that builds the Parse step block with a collapsed Advanced --allow-
    ## unverified option
    def _build_parse_step(self) -> None:
        self.step_parse = StepBlock(
            self.content,
            title="Step 1 – Parse",
            description="Turns the raw log lines into tables without losing a single byte.",
            on_run=lambda: self.run_parse(),
            run_label="Run Parse",
            font_family=self.font_family,
        )
        self.step_parse.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        ctrl = self.step_parse.enable_controls_bar()
        self.adv_btn = ttk.Button(
            ctrl,
            text="▸ Advanced options",
            style="Secondary.TButton",
            command=self._toggle_advanced,
        )
        self.adv_btn.grid(row=0, column=0, sticky="w")

        self.adv_frame = ttk.Frame(ctrl)
        self.adv_frame.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.adv_frame.grid_remove()

        self.unverified_cb = ttk.Checkbutton(
            self.adv_frame,
            text="Allow unverified evidence (--allow-unverified)",
            variable=self.allow_unverified_var,
            command=self._on_unverified_toggled,
        )
        self.unverified_cb.grid(row=0, column=0, sticky="w")

        self.unverified_warn = tk.Label(
            self.adv_frame,
            text=(
                "⚠ Warning: The evidence will NOT be required to pass verification "
                "before parsing, and the derived dataset will be marked unverified."
            ),
            fg=STATUS_FAIL,
            bg=STATUS_FAIL_BG,
            font=(self.font_family, 10, "bold"),
            padx=8,
            pady=4,
            relief="solid",
            bd=1,
        )
        self.unverified_warn.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.unverified_warn.grid_remove()

        self.parse_table = ResultTable(
            self.step_parse.result_area,
            columns=(
                ("metric", "Parse Summary Metric", 240),
                ("value", "Value", 540),
            ),
            height=5,
        )
        self.parse_table.grid(row=0, column=0, sticky="ew", pady=2)

    def _toggle_advanced(self) -> None:
        self._adv_expanded = not self._adv_expanded
        if self._adv_expanded:
            self.adv_btn.configure(text="▾ Advanced options")
            self.adv_frame.grid()
        else:
            self.adv_btn.configure(text="▸ Advanced options")
            self.adv_frame.grid_remove()

    def _on_unverified_toggled(self) -> None:
        if self.allow_unverified_var.get():
            self.unverified_warn.grid()
        else:
            self.unverified_warn.grid_remove()

    ## creating a function that builds the Verify derived step block
    def _build_verify_derived_step(self) -> None:
        self.step_verify_derived = StepBlock(
            self.content,
            title="Step 2 – Verify derived",
            description="Proves the tables still match the original signed evidence.",
            on_run=lambda: self.run_verify_derived(),
            run_label="Run Verify derived",
            font_family=self.font_family,
        )
        self.step_verify_derived.grid(row=2, column=0, sticky="ew", pady=(0, 8))

        self.verify_derived_table = ResultTable(
            self.step_verify_derived.result_area,
            columns=(
                ("check", "Derived Check", 220),
                ("status", "Status", 105),
                ("label", "What Was Checked", 330),
                ("message", "Detail", 220),
            ),
            height=6,
        )
        self.verify_derived_table.grid(row=0, column=0, sticky="ew", pady=2)

    ## creating a function that builds the SQL query step block with preset dropdown and results
    ## table
    def _build_sql_step(self) -> None:
        self.step_sql = StepBlock(
            self.content,
            title="Step 3 – SQL query",
            description="Ask questions of the parsed logs.",
            on_run=lambda: self.run_sql(),
            run_label="Run Query",
            font_family=self.font_family,
        )
        self.step_sql.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        ctrl = self.step_sql.enable_controls_bar()
        ctrl.columnconfigure(1, weight=1)

        ttk.Label(ctrl, text="Preset query:", style="Bold.TLabel").grid(
            row=0, column=0, padx=(0, 8), pady=4, sticky="w"
        )
        preset_names = [name for name, _ in SQL_PRESETS]
        self.preset_combo = ttk.Combobox(
            ctrl,
            textvariable=self.preset_var,
            values=preset_names,
            state="readonly",
        )
        self.preset_combo.grid(row=0, column=1, padx=(0, 8), pady=4, sticky="ew")
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        self.info_badge = ttk.Label(
            ctrl,
            text="ⓘ Tables: access, error (hover for columns & guard note)",
            style="Muted.TLabel",
        )
        self.info_badge.grid(row=0, column=2, padx=(4, 0), pady=4, sticky="e")
        Tooltip(self.info_badge, SQL_COLUMNS_HELP, self.font_family)

        self.sql_text = tk.Text(
            ctrl,
            height=3,
            font=("Menlo" if self.font_family != "Consolas" else "Consolas", 11),
            fg=TEXT_COLOR,
            bg=BG_ENTRY,
            relief="solid",
            bd=1,
            highlightthickness=0,
        )
        self.sql_text.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(4, 2))
        self.sql_text.insert("1.0", SQL_PRESETS[0][1])
        Tooltip(self.sql_text, SQL_COLUMNS_HELP, self.font_family)

        self.sql_row_info = ttk.Label(
            self.step_sql.result_area,
            text="Run a query to view results.",
            style="Muted.TLabel",
        )
        self.sql_row_info.grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.sql_table = ResultTable(
            self.step_sql.result_area,
            columns=(("col", "Result", 400),),
            height=8,
        )
        self.sql_table.grid(row=1, column=0, sticky="ew", pady=2)

    def _on_preset_selected(self, _event: tk.Event[Any] | None = None) -> None:
        chosen = self.preset_var.get()
        for name, sql in SQL_PRESETS:
            if name == chosen:
                self.sql_text.delete("1.0", tk.END)
                self.sql_text.insert("1.0", sql)
                break

    ## creating a function that runs lapa parse and displays row counts and output folder
    def run_parse(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_parse)
        if not eid:
            return
        cmd = [*self.app.lapa_cmd(), "parse", self.app.case_id, "--evidence-id", eid]
        if self.allow_unverified_var.get():
            cmd.append("--allow-unverified")

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_parse.json_viewer.set_data(data, outcome.stdout)
            self.parse_table.clear()

            if "signing key not found" in outcome.stderr.lower():
                self.app.show_missing_key_banner()
                self.step_parse.chip.set_status("fail")
                self.step_parse.show_banner(
                    (
                        "Signing key (evidence) not found. Click "
                        "'Create signing keys' in the top bar first."
                    ),
                    "fail",
                )
                return False

            # If derived output already exists from an earlier parse, load its summary cleanly
            if outcome.returncode != 0 and "derived output already exists" in outcome.stderr:
                out_dir = self.app.working_folder / "derived" / self.app.case_id / eid
                self._populate_parse_summary_from_disk(out_dir, None)
                self.step_parse.chip.set_status("pass")
                self.step_parse.show_banner(
                    (
                        "✓ Derived Parquet tables already exist at "
                        f"derived/{self.app.case_id}/{eid}. Ready for Verify derived."
                    ),
                    "pass",
                )
                if on_success:
                    on_success()
                return True

            if outcome.returncode != 0 or not data or not data.get("results"):
                self.step_parse.chip.set_status("fail")
                self.step_parse.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            entry = data["results"][0]
            out_dir_str = str(entry.get("output_directory", f"derived/{self.app.case_id}/{eid}"))
            out_dir = Path(out_dir_str)
            if not out_dir.is_absolute():
                out_dir = self.app.working_folder / out_dir

            self._populate_parse_summary_from_disk(out_dir, entry)
            ev_verified = bool(entry.get("evidence_verified", True))
            if ev_verified:
                self.step_parse.chip.set_status("pass")
                self.step_parse.show_banner(
                    f"✓ Parsed logs into signed Parquet tables under {out_dir_str}.",
                    "pass",
                )
            else:
                self.step_parse.chip.set_status("warn")
                self.step_parse.show_banner(
                    f"▲ Parsed with --allow-unverified into {out_dir_str}.",
                    "warn",
                )
            if on_success:
                on_success()
            return True

        self.app.execute_step(self.step_parse, "Parse", cmd, handler=handle)

    def _populate_parse_summary_from_disk(
        self, out_dir: Path, entry: dict[str, Any] | None
    ) -> None:
        self.parse_table.clear()
        if entry:
            self.parse_table.add_row(("Output Folder", entry.get("output_directory")))
            self.parse_table.add_row(("Derived ID", entry.get("derived_id")))
            self.parse_table.add_row(
                (
                    "Evidence Verified Before Parse",
                    entry.get("evidence_verified"),
                )
            )
            self.parse_table.add_row(("Canonical Content Hash", entry.get("content_hash")))
        else:
            self.parse_table.add_row(("Output Folder", str(out_dir)))

        report_path = out_dir / "parse_report.json"
        if report_path.is_file():
            try:
                rep = json.loads(report_path.read_text(encoding="utf-8"))
                self.parse_table.add_row(("Total Physical Lines", rep.get("total_lines")))
                self.parse_table.add_row(("Rows Parsed Successfully", rep.get("parsed_lines")))
                self.parse_table.add_row(
                    (
                        "Unparsed Rows (retained raw)",
                        rep.get("unparsed_lines"),
                    )
                )
                self.parse_table.add_row(
                    (
                        "Total Bytes & 100% Byte Coverage",
                        f"{rep.get('total_bytes')} bytes (coverage={rep.get('byte_coverage')})",
                    )
                )
            except (OSError, json.JSONDecodeError):
                pass

    ## creating a function that runs lapa verify-derived and unlocks Page 3 when all checks pass
    def run_verify_derived(self, on_success: Callable[[], None] | None = None) -> None:
        eid = self.app.require_evidence_id(self.step_verify_derived)
        if not eid:
            return
        cmd = [*self.app.lapa_cmd(), "verify-derived", self.app.case_id, "--evidence-id", eid]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_verify_derived.json_viewer.set_data(data, outcome.stdout)
            self.verify_derived_table.clear()

            if not data or not isinstance(data.get("results"), list) or not data["results"]:
                self.step_verify_derived.chip.set_status("fail")
                self.step_verify_derived.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            entry = data["results"][0]
            for row in format_verify_derived_checks(entry):
                passed = bool(row["passed"])
                self.verify_derived_table.add_row(
                    (
                        row["name"],
                        "✓ Passed" if passed else "✗ Failed",
                        row["label"],
                        row["message"],
                    ),
                    tag="pass" if passed else "fail",
                )

            overall_ok = bool(data.get("ok")) and bool(entry.get("ok")) and outcome.returncode == 0
            if overall_ok:
                self.step_verify_derived.chip.set_status("pass")
                self.step_verify_derived.show_banner(
                    (
                        "✓ Passed: Derived Parquet tables and canonical row hashes "
                        f"match signed evidence {eid}. Page 3 is now unlocked."
                    ),
                    "pass",
                )
                self.app.mark_derived_verified(self.app.case_id, eid, True)
                if on_success:
                    on_success()
                return True

            failed = ", ".join(str(x) for x in entry.get("failed_checks", []))
            self.step_verify_derived.chip.set_status("fail")
            self.step_verify_derived.show_banner(
                f"✗ Derived verification failed: {failed or outcome.last_stderr_line}",
                "fail",
            )
            self.app.mark_derived_verified(self.app.case_id, eid, False)
            return False

        self.app.execute_step(self.step_verify_derived, "Verify derived", cmd, handler=handle)

    ## creating a function that validates the SQL query, wraps it with LIMIT 1001, and renders the
    ## DuckDB result table
    def run_sql(self) -> None:
        eid = self.app.require_evidence_id(self.step_sql)
        if not eid:
            return
        raw_query = self.sql_text.get("1.0", tk.END)
        try:
            wrapped_query = validate_and_wrap_sql(raw_query, limit=1001)
        except ValueError as error:
            self.step_sql.chip.set_status("fail")
            self.step_sql.show_banner(f"✗ SQL validation error: {error}", "fail")
            return

        cmd = [*self.app.lapa_cmd(), "sql", self.app.case_id, eid, wrapped_query]

        def handle(outcome: RunOutcome) -> bool:
            data = outcome.parsed_json
            self.step_sql.json_viewer.set_data(data, outcome.stdout)
            self.sql_table.clear()

            if outcome.returncode != 0 or not data:
                self.step_sql.chip.set_status("fail")
                self.step_sql.show_banner(f"✗ {outcome.last_stderr_line}", "fail")
                return False

            columns = data.get("columns", [])
            rows = data.get("rows", [])
            if not isinstance(columns, list) or not isinstance(rows, list):
                self.step_sql.chip.set_status("fail")
                self.step_sql.show_banner("✗ Unexpected SQL output format.", "fail")
                return False

            col_specs = [
                (f"c{idx}", str(col_name), max(110, min(260, len(str(col_name)) * 12)))
                for idx, col_name in enumerate(columns)
            ]
            if col_specs:
                self.sql_table.set_columns(col_specs)

            has_more = len(rows) > 1000
            display_rows = rows[:1000]
            for row in display_rows:
                if isinstance(row, list):
                    self.sql_table.add_row([format_cell_value(cell) for cell in row])

            more_note = " (showing first 1,000 rows — more rows exist)" if has_more else ""
            self.sql_row_info.configure(text=f"Returned {len(display_rows)} row(s){more_note}.")
            self.step_sql.chip.set_status("pass")
            self.step_sql.show_banner(
                f"✓ Query succeeded: {len(display_rows)} row(s) displayed{more_note}.", "pass"
            )
            return True

        self.app.execute_step(self.step_sql, "SQL query", cmd, handler=handle)

    ## creating a function that disables or enables Page 2 controls while a command runs
    def set_busy(self, busy: bool) -> None:
        self.step_parse.set_busy(busy)
        self.step_verify_derived.set_busy(busy)
        self.step_sql.set_busy(busy)
