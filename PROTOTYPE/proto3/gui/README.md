# LAPA Desktop GUI (`gui/`)

Tkinter/ttk desktop front-end for the `lapa` command-line tool, styled with the `#1a81a3`–`#2bc2c4` teal palette and designed for live demonstrations.

## Launching the GUI

From the `proto3/` root:

```sh
.venv/bin/python -m gui.lapa_gui
```

## Structure

- `lapa_gui.py` — Main window, workspace/case/evidence header, `Create signing keys` button, 3-page `ttk.Notebook` with session verification gating, `Run full pipeline` orchestrator, live timestamped log, and progress/cancel footer.
- `theme.py` — Teal color palette (`#1a81a3`, `#2bc2c4`, `#146a85`, `#f2fafb`, `#e3f4f6`), semantic status colors (`#2f9e44`, `#e8a317`, `#c92a2a`), font selection, and `clam` ttk styles.
- `runner.py` — Tkinter-free `CommandRunner` (`subprocess.Popen` + worker thread + `queue.Queue`), CLI path resolution, `.pem` path shortening, SQL single-statement `SELECT`/`WITH` guard (`LIMIT 1001`), and JSON output groupers.
- `aws.py` — Tkinter-free temporary EC2 Ansible inventory writer, `.pem` `0600` permission check, AWS CLI public IP lookup command builder, and SSH connectivity test builder.
- `widgets.py` — `StatusChip`, `StepBlock`, collapsible `JsonViewer` (*Show technical details*), `ResultTable`, `Tooltip`, and `ScrollablePage`.
- `pages/` — `page_acquire.py` (Tab 1: Target setup, Acquire, Show manifest, Verify), `page_parse.py` (Tab 2: Parse, Verify derived, DuckDB SQL), and `page_analyze.py` (Tab 3: Analyze, Detect, Evaluate, Report).
- `tests/test_gui_core.py` — Unit tests for `runner.py` and `aws.py`.
