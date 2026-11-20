# LAPA Desktop GUI (`gui/`)

Standard-library-only Tkinter/ttk desktop front-end for the `lapa` CLI, styled with the `#1a81a3`–`#2bc2c4` teal palette and session verification gating.

## Launching the GUI

From the `proto4/` root:

```sh
make gui
# or directly:
.venv/bin/python -m gui.lapa_gui
```

## Target Selection (No Mode Switches)

On Tab 1, choosing the target determines which tools appear:

- **Docker lab:** Built-in test server. Shows Ansible inventory picker, **Start lab**, and **Generate traffic** (isolated in `gui/lab_tools.py`). Pre-fills `lab/out/labels.jsonl` on Page 3 if the file exists.
- **My server (AWS EC2) (untested):** Your own server; read-only controls only (`gui/ec2_panel.py` and `gui/aws.py`). Shows Instance ID, **Look up IP**, Public IP / Host, SSH user, SSH key `.pem`, optional AWS profile/region (passed through to `lapa acquire` for dual-source cloud cross-checking), Remote Python path, **Test SSH**, and **Check access** (read-only `lapa preflight` pass/fail checklist with admin hints). Never imports or exposes lab/traffic-generation actions.

On Tab 3, ground-truth labels are an optional input under **Advanced: ground-truth labels (testing only)** rather than a mode. **Evaluate** runs whenever a labels file is chosen regardless of target (showing `○ Not run - needs a labels file` when empty), and **Report** receives `--labels` only when a file is chosen.

## Structure

- `lapa_gui.py` — Main window, workspace/case/evidence header, `Create signing keys` button, 3-page `ttk.Notebook` with session verification gating, `Run full pipeline` orchestrator, live timestamped log, and progress/cancel footer.
- `targets.py` — Tkinter-free target definitions (`TARGET_LAB`, `TARGET_EC2`, single `EC2_UNTESTED_SUFFIX` constant), allowed action rules separating EC2 from lab actions, and target-independent labels/Evaluate helpers.
- `lab_tools.py` — Docker lab-only panel and command builders (`Start lab`, `Generate traffic`), never imported by EC2 modules.
- `ec2_panel.py` — Read-only EC2 configuration panel (`Look up IP`, `Test SSH`, `Check access` preflight checklist).
- `aws.py` — Tkinter-free temporary mode-`0600` EC2 Ansible inventory writer, `.pem` permission check, AWS IP lookup, SSH test, `preflight`, and `--aws-*` acquire argument builders.
- `runner.py` — Tkinter-free `CommandRunner` (`subprocess.Popen` + worker thread + `queue.Queue`), CLI path resolution, `.pem` path shortening, SQL guard (`LIMIT 1001`), Verify grouping (`Manifest`, `Custody`, `Completeness`, `Files`), Preflight/Manifest/Acquire display formatters.
- `theme.py` & `widgets.py` — Teal theme (`clam`), `StatusChip`, `StepBlock`, collapsible `JsonViewer`, `ResultTable`, `Tooltip`, and `ScrollablePage`.
- `pages/` — `page_acquire.py` (Tab 1: Target setup, Acquire with exit-2/mismatch amber warnings, enhanced Show manifest with per-file flags + two-column cloud comparison + signing key ID + footprint command count, Verify checklist), `page_parse.py` (Tab 2), and `page_analyze.py` (Tab 3).
- `tests/test_gui_core.py` — Unit tests for `targets.py`, `runner.py`, and `aws.py`.
