---
title: "Project Elijah"
subtitle: "Live Demo Guide: from signed evidence to analysis report"
author: "Partial demo for supervisors: Phases 1 to 4"
date: "17 November 2026"
lang: en-GB
mainfont: "Avenir Next"
monofont: "Menlo"
fontsize: 11pt
geometry: "top=0.8in,bottom=0.8in,left=0.8in,right=0.8in"
colorlinks: true
linkcolor: "ElijahBlue"
urlcolor: "ElijahBlue"
toc: true
toc-depth: 2
header-includes:
  - \usepackage{xcolor}
  - \usepackage{fancyhdr}
  - \usepackage{titlesec}
  - \usepackage{booktabs}
  - \usepackage{longtable}
  - \usepackage{array}
  - \usepackage{fvextra}
  - \usepackage[most]{tcolorbox}
  - \definecolor{ElijahNavy}{HTML}{12355B}
  - \definecolor{ElijahBlue}{HTML}{185A9D}
  - \definecolor{ElijahTeal}{HTML}{0E7C7B}
  - \definecolor{ElijahLight}{HTML}{EEF4FA}
  - \definecolor{ElijahGrey}{HTML}{52606D}
  - \DefineVerbatimEnvironment{Highlighting}{Verbatim}{breaklines,breakanywhere,commandchars=\\\{\},fontsize=\footnotesize}
  - \RecustomVerbatimEnvironment{verbatim}{Verbatim}{breaklines,breakanywhere,fontsize=\footnotesize}
  - \pagestyle{fancy}
  - \fancyhf{}
  - \fancyhead[L]{\small\color{ElijahGrey}PROJECT ELIJAH}
  - \fancyhead[R]{\small\color{ElijahGrey}LIVE DEMO GUIDE}
  - \fancyfoot[R]{\small\color{ElijahGrey}\thepage}
  - \renewcommand{\headrulewidth}{0.4pt}
  - \titleformat{\section}{\Large\bfseries\color{ElijahNavy}}{\thesection}{0.7em}{}
  - \titleformat{\subsection}{\large\bfseries\color{ElijahBlue}}{\thesubsection}{0.6em}{}
  - \renewcommand{\arraystretch}{1.25}
  - \setlength{\parindent}{0pt}
  - \setlength{\parskip}{5pt}
---

# Is the analysis stage implemented?

**Largely yes. It is not complete, and you should say so.** The analysis stage was built in this session and works end to end on your recorded lab package. This table is the honest scope statement to use with supervisors.

| Capability | Status | Evidence |
|:-------------------|:-----------|:---------------------------------------|
| Verified working copy, lossless parsing, signed Parquet | Done (Phase 2) | `verify-derived`: 11 checks pass |
| Log consistency checks (7 checks) | Done | `elijah analyze` |
| Merged timeline with gap detection | Done | `elijah analyze` |
| Rule-based attack detectors (5 classes) | Done | `elijah detect` |
| Scoring against lab ground truth | Done | `elijah evaluate` |
| Forensic report (Markdown and JSON) | Done | `elijah report` |
| Statistical or machine-learning anomaly detection | **Not done** | Rules only; no learned model |
| Cross-checking logs against independent cloud evidence | **Not done** | Needs cloud metadata collection |
| Scoring `error.log` content | **Not done** | Parsed and timelined, not scored |
| Signed analysis outputs | **Not done** | Reports are regenerable, not signed |
| S3 Object Lock store, disk and block evidence | **Not done** | Out of current scope |

**How the missing parts can be built**, in the order I would do them:

1. **Anomaly detection.** Add per-client and per-minute features (request rate, distinct paths, 4xx ratio) to `features.py`, then a baseline detector such as a z-score on request rate. Score it with the existing `evaluate` command, and test on a second, differently seeded lab run so the result is not tuned to one run.
2. **Signed analysis outputs.** Reuse `sign_manifest` so each report carries a signature and a link to the derived manifest.
3. **`error.log` scoring.** Add rules over the parsed error rows, for example repeated upstream failures.
4. **Cross-source consistency.** After cloud metadata collection exists, compare nginx activity against control-plane records such as load-balancer or flow logs. A request in one source and missing from the other is a tamper lead.

> **Say this out loud in the demo.** Provenance proves the evidence did not change after acquisition. It cannot prove the logs were genuine before acquisition, and the detectors produce leads, not proof.


# Guided mode: let the script drive

You do not have to type the commands yourself. `scripts/demo_live.sh` is a narrated runner: for each step it **shows the real command, waits for you to press Enter, runs it, and then prints a "what this means" explanation**. Nothing is faked; the output on screen is exactly what the tool printed.

```sh
cd ~/Desktop/RESEARCH_PROJECT/PROTOTYPE/proto2/elijah
bash scripts/demo_live.sh              # recorded package, Enter per step (recommended)
bash scripts/demo_live.sh --live-lab   # start Docker, acquire live, then continue
bash scripts/demo_live.sh --auto       # no pauses: use this for a quick rehearsal
bash scripts/demo_live.sh --keep       # keep the scratch folder and its outputs
```

Equivalent shortcuts: `make demo-live` and `make demo-live-lab`.

**What is automated, and what it means.** The long steps are single commands that automate many actions internally, which is worth saying to supervisors:

| Command | What it automates |
|:------------|:--------------------------------------------------------|
| `acquire` | SSH and privilege preflight, read-only collection, hashing before and after transfer, manifest, signature, custody record, create-only storage |
| `parse` | Verify evidence, copy it, verify the copy, parse, sign, publish atomically |
| `analyze`, `detect`, `evaluate`, `report` | Each re-verifies its inputs first and writes nothing if that fails |

The runner works on a scratch **copy** of the recorded package, so your originals are never touched. It takes about 20 minutes at a talking pace, and about 5 seconds with `--auto`. The tamper step is the centrepiece; leave time for it. The step-by-step sections below are the same flow written out, in case you prefer to type the commands yourself or need to recover from a problem.

# Demo plan at a glance

## Storyline (about 20 minutes)

The story is: *evidence is acquired safely, provably unchanged, then analysed without ever touching the original.*

| Segment | Time | Message to land |
|:--------------------|:-------|:-----------------------------------------------|
| 1. What the evidence package is | 2 min | Signed manifest, custody chain, hashed artifacts |
| 2. Verify the evidence | 2 min | 44 independent checks, all named |
| 3. Query the parsed data | 3 min | Every row traces to original bytes |
| 4. **Tamper test** | 3 min | One flipped byte is caught and named |
| 5. Consistency and timeline | 2 min | Is the dataset internally sound? |
| 6. Detection | 3 min | Five attack classes, each with a row reference |
| 7. Honest evaluation | 3 min | Scores, and why a perfect score is not proof |
| 8. Report and limits | 2 min | One verified document; stated limitations |

## Two paths: choose before you start

**Path A: recorded package (recommended as the core of the demo).** Uses the signed package already in `staging/phase2-demo/`, acquired from the Docker lab on 12 November. No Docker, no network, no SSH. Every command was re-run on 17 November and the outputs below are from those runs. This path cannot fail because of Docker.

**Path B: live acquisition (optional opening).** Starts the Docker lab, sends traffic, acquires over SSH with Ansible, then parses. It is more impressive and has more ways to fail. Do it only if you have rehearsed it on the demo machine. If it fails, switch to Path A without apology.

> **Note on what was verified.** I could not reach the Docker daemon from my working environment, so I did **not** re-run Path B on 17 November. Its steps come from the project README and the recorded 11 and 12 November runs. Path A outputs are exact. Path B outputs have the same *shape* but different IDs, times, and hashes each run. Rehearse Path B yourself before relying on it.

# Before the demo

## One day before

- Confirm the project opens and tests pass: `make test` should report **153 passed**.
- Rehearse Path A twice, start to finish, from a clean terminal.
- If you want Path B: start Docker Desktop, run it once end to end, and note any prompts (SSH host keys, firewall dialogs).
- Check `jq` is installed (`jq --version`). It makes JSON readable. If it is missing, replace `| jq ...` with `| python3 -m json.tool`.
- Have the Phase 1 overview PDF (`docs/Project_Elijah_Phase_1_Overview.pdf`) ready as a backup slide for architecture.

## Fifteen minutes before

1. Open a terminal with a large font (at least 18 pt) and a light-on-dark or dark-on-light theme the room can read.
2. Close notifications. Disconnect from anything you do not need.
3. Run the setup block below and confirm the first verify prints `"ok": true`.

## Terminal setup (Path A)

From the project root:

```sh
cd ~/Desktop/RESEARCH_PROJECT/PROTOTYPE/proto2/elijah
source .venv/bin/activate
cd staging/phase2-demo
cp ../../lab/out/labels.jsonl .
export EID=d13a92df-dbbf-48dc-9784-59758a4c3456
ls
```

**You should see:** `derived  ed25519.pub  evidence  labels.jsonl`

The shell is **zsh**. Run each command as written; do not put several options inside one shell variable, because zsh will not split them.


# Path A: step by step

Each step gives the command, what to say, what you should see, and what it proves.

## Step 1: Show what an evidence package is

```sh
ls evidence/C002/$EID evidence/C002/$EID/artifacts
```

**You should see (abridged; `ls` also prints each folder name):**

```text
artifacts  context  custody.jsonl  manifest.json
0000-access.log  0001-error.log
```

**Say:** Acquisition produces four things. The raw nginx logs under `artifacts/`, captured system context (nginx config, timezone, clock) under `context/`, a hash-chained custody record, and a signed manifest tying them together.

```sh
elijah show C002 --evidence-id $EID | jq -c '.evidence[0] | {schema_version, target: .target.hostname, artifacts: [.artifacts[]|{stored_as,size_at_open,verified}], signature: .signature.algorithm}'
```

**You should see:**

```text
{"schema_version":2,"target":"e6c54b46b416","artifacts":[{"stored_as":"artifacts/0000-access.log","size_at_open":20245,"verified":true},{"stored_as":"artifacts/0001-error.log","size_at_open":532,"verified":true}],"signature":"ed25519"}
```

**Proves:** the manifest records the target, each artifact's size when it was opened, that its source and destination hashes matched, and an Ed25519 signature.

```sh
jq -c '{seq, actor, action, entry_hash: .entry_hash[0:16], prev_hash: .prev_hash[0:8]}' evidence/C002/$EID/custody.jsonl
```

**You should see:** `{"seq":1,"actor":"thegreatday21","action":"acquire","entry_hash":"23e969442138c65c","prev_hash":"00000000"}`

**Say:** The first custody entry chains from an all-zero hash. Later entries would chain from this one, so removing or editing an entry breaks every hash after it.

## Step 2: Verify the evidence

```sh
elijah verify C002 --evidence-id $EID --public-key ed25519.pub | jq '.results[0] | {ok, checks: (.checks|length), failed_checks}'
```

**You should see:**

```text
{
  "ok": true,
  "checks": 44,
  "failed_checks": []
}
```

**Say:** That was 44 separate checks: manifest signature, custody chain, and for every artifact its presence, size, source-versus-destination hash, and full-file hash. Each check has a name, so a failure says exactly what broke.

To show the check names, run `elijah verify C002 --evidence-id $EID --public-key ed25519.pub | jq -r '.results[0].checks[].name' | head -12`.

## Step 3: Verify the derived dataset

The raw logs were parsed into Parquet tables. The parsed data is signed too, and linked back to the evidence.

```sh
elijah verify-derived C002 --evidence-id $EID --public-key ed25519.pub | jq '.results[0] | {ok, checks: (.checks|length), failed_checks}'
```

**You should see:** `"ok": true`, `"checks": 11`, `"failed_checks": []`.

**Say:** These 11 checks cover the derived signature, each file's hash, row counts, a canonical hash over every row, and the link to the evidence manifest. If someone edited a parsed row, the row hash would fail.

## Step 4: Query the data and trace a row to the original bytes

```sh
elijah sql C002 $EID "SELECT status, count(*) AS requests FROM access WHERE parse_ok GROUP BY 1 ORDER BY 1" | jq -c '.rows'
```

**You should see:** `[[200,38],[204,8],[400,2],[404,29],[502,2]]`

```sh
elijah sql C002 $EID "SELECT substr(ts_utc,1,16) AS minute_utc, count(*) AS requests FROM access WHERE parse_ok GROUP BY 1 ORDER BY 1" | jq -c '.rows'
```

**You should see:** `[["2026-11-11T11:52",74],["2026-11-12T16:04",4],["2026-11-12T16:07",1]]`

**Say:** 74 of the 79 requests happened in one minute: that is the synthetic traffic run. The other five were manual `curl` checks the next day. This is also why the timeline will show a long gap later.

Now the key forensic claim: a parsed row can be traced to the original bytes.

```sh
elijah sql C002 $EID "SELECT line_no, byte_offset, byte_length, raw_line FROM access WHERE trace_id = 'lapa-phase2-demo' AND parse_ok ORDER BY line_no DESC LIMIT 1" | jq -c '.rows[0]'
```

**You should see:** `[79,20022,223,"172.23.0.1 - - [12/Nov/2026:16:07:11 +0000] \"GET /assets/site.css HTTP/1.1\" 200 48 ..."]`

```sh
dd if=evidence/C002/$EID/artifacts/0000-access.log bs=1 skip=20022 count=223 2>/dev/null; echo "[end]"
```

**You should see:** the same log line, ending in `trace_id=lapa-phase2-demo` followed by `[end]`.

**Proves:** line 79 sits at byte 20022 and is 223 bytes long, and reading those exact bytes from the stored file gives the same line. Nothing was lost or rewritten by the parser.


## Step 5: The tamper test (the centrepiece)

This works only on copies in a scratch folder; your originals are never touched.

```sh
EID=$EID sh ../../scripts/demo_tamper.sh
```

**You should see:**

```text
1) Flip ONE byte in a copy of the stored access log, then verify the evidence
  exit status: 1
  ok = False | failed checks = ['artifact_prefix:artifacts/0000-access.log', 'artifact_full:artifacts/0000-access.log']

2) Flip ONE byte in a copy of the derived parse report, then verify the derived data
  exit status: 1
  ok = False | failed checks = ['derived_file:parse_report.json']

3) Ask for detection on the tampered derived data
detection failed for d13a92df-...: derived verification failed for d13a92df-...: derived_file:parse_report.json
  exit status: 1
  nothing was written to the analysis directory
```

**Say:** I changed a single bit in a 20 KB log. Verification fails, exits non-zero, and names the artifact and the check. When I tamper with the parsed report instead, the analysis tools refuse to read it and write nothing. Analysis can never silently run on altered data.

Prove the originals are fine afterwards by re-running Step 2: it still prints `"ok": true`.

> **Be precise if asked.** This detects change *after* acquisition. It does not prove the logs were untouched *before* we collected them.

## Step 6: Consistency checks and timeline

```sh
elijah analyze C002 --evidence-id $EID --public-key ed25519.pub | jq -c '.results[0] | {ok, total_events, gaps, checks: [.checks[] | {name, status}]}'
```

**You should see:**

```text
{"ok":true,"total_events":81,"gaps":2,"checks":[{"name":"clock_skew","status":"pass"},{"name":"byte_coverage","status":"pass"},{"name":"unparsed_ratio","status":"pass"},{"name":"line_continuity:access","status":"pass"},{"name":"line_continuity:error","status":"pass"},{"name":"timestamp_monotonicity:access","status":"pass"},{"name":"timestamp_monotonicity:error","status":"pass"}]}
```

**Say:** Seven checks, all passing. The clock offset between the target and the control host was 0.05 s, plus or minus 0.09 s. Every byte is accounted for, line numbers have no gaps, and timestamps never run backwards within a file. The timeline merges 81 events from the access and error logs and finds two gaps.

To show the gaps: `jq -c '.gaps[] | {after_ts_utc, before_ts_utc, gap_seconds}' analysis/C002/$EID/timeline_report.json`. The large one is about 101,486 seconds (28 hours) between the synthetic run and the next day's `curl` checks. The tool reports a gap; it cannot say whether it was an idle server or removed lines. **That is why gaps are leads.**

## Step 7: Detection

```sh
elijah detect C002 --evidence-id $EID --public-key ed25519.pub | jq '.results[0]'
```

**You should see:**

```text
{
  "by_class": {"brute_force": 8, "low_slow": 5, "path_scan": 6, "sqli_like": 3, "traversal": 3},
  "detections_file": "analysis/C002/d13a92df-.../detections.json",
  "scored_requests": 79,
  "total_detections": 25
}
```

(The real output is pretty-printed over more lines.) Now show that each detection points at an exact row:

```sh
jq -r '.detections[] | select(.attack_class=="traversal") | [.line_no, .uri_raw, .status, .detector] | @tsv' analysis/C002/$EID/detections.json
```

**You should see:**

```text
59   /%2e%2e/%2e%2e/etc/passwd                              400   traversal_sequence
60   /download?file=..%2f..%2f..%2fetc%2fshadow             404   traversal_sequence
61   /%2e%2e%2f%2e%2e%2fvar%2flog%2fnginx%2faccess.log      400   traversal_sequence
```

**Say:** Five rule-based detectors: sensitive-path probes, SQL-injection fragments, directory traversal (including percent-encoded forms), bursts of login POSTs, and numbered-resource enumeration that stays under any rate threshold. The rules are transparent on purpose, so I can explain each one. Every detection carries the log line and byte offset, so I can trace it back using Step 4.


## Step 8: Honest evaluation

```sh
elijah evaluate C002 --evidence-id $EID --public-key ed25519.pub --labels labels.jsonl | jq -c '.results[0] | {labelled_rows, labels_without_joined_row, overall: .overall_attack_vs_benign | {precision, recall, true_positives, false_positives, false_negatives}}'
```

**You should see:**

```text
{"labelled_rows":72,"labels_without_joined_row":2,"overall":{"precision":1.0,"recall":1.0,"true_positives":23,"false_positives":0,"false_negatives":0}}
```

**Say:** The lab generator labels every request it sends and tags it with a trace ID that nginx logs, so I can score the detectors against ground truth. On this run every class scored 1.0.

**Then immediately add the caveat; this is what earns credibility:**

- I wrote the rules knowing the generator's five attack types, and this is one synthetic run. The score shows the rules do what they say. It says nothing about real-world detection.
- Two labels did not join to a log row. Both are traversal requests that nginx rejected with HTTP 400 before it read headers, so they were logged with no trace ID. Both rows were still flagged by a detector. The tool reports this separately instead of hiding it. In real casework, an unjoined label could also mean a missing log line.
- The unit tests include benign near-misses ("union station", "O'Brien") to check the rules do not over-match.

## Step 9: The report

```sh
elijah report C002 --evidence-id $EID --public-key ed25519.pub --labels labels.jsonl | jq -c '.results[0]'
```

**You should see:** a JSON line with `"consistency_ok":true`, `"total_detections":25`, and the paths `reports/C002/.../report.md` and `report.json`.

```sh
less reports/C002/$EID/report.md
```

**Scroll through:** Acquisition facts (target, operator, clock offset), Dataset coverage (81 lines, 20,777 bytes, 0 unparsed, byte coverage true), the Consistency table, Timeline, Clients, Findings with row references, Evaluation, and **Limitations**.

**Say:** The report re-verifies the evidence and the derived data and recomputes everything itself. It does not trust earlier files. If verification fails, it refuses to produce a report. The Limitations section is part of the report, not an afterthought.

## Cleanup after the demo

```sh
rm -rf analysis bench reports labels.jsonl
```

This removes only regenerable outputs. The signed `evidence/` and `derived/` stay.


# Path B: live acquisition (optional)

Run this from the project root, with Docker Desktop running. Use a **fresh** lab so the logs match the labels.

## Steps

```sh
cd ~/Desktop/RESEARCH_PROJECT/PROTOTYPE/proto2/elijah
source .venv/bin/activate
make lab-down
make lab-up
make traffic
```

`make lab-down` removes the old container and its logs. `make lab-up` builds and starts the nginx and SSH target; it prints the container as healthy. `make traffic` sends 74 labelled requests (benign plus the five attack classes) and writes `lab/out/labels.jsonl`. A fresh container keeps old traffic out of the evidence, so the labels match the logs. I inferred this from the compose file, so confirm it in your rehearsal.

Add two manual requests with an obvious trace value (this is what the Step 4 trace query uses):

```sh
curl -sS -H 'X-Elijah-Trace: lapa-phase2-demo' http://127.0.0.1:8080/ -o /dev/null
curl -sS http://127.0.0.1:8080/assets/site.css -o /dev/null
```

Create signing keys once (skip if `~/.elijah/keys` exists), then acquire:

```sh
elijah keygen
elijah acquire --inventory lab/inventory.ini --case-id C010 --store local
```

**You should see** a JSON line like:

```text
{"case_id":"C010","collection_errors":[],"evidence_id":"<new uuid>","ok":true,"staging_dir":"/tmp/elijah-C010-...","store":"local","unverified_artifacts":[]}
```

`ok: true` with empty `collection_errors` and `unverified_artifacts` is the success signal. Copy the evidence ID, then parse:

```sh
export EID=<paste the evidence_id>
elijah parse C010 --evidence-id $EID
```

**You should see:** a JSON result with `"evidence_verified": true`, a `derived_id`, an output directory under `derived/C010/`, and a `content_hash`.

**Say:** Acquisition ran over SSH as a non-root user with read-only access, hashed the source bytes before transfer, verified them after, and signed the result. Parsing re-verifies the evidence, works on a private copy, and publishes the Parquet tables only if everything checks out.

## Continue with Path A steps

From here use the same commands as Path A, with these changes: use case `C010`, run from the project root (the default `evidence/` and `derived/` folders apply), drop `--public-key ed25519.pub` because the default key in `~/.elijah/keys` is used, and use `--labels lab/out/labels.jsonl`. For the tamper step, run it from the project root as `KEY=$HOME/.elijah/keys/ed25519.pub CASE=C010 EID=$EID sh scripts/demo_tamper.sh`.

**Expected differences in a live run:** new IDs and hashes, a different clock offset, and about the same detection counts. The two unjoined traversal labels should recur because nginx treats those two requests the same way each time.

# Likely questions and honest answers

| Question | Answer |
|:------------------------|:------------------------------------------------|
| Could the attacker have edited the logs before you collected them? | Yes. Signing proves nothing changed after acquisition. Detecting earlier edits needs independent evidence, which is planned future work. |
| Why trust your timestamps? | Both clocks are probed before and after collection. The offset (0.05 s here) and its uncertainty are stored in the signed manifest, and the timezone comes from the target. |
| Is a perfect detection score meaningful? | Only as a check that the rules work as designed. Rules were written knowing the attack types; it is one synthetic run. Next step is an unseen, differently seeded run. |
| Is this machine learning? | No. The detectors are explainable rules. Statistical anomaly detection is not built yet. |
| What if the log is huge? | Parsing streams the data. Detection currently loads parsed access rows in memory, which suits lab-sized logs. A streaming version is future work. |
| Does it work on real cloud VMs? | Only tested against the Docker lab. Clock and log-rotation behaviour on a real VM needs separate validation. |
| What stops someone altering the evidence folder? | Read-only permissions only reduce accidents. The protection is cryptographic: any content change fails verification. Production use needs the signing key in a KMS or HSM. |
| What does a gap in the timeline mean? | It is a lead. It could be an idle server or removed lines; the tool cannot tell them apart. |

# If something goes wrong

| Symptom | Likely cause and fix |
|:-----------------------------|:----------------------------------------------|
| `command not found: elijah` | The venv is not active. Run `source ../../.venv/bin/activate` (or `source .venv/bin/activate` from the project root). |
| `No such option` and a long option string | A variable containing several options was passed in zsh. Type each option separately. |
| `jq: command not found` | Pipe into `python3 -m json.tool` instead of `jq ...`. |
| `verify` prints `ok: false` on the original package | Stop. Do not continue. Check the right public key (`ed25519.pub`) and that the files are the recorded ones. |
| `evidence ID ... canonical UUIDv4` error | `$EID` is empty. Re-run the `export EID=...` line. |
| `derived output already exists` | `parse` will not overwrite. Use `--out` with a new folder. |
| `labels.jsonl` not found | Run `cp ../../lab/out/labels.jsonl .` from `staging/phase2-demo`. |
| Docker permission or daemon error | Start Docker Desktop and retry; otherwise switch to Path A. |
| `acquire` fails over SSH | Confirm `make lab-up` shows healthy and port 2222 is free; otherwise switch to Path A. |
| Output looks different but `ok: true` | Fine in Path B: IDs, times, and hashes change every run. |

# Quick reference

**One-line summary for supervisors.** *Elijah acquires nginx logs from a Linux target without root, signs them, and chains custody. It then analyses a verified working copy: it checks consistency, rebuilds the timeline, flags five attack patterns with traceable row references, scores itself against lab ground truth, and writes a report that states its own limits.*

| Command | Purpose | Reads | Writes |
|:---------------|:------------------------------|:----------------|:--------------|
| `acquire` | Collect and sign evidence | Target over SSH | `evidence/` |
| `verify` | Check evidence integrity | `evidence/` | Nothing |
| `parse` | Create signed Parquet | `evidence/` | `derived/` |
| `verify-derived` | Check derived integrity | `derived/` | Nothing |
| `sql` | Query parsed data | `derived/` | Nothing |
| `analyze` | Consistency and timeline | `derived/` | `analysis/` |
| `detect` | Attack detectors | `derived/` | `analysis/` |
| `evaluate` | Score against labels | `derived/`, labels | `bench/` |
| `report` | Full verified report | `evidence/`, `derived/` | `reports/` |

Project files: `docs/ANALYSIS.md` explains every check and rule. `docs/QUERIES.md` has the longer tamper walkthrough. `make demo-phase4` runs the analysis steps in one go as a fallback.
