# Phase 3 and 4 analysis guide

All analysis reads verified derived data. Output goes to `analysis/`, `bench/`, and `reports/`, each laid out as `<root>/<case>/<evidence-id>/`. Re-running overwrites these regenerable files; the signed evidence and derived data are never touched.

## Consistency checks (`elijah analyze`)

| Check | Pass | Warn | Fail |
| --- | --- | --- | --- |
| `clock_skew` | offset under 5 s | 5 s or more, or timing data missing | 30 s or more |
| `byte_coverage` | every stream byte maps to a row | report lacks the field | coverage false |
| `unparsed_ratio` | 5% or fewer lines unparsed | more than 5% | n/a |
| `line_continuity:<table>` | line numbers gapless per artifact | n/a | a gap, or missing file |
| `timestamp_monotonicity:<table>` | timestamps never go backwards per artifact | a retrograde jump | missing file |

`analyze` exits 1 on any warn or fail, so a warning is visible in automation. The timeline merges access and error rows by UTC time and lists gaps longer than `--gap-threshold` (default 60 s). A long gap can be an idle server, a stopped service, or removed log lines; the tool cannot tell which.

## Detectors (`elijah detect`)

Rules are signatures and heuristics over the request line. Thresholds live in `DetectorConfig` and are written into every detection file.

| Class | Rule | Fires on |
| --- | --- | --- |
| `path_scan` | `sensitive_path` | VCS metadata, `.env`, admin consoles, `server-status`, backup archives |
| `sqli_like` | `sqli_signature` | `UNION SELECT`, numeric tautologies, stacked statements, time-delay functions, `information_schema`, quoted comment terminators |
| `traversal` | `traversal_sequence`, `sensitive_file` | `../` or `..\` after one or two rounds of percent-decoding, `/etc/passwd`-style targets |
| `brute_force` | `login_burst` | 5 or more POSTs to one login-like path from one client within 60 s |
| `low_slow` | `numbered_enumeration` | 4 or more distinct numbered resources returning 401/403/404 from one client within an hour |

The parser keeps `+` literally in `query_decoded`, so the detectors treat `+` in a query as a space. Each detection carries the artifact path, line number, and byte offset, so it traces to the original bytes the same way the SQL walkthrough does.

Known gaps: coverage is five classes; encodings beyond double percent-encoding, request bodies, and attacks spread over many addresses are not examined; requests nginx rejects before reading headers (HTTP 400) have no trace ID; `error.log` content is not scored.

## Evaluation (`elijah evaluate`)

Labels come from `lab/traffic/generate.py` and join to access rows on `trace_id`. They are lab ground truth, not signed evidence. The result reports attack-versus-benign precision, recall, F1, and accuracy, the same per class, and every disagreement.

Join accounting is reported separately, not folded into the scores:

- `labels_without_joined_row`: labels with no row carrying their trace ID.
- `rows_without_trace_id` and `rows_without_trace_id_flagged`: rows logged with `trace_id` of `-`, and how many a detector flagged.

On the recorded demo (case `C002`), the two traversal requests nginx rejected with HTTP 400 account for both unjoined labels, and both rows were flagged. In general, an unjoined label could also mean a missing log line, which is why it is counted rather than ignored.

> [!NOTE]
> The rules were written knowing the generator's five attack types, and one run of one synthetic workload scored 1.0 on every class. That shows the rules do what they say. It is not evidence about detection on real traffic. The unit tests include benign near-misses (for example `union station` and `O'Brien`) to guard against over-matching.

## Report (`elijah report`)

The report includes integrity status, acquisition facts, dataset coverage, consistency table, timeline summary, per-client summary, findings with sample rows, optional evaluation, and a fixed limitations section. It refuses to run if evidence or derived verification fails.
