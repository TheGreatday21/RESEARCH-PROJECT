# Measuring Detection Accuracy (`docs/EVALUATION.md`)

LAPA's detectors flag suspicious HTTP requests using five rule-based detectors (`phase4_detect/detectors.py`) and an unsupervised Isolation Forest (`phase4_detect/isolation_forest.py`). Because real production logs do not contain ground-truth labels, LAPA separates accuracy measurement into two distinct approaches and states which one any reported figure comes from.

---

## 1. Automated evaluation against a labels file (`lapa evaluate`)

Implemented in `phase4_detect/evaluate.py` and invoked via:

```sh
lapa evaluate <CASE_ID> --evidence-id <EVIDENCE_ID> --labels <path/to/labels.jsonl>
```

### How the join works

1. **Label input (`load_labels`):** Reads a JSONL file where each non-blank line is a JSON object with string fields `trace_id` and `class` (for example `"benign"`, `"path_scan"`, `"sqli_like"`, `"traversal"`, `"brute_force"`, or `"low_slow"`). Duplicate `trace_id` values are rejected.
2. **Row join (`evaluate_detections`):** Extracted access rows (`phase4_detect/features.py`) carry the `trace_id` parsed from nginx's `$http_x_lapa_trace` field (from the `X-Lapa-Trace` request header in `log_format lapa`; rows from stock `combined` logs have `trace_id = None`).
   - Rows whose `trace_id` appears in `labels` form the **labelled set** (`labelled_rows`).
   - Rows whose `trace_id` is absent (`None`) or not in `labels` form the **unlabelled set** (`unlabelled_rows`).
3. **Scoring on the labelled set only:**
   - **Binary (`overall_attack_vs_benign`):** Treats any label other than `"benign"` as positive (`is_attack`) and any row with at least one rule detection as predicted positive (`flagged`), computing `true_positives`, `false_positives`, `false_negatives`, `true_negatives`, `precision`, `recall`, `f1`, and `accuracy`.
   - **Per class (`per_class`):** Computes `true_positives`, `false_positives`, `false_negatives`, `precision`, `recall`, and `f1` independently for each of the five classes in `ATTACK_CLASSES`.
   - **Disagreements (`disagreements`):** Lists every labelled row where binary or class prediction disagreed with the label, with `trace_id`, `uri_raw`, `truth`, `predicted`, `artifact_path`, and `line_no`.
   - When a denominator is zero, metrics are `null` (`None`), never fabricated as `0.0`.
4. **Unjoined labels and unlabelled detections (reported separately):**
   - `labels_without_joined_row` / `unjoined_trace_ids`: labels whose `trace_id` did not appear in parsed access rows (for example, malformed requests that nginx rejected with HTTP 400 before reading headers, or missing log lines).
   - `unlabelled_detections_count`, `unlabelled_detections_by_class`, `unlabelled_detections`, and `unlabelled_rows_flagged`: detections fired on rows with **no matching `trace_id` in `labels`** (for example, background internet scanners hitting an EC2 test instance, or untraced HTTP 400 lines). Each entry is explicitly marked `"unlabelled detection, not scored"` and is **never silently counted as a false positive**.
5. **Scope limit:** Labels are an external testing input, not signed evidence. Reported scores describe **only that labelled set**. LAPA cannot determine whether a provided labels file came from synthetic traffic or manual labelling, and never claims either.

---

## 2. Manual procedure for estimating precision and recall on a real log

Real server logs have no `X-Lapa-Trace` labels. To estimate detector quality on real traffic without building an unverified labelling pipeline into the tool, an analyst can follow this manual sampling procedure using existing LAPA outputs (`detections.json` and `lapa sql`).

### Step A — Estimate precision from flagged detections

Every rule detection in `analysis/<CASE_ID>/<EVIDENCE_ID>/detections.json` includes its exact provenance (`artifact_path`, `line_no`, `byte_offset`, `attack_class`, `detector`, `uri_raw`, `reason`).

1. If `total_detections` is small enough to review in full, inspect all distinct flagged `(artifact_path, line_no)` rows; otherwise draw a simple random sample of $n_p$ distinct flagged rows (or stratified by `attack_class`).
2. Inspect each flagged request in context (its full `raw_line`, status code, client IP history, and surrounding lines) using `lapa sql`:
   ```sh
   lapa sql C001 <EVIDENCE_ID> \
     "SELECT artifact_path, line_no, ts_utc, remote_addr, method, uri_raw, status, user_agent
      FROM access
      WHERE artifact_path = 'artifacts/0000-access.log'
        AND line_no BETWEEN 115 AND 125
      ORDER BY line_no"
   ```
3. Label each sampled flagged request as **TP** (genuine attack/probe) or **FP** (benign traffic triggered a rule).
4. Compute estimated precision on the reviewed sample:
   $$\widehat{\text{Precision}} = \frac{\text{TP}_{\text{sample}}}{\text{TP}_{\text{sample}} + \text{FP}_{\text{sample}}}$$

### Step B — Estimate approximate recall by sampling unflagged requests

Precision alone cannot tell you how many attacks were missed (false negatives). To estimate recall, you must inspect a random sample of requests that were **not** flagged:

1. Draw a reproducible random sample of $n_u$ parsed requests from `access` using `lapa sql` (filtering out any `(artifact_path, line_no)` already present in `detections.json` after exporting or in SQL by excluding flagged paths/line numbers):
   ```sh
   lapa sql C001 <EVIDENCE_ID> \
     "SELECT artifact_path, line_no, byte_offset, ts_utc, remote_addr, method, uri_raw, status, user_agent
      FROM access
      WHERE parse_ok AND ts_utc IS NOT NULL
      ORDER BY md5(artifact_path || ':' || CAST(line_no AS VARCHAR) || ':sample-seed-1')
      LIMIT 200"
   ```
   (Using `ORDER BY md5(... || ':seed')` makes the sample deterministic and reproducible for peer review; remove any sampled rows that appear in `detections.json` so only unflagged rows remain.)
2. Manually review each unflagged sampled request and count genuine missed attacks ($\text{FN}_{\text{sample}}$) out of $n_u$ unflagged rows reviewed.
3. Let $N_{\text{flagged}}$ be the total distinct flagged requests and $N_{\text{unflagged}}$ be the total distinct unflagged parsed requests. The estimated total true positives is $\widehat{\text{TP}} = N_{\text{flagged}} \times \widehat{\text{Precision}}$ and estimated total false negatives is $\widehat{\text{FN}} = N_{\text{unflagged}} \times (\text{FN}_{\text{sample}} / n_u)$, giving:
   $$\widehat{\text{Recall}} \approx \frac{\widehat{\text{TP}}}{\widehat{\text{TP}} + \widehat{\text{FN}}}$$

### Statistical limits of small samples

- **Rare attacks are hard to bound:** If true unflagged attacks occur at rate $p = 0.5\%$ (1 in 200 requests), a random sample of $n_u = 100$ unflagged rows has a ~61% chance of finding zero false negatives (`FN_sample = 0`). Observing zero false negatives in a small sample does **not** prove recall is 100%.
- **Report sample sizes and uncertainty:** Whenever reporting manual estimates, always state the sample sizes ($n_p$, $n_u$), the total counts ($N_{\text{flagged}}$, $N_{\text{unflagged}}$), and that the recall figure is an **approximate sample-based estimate** (ideally with a binomial confidence interval such as Wilson or Clopper–Pearson).

---

## 3. Unsupervised Isolation Forest (`phase4_detect/isolation_forest.py`)

LAPA also runs a deterministic pure-Python Isolation Forest over every parsed, timestamped access request (`n_trees=100`, `max_samples=256`, `contamination=0.05`, `min_score_threshold=0.60`, `seed=42`) using eight numerical features:

`uri_length`, `path_depth`, `query_length`, `encoded_char_count`, `special_char_count`, `status_severity`, `client_burst_60s`, `client_error_ratio`.

- **Unsupervised:** The Isolation Forest uses **no labels** when building trees or computing anomaly scores $s(x, n) \in (0, 1]$. A high score indicates a statistically unusual request relative to the rest of the log, not confirmed maliciousness.
- **Evaluation:** `lapa evaluate` currently scores the five rule detectors (`run_detectors`); evaluating the Isolation Forest's ranked anomalies uses the exact same two principles — comparing flagged anomaly `(artifact_path, line_no)` rows against a labelled test set, or manually reviewing top-ranked anomalies (from `detections.json` -> `isolation_forest.anomalies`) alongside a random sample of non-anomalous requests on a real log.
