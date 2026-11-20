"""Target definitions, allowed action rules, and labels/evaluate helpers (no tkinter imports)."""

from __future__ import annotations

from pathlib import Path

TARGET_LAB = "lab"
TARGET_EC2 = "ec2"

# Single constant so the "(untested)" wording can be removed in one place after a real VM run.
EC2_UNTESTED_SUFFIX = " (untested)"

TARGET_LABELS: dict[str, str] = {
    TARGET_LAB: "Docker lab",
    TARGET_EC2: f"My server (AWS EC2){EC2_UNTESTED_SUFFIX}",
}

TARGET_DESCRIPTIONS: dict[str, str] = {
    TARGET_LAB: "Built-in test server. Start lab and Generate traffic are available.",
    TARGET_EC2: "Your own server. LAPA only reads from it; nothing is sent to or changed on it.",
}

LAB_ONLY_ACTIONS: frozenset[str] = frozenset({"start_lab", "generate_traffic"})

TARGET_ALLOWED_ACTIONS: dict[str, frozenset[str]] = {
    TARGET_LAB: frozenset({"browse_inventory", "start_lab", "generate_traffic", "acquire"}),
    TARGET_EC2: frozenset({"lookup_ip", "browse_pem", "test_ssh", "preflight", "acquire"}),
}

DEFAULT_LAB_LABELS_RELATIVE = "lab/out/labels.jsonl"
EVALUATE_NEEDS_LABELS_TEXT = "○ Not run - needs a labels file"


## creating a function that returns the allowed actions for a given target identifier
def allowed_actions_for_target(target_id: str) -> frozenset[str]:
    if target_id not in TARGET_ALLOWED_ACTIONS:
        raise ValueError(f"Unknown target identifier: {target_id!r}")
    return TARGET_ALLOWED_ACTIONS[target_id]


## creating a function that checks whether a specific UI action is permitted for a target
def is_action_allowed(target_id: str, action: str) -> bool:
    return action in allowed_actions_for_target(target_id)


## creating a function that resolves a user-entered labels path against working_folder or
## project_root
def resolve_selected_labels_path(
    labels_path: str,
    working_folder: Path,
    project_root: Path,
) -> Path | None:
    cleaned = labels_path.strip()
    if not cleaned:
        return None
    candidate = Path(cleaned).expanduser()
    if candidate.is_absolute():
        return candidate
    in_working = working_folder / candidate
    if in_working.exists():
        return in_working
    return project_root / candidate


## creating a function that pre-fills lab/out/labels.jsonl for Docker lab when present
def default_labels_path_for_target(
    target_id: str,
    working_folder: Path,
    project_root: Path,
) -> str:
    if target_id != TARGET_LAB:
        return ""
    resolved = resolve_selected_labels_path(
        DEFAULT_LAB_LABELS_RELATIVE, working_folder, project_root
    )
    if resolved is not None and resolved.is_file():
        return DEFAULT_LAB_LABELS_RELATIVE
    return ""


## creating a function that decides whether Evaluate can run (depends on labels, not target)
def can_run_evaluate(locked: bool, labels_path: str) -> bool:
    return (not locked) and bool(labels_path.strip())


## creating a function that returns the idle status label for Evaluate based on labels input
def evaluate_idle_status(labels_path: str) -> str:
    if labels_path.strip():
        return "○ Not run"
    return EVALUATE_NEEDS_LABELS_TEXT


## creating a function that decides whether lapa report should receive --labels
def report_labels_path(
    labels_path: str,
    working_folder: Path,
    project_root: Path,
) -> Path | None:
    resolved = resolve_selected_labels_path(labels_path, working_folder, project_root)
    if resolved is not None and resolved.is_file():
        return resolved
    return None
