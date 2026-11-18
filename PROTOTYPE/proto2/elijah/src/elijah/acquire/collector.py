#!/usr/bin/env python3
"""Collect nginx evidence as one JSON document using only the stdlib."""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import platform
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Mapping, Optional, Sequence, Tuple

COLLECTOR_VERSION = "0.1.0"
CHUNK_SIZE = 1024 * 1024
DEFAULT_LOG_GLOBS = ["/var/log/nginx/access.log*", "/var/log/nginx/error.log*"]
DEFAULT_CONTEXT_COMMANDS = {
    "nginx_config": ["nginx", "-T"],
    "nginx_version": ["nginx", "-V"],
    "uname": ["uname", "-a"],
}


def _canonical_json_bytes(value: Any) -> bytes:
    """Encode deterministic compact JSON as UTF-8."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def _utc_iso(timestamp: float) -> str:
    """Format a filesystem timestamp as UTC ISO 8601."""
    value = datetime.fromtimestamp(timestamp, timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _now_utc() -> str:
    """Return the current system time as UTC ISO 8601."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _hash_prefix(stream: BinaryIO, size_at_open: int) -> Tuple[str, int]:
    """Hash exactly the available prefix and return its actual length."""
    digest = hashlib.sha256()
    bytes_read = 0
    while bytes_read < size_at_open:
        chunk = stream.read(min(CHUNK_SIZE, size_at_open - bytes_read))
        if not chunk:
            break
        digest.update(chunk)
        bytes_read += len(chunk)
    return digest.hexdigest(), bytes_read


def _decode_text(data: bytes) -> str:
    """Convert captured bytes to deterministic UTF-8-compatible text."""
    return data.decode("utf-8", errors="replace")


def _execute(argv: Sequence[str], commands: List[List[str]]) -> Dict[str, Any]:
    """Execute one configured command without a shell and retain all output."""
    command = list(argv)
    commands.append(command)
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        return {
            "argv": command,
            "returncode": 127,
            "stdout": b"",
            "stderr": str(error).encode("utf-8"),
        }
    return {
        "argv": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _combined_command_text(result: Mapping[str, Any]) -> str:
    """Retain stdout and stderr in a labelled text artefact."""
    stdout = _decode_text(result.get("stdout", b""))
    stderr = _decode_text(result.get("stderr", b""))
    if stdout and stderr:
        separator = "" if stdout.endswith("\n") else "\n"
        return stdout + separator + "[stderr]\n" + stderr
    return stdout or stderr


def _context_record(
    logical_name: str,
    text: str,
    *,
    source_path: Optional[str] = None,
    command: Optional[Sequence[str]] = None,
    success: bool = True,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a text context record whose hash covers its stored representation."""
    data = text.encode("utf-8")
    record: Dict[str, Any] = {
        "logical_name": logical_name,
        "source_path": source_path,
        "command": list(command) if command is not None else None,
        "content": text,
        "size_at_open": len(data),
        "sha256_source": _sha256_bytes(data),
        "changed_during_read": False,
        "success": success,
    }
    if extra:
        record.update(extra)
    return record


def _target_clock(commands: List[List[str]]) -> Dict[str, Any]:
    """Read Python and date-command clocks without changing the target clock."""
    result = _execute(["date", "-u", "+%Y-%m-%dT%H:%M:%S.%NZ"], commands)
    reading: Dict[str, Any] = {
        "utc": _now_utc(),
        "original": _combined_command_text(result).strip(),
        "returncode": result["returncode"],
    }
    return reading


def _stat_fields(file_stat: os.stat_result) -> Dict[str, Any]:
    """Return the required inode and filesystem metadata."""
    return {
        "inode": file_stat.st_ino,
        "device": file_stat.st_dev,
        "size": file_stat.st_size,
        "mtime_utc": _utc_iso(file_stat.st_mtime),
        "ctime_utc": _utc_iso(file_stat.st_ctime),
        "mode": format(stat.S_IMODE(file_stat.st_mode), "04o"),
        "uid": file_stat.st_uid,
        "gid": file_stat.st_gid,
    }


def collect_artifact(path: str) -> Dict[str, Any]:
    """Collect one file's metadata and source prefix hash without writing."""
    initial = os.stat(path)
    with open(path, "rb", buffering=0) as stream:
        opened = os.fstat(stream.fileno())
        size_at_open = opened.st_size
        sha256_source, bytes_read = _hash_prefix(stream, size_at_open)

    after: Optional[os.stat_result]
    stat_error: Optional[str]
    try:
        after = os.stat(path)
        stat_error = None
    except OSError as error:
        after = None
        stat_error = str(error)

    inode_changed = initial.st_ino != opened.st_ino or initial.st_dev != opened.st_dev
    size_after: Optional[int] = None
    if after is not None:
        inode_changed = (
            inode_changed or after.st_ino != opened.st_ino or after.st_dev != opened.st_dev
        )
        size_after = after.st_size
    size_shrank = size_after is None or size_after < size_at_open
    changed = inode_changed or size_shrank or bytes_read != size_at_open

    record: Dict[str, Any] = {
        "logical_name": os.path.basename(path),
        "source_path": path,
        "size_at_open": size_at_open,
        "sha256_source": sha256_source,
        "prefix_bytes_read": bytes_read,
        "size_after": size_after,
        "grew_during_read": size_after is not None and size_after > size_at_open,
        "changed_during_read": changed,
    }
    record.update(_stat_fields(initial))
    if stat_error is not None:
        record["stat_after_error"] = stat_error
    return record


def _read_context_file(path: str, logical_name: str) -> Dict[str, Any]:
    """Capture a context file as text or preserve the read error as content."""
    try:
        text = _decode_text(Path(path).read_bytes())
    except OSError as error:
        return _context_record(
            logical_name,
            "capture error: " + str(error) + "\n",
            source_path=path,
            success=False,
        )
    return _context_record(logical_name, text, source_path=path)


def _localtime_target_context(path: str) -> Dict[str, Any]:
    """Resolve the target's localtime link without changing the filesystem."""
    try:
        resolved = str(Path(path).resolve(strict=True))
    except OSError as error:
        return _context_record(
            "target_localtime_target",
            "capture error: " + str(error) + "\n",
            source_path=path,
            success=False,
        )
    return _context_record(
        "target_localtime_target",
        resolved + "\n",
        source_path=path,
    )


def _nginx_config_fallback(config_root: str) -> Tuple[str, List[str]]:
    """Read the main configuration and conventional include files directly."""
    root = Path(config_root)
    candidates = {root / "nginx.conf"}
    for pattern in ("*.conf", "conf.d/*", "sites-enabled/*"):
        candidates.update(candidate for candidate in root.glob(pattern) if candidate.is_file())
    sections: List[str] = []
    errors: List[str] = []
    for candidate in sorted(candidates, key=lambda item: str(item)):
        try:
            content = _decode_text(candidate.read_bytes())
        except OSError as error:
            errors.append(str(candidate) + ": " + str(error))
            continue
        sections.append("[file] " + str(candidate) + "\n" + content)
    return "\n".join(sections), errors


def _capture_nginx_config(
    commands: List[List[str]],
    argv: Sequence[str],
    config_root: str,
) -> Dict[str, Any]:
    """Capture nginx -T, retaining its output when direct-file fallback is needed."""
    result = _execute(argv, commands)
    command_text = _combined_command_text(result)
    if result["returncode"] == 0:
        return _context_record(
            "nginx_config",
            command_text,
            command=argv,
            extra={"fallback_used": False, "returncode": 0},
        )

    fallback, errors = _nginx_config_fallback(config_root)
    text = (
        "[nginx -T failed; direct-file fallback follows]\n"
        + command_text
        + "\n[direct configuration files]\n"
        + fallback
    )
    if errors:
        text += "\n[fallback errors]\n" + "\n".join(errors) + "\n"
    return _context_record(
        "nginx_config",
        text,
        command=argv,
        success=bool(fallback) and not errors,
        extra={
            "fallback_used": True,
            "returncode": result["returncode"],
            "fallback_errors": errors,
        },
    )


def _directory_listing(log_directory: str) -> Dict[str, Any]:
    """Describe log-directory entries in sorted order as hashed text."""
    lines: List[str] = []
    success = True
    try:
        entries = sorted(os.scandir(log_directory), key=lambda entry: entry.name)
    except OSError as error:
        entries = []
        lines.append("listing error: " + str(error))
        success = False
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
            row = {
                "path": entry.path,
                "inode": metadata.st_ino,
                "device": metadata.st_dev,
                "size": metadata.st_size,
                "mtime_utc": _utc_iso(metadata.st_mtime),
                "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
            }
            lines.append(_decode_text(_canonical_json_bytes(row)))
        except OSError as error:
            success = False
            lines.append(entry.path + ": stat error: " + str(error))
    return _context_record(
        "log_directory_listing",
        "\n".join(lines) + ("\n" if lines else ""),
        source_path=log_directory,
        success=success,
    )


def _os_release_facts(path: str) -> Dict[str, str]:
    """Parse simple os-release assignments for manifest target facts."""
    facts: Dict[str, str] = {}
    try:
        lines = _decode_text(Path(path).read_bytes()).splitlines()
    except OSError:
        return facts
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        facts[key] = value.strip().strip('"').strip("'")
    return facts


def _load_json_setting(raw: str, label: str) -> Any:
    """Decode a CLI or environment JSON setting with a clear error."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(label + " must be valid JSON: " + str(error)) from error


def collect(
    log_globs: Sequence[str],
    context_commands: Mapping[str, Sequence[str]],
    log_directory: str,
    nginx_config_root: str = "/etc/nginx",
    os_release_path: str = "/etc/os-release",
    logrotate_path: str = "/etc/logrotate.d/nginx",
    localtime_path: str = "/etc/localtime",
    timezone_path: str = "/etc/timezone",
) -> Dict[str, Any]:
    """Run the complete read-only collection and return one JSON-compatible object."""
    commands: List[List[str]] = []
    before = _target_clock(commands)
    collection_errors: List[str] = []
    artifacts: List[Dict[str, Any]] = []

    paths = sorted({path for pattern in log_globs for path in glob.glob(pattern)})
    for pattern in log_globs:
        if not glob.glob(pattern):
            collection_errors.append("no files matched glob: " + pattern)
    for path in paths:
        if not os.path.isfile(path):
            collection_errors.append("matched path is not a regular file: " + path)
            continue
        try:
            artifacts.append(collect_artifact(path))
        except OSError as error:
            collection_errors.append(path + ": " + str(error))
            artifacts.append(
                {
                    "logical_name": os.path.basename(path),
                    "source_path": path,
                    "collection_error": str(error),
                    "changed_during_read": True,
                }
            )

    context: List[Dict[str, Any]] = []
    context.append(
        _capture_nginx_config(
            commands,
            context_commands.get("nginx_config", DEFAULT_CONTEXT_COMMANDS["nginx_config"]),
            nginx_config_root,
        )
    )
    for logical_name in ("nginx_version", "uname"):
        argv = context_commands.get(logical_name, DEFAULT_CONTEXT_COMMANDS[logical_name])
        result = _execute(argv, commands)
        context.append(
            _context_record(
                logical_name,
                _combined_command_text(result),
                command=argv,
                success=result["returncode"] == 0,
                extra={"returncode": result["returncode"]},
            )
        )
    context.append(_read_context_file(logrotate_path, "logrotate_config"))
    context.append(_read_context_file(os_release_path, "os_release"))
    for logical_name, argv in (
        ("target_utc_offset", ["date", "+%z"]),
        ("target_timezone_name", ["date", "+%Z"]),
    ):
        result = _execute(argv, commands)
        context.append(
            _context_record(
                logical_name,
                _combined_command_text(result),
                command=argv,
                success=result["returncode"] == 0,
                extra={"returncode": result["returncode"]},
            )
        )
    context.append(_localtime_target_context(localtime_path))
    if Path(timezone_path).is_file():
        context.append(_read_context_file(timezone_path, "target_timezone_file"))
    context.append(_directory_listing(log_directory))

    after = _target_clock(commands)
    try:
        collector_sha256 = _sha256_bytes(Path(__file__).read_bytes())
    except OSError as error:
        collector_sha256 = ""
        collection_errors.append("collector self-hash failed: " + str(error))
    return {
        "schema_version": 1,
        "collector_version": COLLECTOR_VERSION,
        "collector_sha256": collector_sha256,
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "os_release": _os_release_facts(os_release_path),
        "target_time_before": before,
        "target_time_after": after,
        "artifacts": artifacts,
        "context_artifacts": context,
        "collection_errors": collection_errors,
        "footprint": {"files_created": [], "commands": commands},
    }


def _parser() -> argparse.ArgumentParser:
    """Create the standalone collector argument parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-glob", action="append", dest="log_globs")
    parser.add_argument("--log-globs-json")
    parser.add_argument("--context-commands-json")
    parser.add_argument("--log-directory", default="/var/log/nginx")
    parser.add_argument("--nginx-config-root", default="/etc/nginx")
    parser.add_argument("--os-release-path", default="/etc/os-release")
    parser.add_argument("--logrotate-path", default="/etc/logrotate.d/nginx")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Print exactly one canonical JSON document to stdout."""
    args = _parser().parse_args(argv)
    raw_globs = args.log_globs_json or os.environ.get("ELIJAH_LOG_GLOBS")
    if raw_globs:
        log_globs = _load_json_setting(raw_globs, "log globs")
        if not isinstance(log_globs, list) or not all(isinstance(item, str) for item in log_globs):
            raise ValueError("log globs must be a JSON list of strings")
    else:
        log_globs = args.log_globs or list(DEFAULT_LOG_GLOBS)

    raw_commands = args.context_commands_json or os.environ.get("ELIJAH_CONTEXT_COMMANDS")
    if raw_commands:
        context_commands = _load_json_setting(raw_commands, "context commands")
        if not isinstance(context_commands, dict):
            raise ValueError("context commands must be a JSON object")
    else:
        context_commands = DEFAULT_CONTEXT_COMMANDS

    result = collect(
        log_globs=log_globs,
        context_commands=context_commands,
        log_directory=args.log_directory,
        nginx_config_root=args.nginx_config_root,
        os_release_path=args.os_release_path,
        logrotate_path=args.logrotate_path,
    )
    sys.stdout.buffer.write(_canonical_json_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
