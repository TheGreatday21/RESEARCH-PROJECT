"""Tests for the standalone read-only target collector."""

import ast
import gzip
import json
from pathlib import Path
from typing import BinaryIO

import pytest

from elijah.acquire import collector


def test_artifact_hash_and_metadata(tmp_path: Path) -> None:
    """A stable file records its prefix hash and all required stat fields."""
    path = tmp_path / "access.log"
    content = b"one\ntwo\n"
    path.write_bytes(content)
    result = collector.collect_artifact(str(path))
    assert result["sha256_source"] == collector._sha256_bytes(content)
    assert result["size_at_open"] == len(content)
    assert result["prefix_bytes_read"] == len(content)
    assert result["changed_during_read"] is False
    for field in ("inode", "device", "mtime_utc", "ctime_utc", "mode", "uid", "gid"):
        assert field in result


def test_gzip_is_hashed_as_opaque_bytes(tmp_path: Path) -> None:
    """Rotated compressed logs are never decompressed or recompressed."""
    path = tmp_path / "access.log.2.gz"
    compressed = gzip.compress(b"one\ntwo\n", mtime=0)
    path.write_bytes(compressed)
    result = collector.collect_artifact(str(path))
    assert result["sha256_source"] == collector._sha256_bytes(compressed)
    assert path.read_bytes() == compressed


def test_growth_after_open_does_not_invalidate_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Appending after the open size is recorded without flagging rotation."""
    path = tmp_path / "access.log"
    original = b"one\ntwo\n"
    path.write_bytes(original)
    original_hash = collector._hash_prefix

    def grow_after_hash(stream: BinaryIO, size: int) -> tuple[str, int]:
        result = original_hash(stream, size)
        with path.open("ab") as output:
            output.write(b"three\n")
        return result

    monkeypatch.setattr(collector, "_hash_prefix", grow_after_hash)
    result = collector.collect_artifact(str(path))
    assert result["sha256_source"] == collector._sha256_bytes(original)
    assert result["grew_during_read"] is True
    assert result["changed_during_read"] is False


def test_truncation_during_read_sets_changed_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shrinking below size_at_open is reported without an exception."""
    path = tmp_path / "access.log"
    path.write_bytes(b"one\ntwo\n")
    original_hash = collector._hash_prefix

    def truncate_after_hash(stream: BinaryIO, size: int) -> tuple[str, int]:
        result = original_hash(stream, size)
        path.write_bytes(b"x")
        return result

    monkeypatch.setattr(collector, "_hash_prefix", truncate_after_hash)
    result = collector.collect_artifact(str(path))
    assert result["changed_during_read"] is True


def test_rotation_during_read_sets_changed_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replacing the pathname with a new inode is reported without a crash."""
    path = tmp_path / "access.log"
    original = b"one\ntwo\n"
    path.write_bytes(original)
    original_hash = collector._hash_prefix

    def rotate_after_hash(stream: BinaryIO, size: int) -> tuple[str, int]:
        result = original_hash(stream, size)
        path.rename(tmp_path / "access.log.1")
        path.write_bytes(b"new inode\n")
        return result

    monkeypatch.setattr(collector, "_hash_prefix", rotate_after_hash)
    result = collector.collect_artifact(str(path))
    assert result["changed_during_read"] is True
    assert result["sha256_source"] == collector._sha256_bytes(original)


def test_nginx_config_fallback_retains_failure_and_files(tmp_path: Path) -> None:
    """A failed nginx -T remains visible alongside direct config capture."""
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "nginx.conf").write_text("user www-data;\n", encoding="utf-8")
    (tmp_path / "conf.d" / "site.conf").write_text("server {}\n", encoding="utf-8")
    commands: list[dict[str, object]] = []
    result = collector._capture_nginx_config(
        commands,
        ["/definitely/missing/nginx", "-T"],
        str(tmp_path),
    )
    assert result["fallback_used"] is True
    assert "capture" not in result["content"]
    assert "user www-data;" in result["content"]
    assert "server {}" in result["content"]
    assert "No such file" in result["content"]
    assert commands == [["/definitely/missing/nginx", "-T"]]


def test_cli_emits_one_json_document_and_writes_no_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI output is canonical JSON and collection creates no local artefacts."""
    log_path = tmp_path / "access.log"
    log_path.write_bytes(b"one\n")
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=test\nPRETTY_NAME="Test OS"\n', encoding="utf-8")
    logrotate = tmp_path / "logrotate"
    logrotate.write_text("/var/log/nginx/*.log {}\n", encoding="utf-8")
    before = sorted(tmp_path.iterdir())
    commands = {
        "nginx_config": ["/bin/echo", "config"],
        "nginx_version": ["/bin/echo", "version"],
        "uname": ["/bin/echo", "uname"],
    }
    exit_code = collector.main(
        [
            "--log-glob",
            str(tmp_path / "*.log"),
            "--log-directory",
            str(tmp_path),
            "--nginx-config-root",
            str(tmp_path),
            "--os-release-path",
            str(os_release),
            "--logrotate-path",
            str(logrotate),
            "--context-commands-json",
            json.dumps(commands),
        ]
    )
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert len(captured.out.splitlines()) == 1
    assert document["collector_sha256"] == collector._sha256_bytes(
        Path(collector.__file__).read_bytes()
    )
    assert document["artifacts"][0]["source_path"] == str(log_path)
    assert document["os_release"]["ID"] == "test"
    context_names = {item["logical_name"] for item in document["context_artifacts"]}
    assert {
        "target_utc_offset",
        "target_timezone_name",
        "target_localtime_target",
    } <= context_names
    assert document["footprint"]["files_created"] == []
    assert sorted(tmp_path.iterdir()) == before


def test_collector_syntax_is_python_38_compatible() -> None:
    """The target entry point parses with Python 3.8 grammar."""
    source = Path(collector.__file__).read_text(encoding="utf-8")
    ast.parse(source, filename=collector.__file__, feature_version=(3, 8))
