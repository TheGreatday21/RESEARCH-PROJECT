"""Tests for the standalone read-only target collector."""

import ast
import gzip
import http.server
import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO

import pytest

from phase1_acquire import collector


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
    commands: list[list[str]] = []
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


@contextmanager
def _fake_imds_server(handler_cls: type[http.server.BaseHTTPRequestHandler]) -> Iterator[str]:
    """Run a localhost HTTP server on an ephemeral port for IMDSv2 tests."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_imds_probe_success_records_identity_commands_and_context(tmp_path: Path) -> None:
    """IMDSv2 token PUT + identity document/pkcs7 GET succeed and record footprint commands."""
    seen_headers: list[tuple[str, str, str | None]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_PUT(self) -> None:
            ttl = self.headers.get("X-aws-ec2-metadata-token-ttl-seconds")
            seen_headers.append(("PUT", self.path, ttl))
            if self.path == "/latest/api/token" and ttl == "60":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"fake-imdsv2-token")
            else:
                self.send_response(400)
                self.end_headers()

        def do_GET(self) -> None:
            token = self.headers.get("X-aws-ec2-metadata-token")
            seen_headers.append(("GET", self.path, token))
            if token != "fake-imdsv2-token":
                self.send_response(401)
                self.end_headers()
                return
            if self.path == "/latest/dynamic/instance-identity/document":
                body = json.dumps(
                    {
                        "instanceId": "i-0123456789abcdef0",
                        "region": "eu-west-1",
                        "accountId": "123456789012",
                        "availabilityZone": "eu-west-1a",
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/latest/dynamic/instance-identity/pkcs7":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"MIAGCSqGSIb3DQEHAqCAMIACAQExFAKE")
            else:
                self.send_response(404)
                self.end_headers()

    log_path = tmp_path / "access.log"
    log_path.write_bytes(b"line\n")
    with _fake_imds_server(Handler) as base_url:
        result = collector.collect(
            log_globs=[str(log_path)],
            context_commands={
                "nginx_config": ["/bin/echo", "cfg"],
                "nginx_version": ["/bin/echo", "ver"],
                "uname": ["/bin/echo", "uname"],
            },
            log_directory=str(tmp_path),
            imds_base_url=base_url,
            imds_timeout=1.0,
        )

    assert result["cloud"] == {
        "provider": "aws",
        "instance_id": "i-0123456789abcdef0",
        "region": "eu-west-1",
        "account_id": "123456789012",
        "availability_zone": "eu-west-1a",
        "source": "imdsv2",
        "error": "",
    }
    assert result["collection_errors"] == []
    commands = result["footprint"]["commands"]
    assert ["HTTP", "PUT", f"{base_url}/latest/api/token"] in commands
    assert ["HTTP", "GET", f"{base_url}/latest/dynamic/instance-identity/document"] in commands
    assert ["HTTP", "GET", f"{base_url}/latest/dynamic/instance-identity/pkcs7"] in commands
    ctx_by_name = {c["logical_name"]: c for c in result["context_artifacts"]}
    assert "imds_identity_document" in ctx_by_name
    assert ctx_by_name["imds_identity_document"]["verified_offline"] is False
    assert "imds_identity_pkcs7" in ctx_by_name
    assert ctx_by_name["imds_identity_pkcs7"]["verified_offline"] is False
    assert ("PUT", "/latest/api/token", "60") in seen_headers


def test_imds_probe_timeout_is_non_fatal() -> None:
    """Slow IMDS endpoints time out cleanly without failing collection."""

    class SlowHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_PUT(self) -> None:
            time.sleep(0.5)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"late-token")
            except OSError:
                pass

    commands: list[list[str]] = []
    with _fake_imds_server(SlowHandler) as base_url:
        cloud, extra = collector._probe_imds(commands, base_url=base_url, timeout=0.05)

    assert cloud["provider"] == ""
    assert cloud["instance_id"] == ""
    assert cloud["source"] == "imdsv2"
    assert cloud["error"]
    assert extra == []
    assert commands == [["HTTP", "PUT", f"{base_url}/latest/api/token"]]


def test_imds_probe_http_error_is_non_fatal() -> None:
    """HTTP errors (e.g. 403/404) return empty identity fields with a short error."""

    class ForbiddenHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_PUT(self) -> None:
            self.send_response(403)
            self.end_headers()

    commands: list[list[str]] = []
    with _fake_imds_server(ForbiddenHandler) as base_url:
        cloud, extra = collector._probe_imds(commands, base_url=base_url, timeout=0.5)

    assert cloud["provider"] == ""
    assert cloud["instance_id"] == ""
    assert cloud["source"] == "imdsv2"
    assert "403" in cloud["error"]
    assert extra == []


def test_imds_probe_non_aws_document_returns_empty_identity() -> None:
    """A non-AWS server returning JSON without instanceId does not claim AWS identity."""

    class NonAwsHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_PUT(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"tok")

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"provider": "other"}')

    commands: list[list[str]] = []
    with _fake_imds_server(NonAwsHandler) as base_url:
        cloud, extra = collector._probe_imds(commands, base_url=base_url, timeout=0.5)

    assert cloud["provider"] == ""
    assert cloud["instance_id"] == ""
    assert cloud["source"] == "imdsv2"
    assert "instanceId" in cloud["error"]
    assert extra == []


def test_imds_disabled_makes_no_http_requests(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """With --no-imds, collector skips IMDS entirely and emits no HTTP footprint commands."""
    log_path = tmp_path / "access.log"
    log_path.write_bytes(b"line\n")
    commands = {
        "nginx_config": ["/bin/echo", "cfg"],
        "nginx_version": ["/bin/echo", "ver"],
        "uname": ["/bin/echo", "uname"],
    }
    rc = collector.main(
        [
            "--log-glob",
            str(log_path),
            "--log-directory",
            str(tmp_path),
            "--context-commands-json",
            json.dumps(commands),
            "--no-imds",
        ]
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["cloud"] == {
        "provider": "",
        "instance_id": "",
        "region": "",
        "account_id": "",
        "availability_zone": "",
        "source": "disabled",
        "error": "",
    }
    assert not any(cmd and cmd[0] == "HTTP" for cmd in doc["footprint"]["commands"])
