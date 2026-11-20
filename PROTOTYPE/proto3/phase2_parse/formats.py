"""Derive nginx access-log parsers from captured configuration text."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

COMBINED_FORMAT = (
    '$remote_addr - $remote_user [$time_local] "$request" '
    '$status $body_bytes_sent "$http_referer" "$http_user_agent"'
)
FALLBACK_FORMAT = (
    COMBINED_FORMAT
    + " msec=$msec request_time=$request_time request_id=$request_id"
    + " connection=$connection trace_id=$http_x_lapa_trace"
)
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_LOG_FORMAT = re.compile(r"\blog_format\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.*?);", re.DOTALL)
_ACCESS_LOG = re.compile(r"\baccess_log\s+([^;]+);", re.DOTALL)


@dataclass(frozen=True)
class AccessFormat:
    """A compiled format and the variable represented by each regex group."""

    name: str
    source: str
    pattern: re.Pattern[str]
    variables: tuple[str, ...]

    def parse(self, line: str) -> dict[str, str] | None:
        """Return variable values, or None when the physical line does not match."""
        match = self.pattern.fullmatch(line)
        if match is None:
            return None
        return {
            variable: match.group(f"field_{index}") for index, variable in enumerate(self.variables)
        }


def _variable_pattern(name: str) -> str:
    if name in {"remote_addr", "remote_user"}:
        return r"\S+"
    if name == "time_local":
        return r"[^\]]+"
    if name == "status":
        return r"(?:\d{3}|-)"
    if name in {"body_bytes_sent", "connection"}:
        return r"(?:\d+|-)"
    if name in {"msec", "request_time"}:
        return r"(?:\d+(?:\.\d+)?|-)"
    return r".*?"


def compile_access_format(format_text: str, *, name: str, source: str) -> AccessFormat:
    """Compile literal text and arbitrary nginx variables into a full-line regex."""
    variables: list[str] = []
    pieces: list[str] = []
    position = 0
    for index, match in enumerate(_VARIABLE.finditer(format_text)):
        pieces.append(re.escape(format_text[position : match.start()]))
        variable = match.group(1) or match.group(2)
        variables.append(variable)
        pieces.append(f"(?P<field_{index}>{_variable_pattern(variable)})")
        position = match.end()
    pieces.append(re.escape(format_text[position:]))
    if not variables:
        raise ValueError("access log format contains no variables")
    return AccessFormat(name, source, re.compile("".join(pieces)), tuple(variables))


def _declared_formats(config: str) -> dict[str, str]:
    formats: dict[str, str] = {"combined": COMBINED_FORMAT}
    for match in _LOG_FORMAT.finditer(config):
        try:
            tokens = shlex.split(match.group(0)[:-1], posix=True)
        except ValueError:
            continue
        if len(tokens) >= 3:
            formats[match.group(1)] = "".join(
                tokens[3:] if tokens[2].startswith("escape=") else tokens[2:]
            )
    return formats


def derive_access_format(config: str) -> AccessFormat:
    """Use the first captured access_log directive with a derivable named format."""
    formats = _declared_formats(config)
    for match in _ACCESS_LOG.finditer(config):
        try:
            tokens = shlex.split(match.group(1), posix=True)
        except ValueError:
            continue
        if not tokens or tokens[0] == "off":
            continue
        name = tokens[1] if len(tokens) > 1 and "=" not in tokens[1] else "combined"
        if name in formats:
            return compile_access_format(formats[name], name=name, source=f"nginx_config:{name}")
    raise ValueError("cannot derive access_log format from captured nginx configuration")


def fallback_access_format() -> AccessFormat:
    """Use the documented lab-compatible fallback and label it as an assumption."""
    return compile_access_format(FALLBACK_FORMAT, name="fallback", source="fallback")
