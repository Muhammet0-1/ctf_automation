"""Plain text, JSON, and JSONL output without terminal-control injection."""

from __future__ import annotations

import json
import math
import unicodedata

from .decoders import DecodeCandidate
from .file_analysis import FileAnalysis
from .scanner import ScanReport


def render_scan(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return _json(report.to_dict())
    if output_format == "jsonl":
        records: list[dict[str, object]] = [
            {
                "type": "scan",
                "target": report.target,
                "selected_endpoint": report.selected_endpoint.to_dict(),
                "port_specification": report.port_specification,
            }
        ]
        records.extend({"type": "open_port", **item.to_dict()} for item in report.open_ports)
        records.append(
            {
                "type": "summary",
                "host_up": report.host_up,
                "open_port_count": len(report.open_ports),
                "duration_seconds": _finite(report.duration_seconds),
            }
        )
        return _jsonl(records)
    if output_format != "text":
        raise ValueError(f"unsupported output format: {output_format}")

    lines = [
        "CTFKit Authorized Scan Report",
        f"Target: {_safe(report.target)}",
        f"Pinned endpoint: {_safe(report.selected_endpoint.address)}",
        f"Ports: {_safe(report.port_specification)}",
        f"Host status: {'up' if report.host_up else 'not reported as up'}",
        f"Open TCP ports: {len(report.open_ports)}",
        "",
    ]
    for item in report.open_ports:
        details = " ".join(
            value
            for value in (_safe(item.service), _safe(item.product), _safe(item.version))
            if value
        )
        suffix = f" ({details})" if details else ""
        lines.append(f"- {item.port}/{_safe(item.protocol)} open{suffix}")
    if not report.open_ports:
        lines.append("No open ports were reported within the selected scope.")
    return "\n".join(lines).rstrip() + "\n"


def render_decode(
    candidates: tuple[DecodeCandidate, ...],
    output_format: str,
) -> str:
    data = {
        "schema_version": 1,
        "command": "decode",
        "candidate_count": len(candidates),
        "candidates": [item.to_dict() for item in candidates],
    }
    if output_format == "json":
        return _json(data)
    if output_format == "jsonl":
        records: list[dict[str, object]] = [{"type": "decode", "candidate_count": len(candidates)}]
        records.extend({"type": "candidate", **item.to_dict()} for item in candidates)
        return _jsonl(records)
    if output_format != "text":
        raise ValueError(f"unsupported output format: {output_format}")
    lines = ["CTFKit Decode Candidates", f"Candidates: {len(candidates)}", ""]
    lines.extend(f"- {_safe(item.transformation)}: {_safe(item.value)}" for item in candidates)
    if not candidates:
        lines.append("No supported single-pass decoding candidate was found.")
    return "\n".join(lines).rstrip() + "\n"


def render_analysis(report: FileAnalysis, output_format: str) -> str:
    if output_format == "json":
        return _json(report.to_dict())
    if output_format == "jsonl":
        records: list[dict[str, object]] = [
            {
                "type": "analysis",
                "path": report.path,
                "size_bytes": report.size_bytes,
                "sha256": report.sha256,
                "detected_type": report.detected_type,
                "sample_entropy": _finite(report.sample_entropy),
            }
        ]
        records.extend({"type": "string", "value": value} for value in report.strings)
        return _jsonl(records)
    if output_format != "text":
        raise ValueError(f"unsupported output format: {output_format}")
    lines = [
        "CTFKit Read-Only File Analysis",
        f"Path: {_safe(report.path)}",
        f"Size: {report.size_bytes} bytes",
        f"SHA-256: {report.sha256}",
        f"Type: {_safe(report.detected_type)}",
        f"Sample entropy: {_finite(report.sample_entropy):.4f}",
        f"Strings ({len(report.strings)}):",
    ]
    lines.extend(f"- {_safe(value)}" for value in report.strings)
    if not report.strings:
        lines.append("- none")
    return "\n".join(lines).rstrip() + "\n"


def _json(data: dict[str, object]) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"


def _jsonl(records: list[dict[str, object]]) -> str:
    return "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
        for record in records
    )


def _finite(value: float) -> float:
    return value if math.isfinite(value) else 0.0


def _safe(value: str | None) -> str:
    if value is None:
        return ""
    output: list[str] = []
    for character in value:
        if unicodedata.category(character).startswith("C"):
            codepoint = ord(character)
            output.append(f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}")
        else:
            output.append(character)
    return "".join(output)
