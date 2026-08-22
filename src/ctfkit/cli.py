"""Command-line interface for bounded CTF helpers."""

from __future__ import annotations

import argparse
import sys
import unicodedata
from collections.abc import Sequence
from typing import NoReturn

from . import __version__
from .config import DEFAULT_PORTS, ScanConfig, parse_port_selection, parse_target
from .decoders import MAX_INPUT_CHARACTERS, decode_candidates
from .errors import ConfigurationError, CTFKitError
from .file_analysis import analyze_file
from .reporting import render_analysis, render_decode, render_scan
from .scanner import NmapScanner

OUTPUT_FORMATS = ("text", "json", "jsonl")


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        super().error(_escape_controls(message))


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="ctfkit",
        description="Bounded helpers for explicitly authorized, local CTF workflows.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run a bounded TCP connect scan through Nmap")
    scan.add_argument("target", help="one hostname or unbracketed IP address")
    scan.add_argument(
        "--acknowledge-authorization",
        action="store_true",
        help="confirm ownership or explicit permission for the target",
    )
    scan.add_argument(
        "--allow-public-target",
        action="store_true",
        help="permit a globally routable target; private CTF ranges are allowed by default",
    )
    scan.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help="comma-separated ports/ranges (max 4096) or 'all'",
    )
    scan.add_argument(
        "--acknowledge-full-scan",
        action="store_true",
        help="additional confirmation required when --ports all is selected",
    )
    scan.add_argument("--timeout", type=float, default=300.0, help="absolute scan timeout, 1-600s")
    scan.add_argument("--max-rate", type=int, default=100, help="Nmap maximum rate, 1-1000")
    scan.add_argument("--format", choices=OUTPUT_FORMATS, default="text")
    scan.add_argument(
        "--fail-on-open",
        action="store_true",
        help="return exit code 3 when at least one open port is reported",
    )

    decode = subparsers.add_parser("decode", help="generate bounded, single-pass decode candidates")
    decode.add_argument("value", nargs="?", help="text to decode; visible in process arguments")
    decode.add_argument(
        "--stdin",
        action="store_true",
        help="read input from standard input instead of a process argument",
    )
    decode.add_argument("--format", choices=OUTPUT_FORMATS, default="text")

    analyze = subparsers.add_parser("analyze", help="inspect one local file without executing it")
    analyze.add_argument("file", help="regular file path; final symlinks are rejected")
    analyze.add_argument(
        "--max-file-bytes",
        type=int,
        default=67_108_864,
        help="maximum file size, up to 268435456 bytes",
    )
    analyze.add_argument("--minimum-string-length", type=int, default=4)
    analyze.add_argument("--max-strings", type=int, default=20)
    analyze.add_argument("--format", choices=OUTPUT_FORMATS, default="text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            config = ScanConfig(
                target=parse_target(args.target),
                ports=parse_port_selection(args.ports),
                acknowledge_authorization=args.acknowledge_authorization,
                allow_public_target=args.allow_public_target,
                acknowledge_full_scan=args.acknowledge_full_scan,
                timeout=args.timeout,
                max_rate=args.max_rate,
            )
            scan_report = NmapScanner().scan(config)
            _write(render_scan(scan_report, args.format))
            return 3 if args.fail_on_open and scan_report.open_ports else 0
        if args.command == "decode":
            value = _decode_input(args.value, args.stdin)
            _write(render_decode(decode_candidates(value), args.format))
            return 0
        analysis_report = analyze_file(
            args.file,
            max_file_bytes=args.max_file_bytes,
            minimum_string_length=args.minimum_string_length,
            max_strings=args.max_strings,
        )
        _write(render_analysis(analysis_report, args.format))
        return 0
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("operation interrupted", file=sys.stderr)
        return 130
    except ConfigurationError as exc:
        parser.error(str(exc))
    except CTFKitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _decode_input(value: str | None, use_stdin: bool) -> str:
    if use_stdin and value is not None:
        raise ConfigurationError("provide either VALUE or --stdin, not both")
    if not use_stdin and value is None:
        raise ConfigurationError("decode requires VALUE or --stdin")
    if use_stdin:
        data = sys.stdin.read(MAX_INPUT_CHARACTERS + 1)
        if len(data) > MAX_INPUT_CHARACTERS:
            raise ConfigurationError(
                f"standard input exceeds the {MAX_INPUT_CHARACTERS}-character limit"
            )
        return data.rstrip("\n")
    return value or ""


def _write(value: str) -> None:
    sys.stdout.write(value)
    sys.stdout.flush()


def _escape_controls(value: str) -> str:
    output: list[str] = []
    for character in value:
        if unicodedata.category(character).startswith("C"):
            codepoint = ord(character)
            output.append(f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}")
        else:
            output.append(character)
    return "".join(output)


if __name__ == "__main__":
    raise SystemExit(main())
