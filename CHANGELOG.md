# Changelog

All notable changes to this project are documented here.

## [1.0.0] - 2026-08-22

### Changed

- Rebuilt the single script as an installable, typed Python package.
- Replaced aggressive Nmap defaults with a bounded TCP connect scan.
- Removed NSE scripts, version/OS detection, aggressive timing, and implicit public-target access.
- Replaced external `file`, `strings`, and `head` pipelines with read-only Python analysis.
- Made decode operations strict, single-pass, bounded, and machine-readable.

### Added

- Explicit authorization acknowledgement and a separate public-target flag.
- RFC1918/ULA-aware target classification, mixed-answer rejection, and DNS endpoint pinning.
- Port, rate, address-count, output-size, and absolute scan timeout limits.
- Extra confirmation for full 65,535-port scans.
- SHA-256, signature, entropy, and capped printable-string file observations.
- Text, JSON, and JSONL reporting with terminal-control escaping.
- Network-free tests, strict type checking, linting, packaging validation, and CI.
