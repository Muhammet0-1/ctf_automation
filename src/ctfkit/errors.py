"""Domain-specific exceptions surfaced by the CLI."""


class CTFKitError(Exception):
    """Base class for expected CTFKit failures."""


class ConfigurationError(CTFKitError):
    """Raised when user-controlled configuration is invalid."""


class ResolutionError(CTFKitError):
    """Raised when a target cannot be resolved into an approved address set."""


class ToolUnavailableError(CTFKitError):
    """Raised when an explicitly requested external tool is unavailable."""


class ScanError(CTFKitError):
    """Raised when a bounded scanner subprocess fails."""


class AnalysisError(CTFKitError):
    """Raised when a local file cannot be inspected safely."""
