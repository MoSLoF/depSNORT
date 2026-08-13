"""depSNORT — an IDS for the dependency supply chain (static, zero-execution).

This Python package is a thin launcher over the Go binary it bundles; the
engine is Go (Decision D-10). Installing gives you the `depsnort` command."""

# Derived from the installed distribution metadata rather than hardcoded, so the
# version has exactly one source (pyproject.toml) and cannot drift from the Go
# binary or the wheel (finding F-06).
try:
    from importlib.metadata import PackageNotFoundError, version as _version
except ImportError:  # pragma: no cover - Python < 3.8
    from importlib_metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("depSNORT")
except PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]
