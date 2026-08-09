"""Launcher: locate the bundled Go binary and hand off to it, unchanged. The
banner and every code path live in the Go tool — this only finds and execs it."""
import os
import sys


def _binary_path():
    here = os.path.dirname(os.path.abspath(__file__))
    name = "depsnort.exe" if os.name == "nt" else "depsnort"
    path = os.path.join(here, "_bin", name)
    return path if os.path.exists(path) else None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    binary = _binary_path()
    if not binary:
        sys.stderr.write(
            "depsnort: bundled binary not found. Reinstall with the Go "
            "toolchain available, or run `go build ./cmd/depsnort`.\n"
        )
        return 70
    if os.name != "nt":
        try:
            os.chmod(binary, 0o755)
        except OSError:
            pass
        os.execv(binary, [binary] + argv)  # replaces this process
        return 0  # unreachable
    import subprocess
    return subprocess.call([binary] + argv)
