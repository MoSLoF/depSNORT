"""Build shim: compile the Go binary into the wheel so `pip install depSNORT`
yields a working `depsnort` command. Requires the Go toolchain at build time
(the tool itself is a single static Go binary — Decision D-10)."""
import os
import subprocess
from setuptools import setup
from setuptools.command.build_py import build_py

# Single-source the version from pyproject.toml so the Go binary, the wheel
# metadata, and `depsnort version` can never drift (finding F-06).
try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # build-time dep on <3.11

with open(os.path.join(os.path.dirname(__file__), "pyproject.toml"), "rb") as _f:
    VERSION = tomllib.load(_f)["project"]["version"]


class BuildGoBinary(build_py):
    def run(self):
        super().run()
        out_dir = os.path.join(self.build_lib, "depsnort", "_bin")
        os.makedirs(out_dir, exist_ok=True)
        binary = "depsnort.exe" if os.name == "nt" else "depsnort"
        out_path = os.path.join(out_dir, binary)
        env = dict(os.environ, CGO_ENABLED="0")
        subprocess.check_call(
            ["go", "build", "-ldflags", "-X main.version=v" + VERSION,
             "-o", out_path, "./cmd/depsnort"],
            env=env,
        )
        # Fail the build loudly if the binary did not land — never ship an empty
        # wheel that installs cleanly and then cannot run (F-04 acceptance).
        if not os.path.exists(out_path):
            raise SystemExit("depsnort: go build produced no binary at %s" % out_path)


# The wheel carries a compiled, OS/arch-specific binary, so it is NOT pure
# Python. Force a platform-specific wheel tag (finding F-04): without this,
# setuptools emits a `py3-none-any` wheel that a package index would offer to
# incompatible platforms, yielding installs that succeed but cannot execute.
cmdclass = {"build_py": BuildGoBinary}
try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel

    class BDistWheel(_bdist_wheel):
        def finalize_options(self):
            super().finalize_options()
            self.root_is_pure = False  # -> platform tag, not "any"

        def get_tag(self):
            # Any interpreter can exec the standalone binary via the launcher, so
            # the Python tag stays broad and the ABI is "none" (no CPython ABI
            # dependency); only the platform is pinned to the built binary.
            _python, _abi, plat = super().get_tag()
            return "py3", "none", plat

    cmdclass["bdist_wheel"] = BDistWheel
except ImportError:  # pragma: no cover - wheel is present in any real build env
    pass


setup(cmdclass=cmdclass)
