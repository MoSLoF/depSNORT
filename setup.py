"""Build shim: compile the Go binary into the wheel so `pip install depSNORT`
yields a working `depsnort` command. Requires the Go toolchain at build time
(the tool itself is a single static Go binary — Decision D-10)."""
import os
import subprocess
from setuptools import setup
from setuptools.command.build_py import build_py


class BuildGoBinary(build_py):
    def run(self):
        super().run()
        out_dir = os.path.join(self.build_lib, "depsnort", "_bin")
        os.makedirs(out_dir, exist_ok=True)
        binary = "depsnort.exe" if os.name == "nt" else "depsnort"
        env = dict(os.environ, CGO_ENABLED="0")
        subprocess.check_call(
            ["go", "build", "-ldflags", "-X main.version=v0.6.1",
             "-o", os.path.join(out_dir, binary), "./cmd/depsnort"],
            env=env,
        )


setup(cmdclass={"build_py": BuildGoBinary})
