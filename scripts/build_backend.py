#!/usr/bin/env python3
"""Build pinned OpenFHE in disposable storage; install runtime in the task."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

OPENFHE_REV = "b59e1f291965f14fbee5172cd83a20f5b856204f"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path)
    p.add_argument("--jobs", type=int, default=4)
    p.add_argument("--prefix", type=Path)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    prefix = (a.prefix or root / ".runtime").resolve()
    cmake = shutil.which("cmake") or str(root / ".venv/bin/cmake")
    if not Path(cmake).exists():
        p.error("Install cmake==3.31.6 into your environment first")
    if not 1 <= a.jobs <= 8:
        p.error("jobs must be 1..8")
    with tempfile.TemporaryDirectory(prefix="ciphershape-build-") as temp:
        source = a.source
        if source is None:
            source = Path(temp) / "source"
            subprocess.run(["git", "clone", "--branch", "v1.6.1", "--depth", "1",
                            "--recurse-submodules", "--shallow-submodules",
                            "https://github.com/openfheorg/openfhe-development.git", str(source)], check=True)
        revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if revision != OPENFHE_REV:
            p.error("source revision does not match pinned OpenFHE 1.6.1")
        build = Path(temp) / "build"
        install = prefix / "openfhe"
        commands = [
            [cmake, "-S", str(source), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release",
             f"-DCMAKE_INSTALL_PREFIX={install}", "-DBUILD_UNITTESTS=OFF", "-DBUILD_EXAMPLES=OFF",
             "-DBUILD_BENCHMARKS=OFF", "-DBUILD_STATIC=ON", "-DBUILD_SHARED=OFF",
             "-DWITH_OPENMP=OFF", "-DGIT_SUBMOD_AUTO=OFF"],
            [cmake, "--build", str(build), "-j", str(a.jobs)],
            [cmake, "--install", str(build)],
            [cmake, "-S", str(root / "native"), "-B", str(Path(temp) / "native"),
             f"-DCMAKE_PREFIX_PATH={install}", "-DCMAKE_BUILD_TYPE=Release"],
            [cmake, "--build", str(Path(temp) / "native"), "-j", "1"],
        ]
        for cmd in commands:
            subprocess.run(cmd, check=True)
        (prefix / "bin").mkdir(parents=True, exist_ok=True)
        for name in ("ciphershape-client", "ciphershape-server"):
            shutil.copy2(Path(temp) / "native" / name, prefix / "bin" / name)
    print(f"Backend installed in {prefix / 'bin'}")


if __name__ == "__main__":
    main()
