"""A minimal test runner, because this project has no test dependencies.

Why not pytest
--------------
pytest is the right tool and this file is a compromise. The reason for the
compromise is that ``quillback``'s entire value proposition is "install this in
your CI and it runs". Every dependency is a thing a security team has to review
before they will let it near a pipeline. Zero dependencies is worth a slightly
worse test runner.

If the project grows, replace this with pytest and keep the test functions —
they are plain asserts with no custom API, so they port directly.

Usage::

    python3 tests/run_tests.py          # run everything
    python3 tests/run_tests.py -k asi01 # only tests matching a substring
    python3 tests/run_tests.py -v       # list each test name
"""

from __future__ import annotations

import argparse
import importlib
import pkgutil
import sys
import traceback
from pathlib import Path
from typing import Callable

# Make the package importable when run from the repository root or from tests/.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

TEST_MODULES = (
    "tests.test_attacks",
    "tests.test_runner",
    "tests.test_sarif",
    "tests.test_demo_contrast",
)


def collect() -> list[tuple[str, Callable[[], None]]]:
    """Import every test module and gather ``test_*`` callables."""
    tests: list[tuple[str, Callable[[], None]]] = []
    for module_name in TEST_MODULES:
        module = importlib.import_module(module_name)
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            obj = getattr(module, name)
            if callable(obj):
                tests.append((f"{module_name}.{name}", obj))
    return tests


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="quillback test runner")
    parser.add_argument("-k", metavar="SUBSTR", help="only run tests whose name contains SUBSTR")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    tests = collect()
    if args.k:
        tests = [(n, f) for n, f in tests if args.k in n]

    if not tests:
        print("no tests collected", file=sys.stderr)
        return 2

    passed: list[str] = []
    failed: list[tuple[str, str]] = []

    for name, fn in tests:
        try:
            fn()
        except Exception:  # noqa: BLE001 - a test failure must not stop the run
            failed.append((name, traceback.format_exc()))
            print("F", end="", flush=True)
        else:
            passed.append(name)
            print("." if not args.verbose else f"PASS {name}", end="" if not args.verbose else "\n", flush=True)

    print()

    for name, tb in failed:
        print(f"\n{'=' * 72}\nFAIL {name}\n{'=' * 72}")
        print(tb)

    print(f"\n{len(passed)} passed, {len(failed)} failed, {len(tests)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
