#!/usr/bin/env python3
"""
Minimal stand-in for pytest, for environments where pytest is not installed.

Supports the subset the EmailShield suite uses: module-scoped fixtures resolved by
parameter name, and @pytest.mark.parametrize. Real pytest is the intended runner;
this exists so the suite can be verified anywhere.

    python3 tools/run_tests.py
"""

from __future__ import annotations

import importlib
import inspect
import sys
import traceback
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------------- #
# A tiny pytest shim, installed before the test module is imported
# --------------------------------------------------------------------------- #

_FIXTURES: dict[str, callable] = {}
_PARAMS: dict[str, list] = {}


def _fixture(*args, **kwargs):
    def register(func):
        _FIXTURES[func.__name__] = func
        return func
    if args and callable(args[0]):
        return register(args[0])
    return register


class _Mark:
    @staticmethod
    def parametrize(argnames, argvalues):
        names = [n.strip() for n in argnames.split(",")]

        def decorate(func):
            _PARAMS[func.__name__] = (names, list(argvalues))
            return func
        return decorate

    def __getattr__(self, _name):
        def passthrough(*_a, **_k):
            def decorate(func):
                return func
            return decorate
        return passthrough


class _Raises:
    def __init__(self, exc):
        self.exc = exc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            raise AssertionError(f"expected {self.exc.__name__} but nothing raised")
        return issubclass(exc_type, self.exc)


shim = types.ModuleType("pytest")
shim.fixture = _fixture
shim.mark = _Mark()
shim.raises = lambda exc: _Raises(exc)
shim.skip = lambda *a, **k: None
sys.modules["pytest"] = shim


def main() -> int:
    module = importlib.import_module("tests.test_emailshield")

    resolved: dict[str, object] = {}

    def get_fixture(name: str):
        if name not in resolved:
            resolved[name] = _FIXTURES[name]()
        return resolved[name]

    tests = [
        (name, obj) for name, obj in vars(module).items()
        if name.startswith("test_") and callable(obj)
    ]
    tests.sort(key=lambda pair: inspect.getsourcelines(pair[1])[1])

    passed = failed = 0
    failures: list[tuple[str, str]] = []

    for name, func in tests:
        signature = inspect.signature(func)
        cases: list[tuple[str, dict]] = []

        if name in _PARAMS:
            argnames, argvalues = _PARAMS[name]
            for values in argvalues:
                if not isinstance(values, (tuple, list)):
                    values = (values,)
                kwargs = dict(zip(argnames, values))
                label = f"{name}[{'-'.join(str(v) for v in values)}]"
                cases.append((label, kwargs))
        else:
            cases.append((name, {}))

        for label, kwargs in cases:
            call_kwargs = dict(kwargs)
            for param in signature.parameters:
                if param not in call_kwargs and param in _FIXTURES:
                    call_kwargs[param] = get_fixture(param)
            try:
                func(**call_kwargs)
                passed += 1
                print(".", end="", flush=True)
            except Exception:
                failed += 1
                print("F", end="", flush=True)
                failures.append((label, traceback.format_exc()))

    print()
    for label, trace in failures:
        print(f"\n{'=' * 74}\nFAILED {label}\n{'-' * 74}\n{trace}")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
