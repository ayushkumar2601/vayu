from __future__ import annotations
"""Deterministic Multi-Language build and project-test execution."""

from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import sys

from crs.verification.language_runners import LanguageRunner


@dataclass(frozen=True)
class CheckResult:
    """Internal result for one deterministic verification command."""

    passed: bool
    reason: str
    skipped: bool = False
    stdout: str = ""
    stderr: str = ""


class TestRunner:
    """Run language checks inside the supplied temporary workspace."""

    __test__ = False

    def __init__(self, timeout: float = 60.0, python_executable: str | None = None) -> None:
        if timeout <= 0:
            raise ValueError("Verification timeout must be greater than zero")
        self.timeout = timeout
        self.python_executable = python_executable or sys.executable
        self.language_runner = LanguageRunner()

    def syntax_check(self, workspace_root: str | Path, affected_file: str) -> CheckResult:
        root = Path(workspace_root).resolve()
        target = self._safe_target(root, affected_file)
        ext = target.suffix.lower()

        if ext == ".py":
            return self._run(
                [self.python_executable, "-m", "py_compile", str(target)], root
            )
        elif ext in (".js", ".ts"):
            if (root / "package.json").exists():
                return self._run(["npm", "run", "build"], root)
            return CheckResult(passed=True, reason="No package.json build script")
        elif ext == ".go":
            return self._run(["go", "build", "./..."], root)
        elif ext == ".rs":
            return self._run(["cargo", "check"], root)

        return CheckResult(passed=True, reason=f"Syntax check skipped for {ext}")

    def run_tests(self, workspace_root: str | Path) -> CheckResult:
        root = Path(workspace_root).resolve()
        detected = self.language_runner.detect_languages(root)
        primary_lang = detected[0] if detected else "python"

        if primary_lang == "python":
            tests = root / "tests"
            if not tests.is_dir():
                return CheckResult(
                    passed=True,
                    skipped=True,
                    reason="No project tests found; treated as neutral for MVP verification",
                )
            return self._run(
                [self.python_executable, "-m", "pytest", str(tests)], root
            )
        else:
            result = self.language_runner.run_tests(root, primary_lang)
            return CheckResult(
                passed=result.tests_passed,
                reason=result.details or f"Language tests completed for {primary_lang}",
                stdout=result.details,
            )

    def _run(self, command: list[str], cwd: Path) -> CheckResult:
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return CheckResult(False, "Verification command timed out")
        except OSError as exc:
            return CheckResult(False, f"Unable to run verification command: {exc}")
        detail = completed.stderr.strip() or completed.stdout.strip()
        return CheckResult(
            passed=completed.returncode == 0,
            reason=(
                "Verification command passed"
                if completed.returncode == 0
                else f"Verification command failed: {detail or 'no details'}"
            ),
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    @staticmethod
    def _safe_target(root: Path, affected_file: str) -> Path:
        normalized = affected_file.replace("\\", "/")
        if PurePosixPath(normalized).is_absolute() or PureWindowsPath(affected_file).is_absolute():
            raise ValueError("Affected file must be relative to temporary workspace")
        if ".." in PurePosixPath(normalized).parts:
            raise ValueError("Affected file traversal is not allowed")
        target = (root / Path(*PurePosixPath(normalized).parts)).resolve()
        if not target.is_relative_to(root):
            raise ValueError("Affected file escapes temporary workspace")
        return target
