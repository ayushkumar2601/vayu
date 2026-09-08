"""Multi-language build and test execution runner."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import subprocess


@dataclass
class LanguageTestResult:
    language: str
    build_passed: bool
    tests_passed: bool
    details: str = ""


class LanguageRunner:
    """Executes language-native build and unit test commands."""

    SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "go", "rust"}

    @staticmethod
    def detect_languages(repo_path: Path) -> list[str]:
        languages = []
        if any(repo_path.glob("*.py")) or any(repo_path.rglob("*.py")):
            languages.append("python")
        if (
            (repo_path / "package.json").exists()
            or any(repo_path.glob("*.js"))
            or any(repo_path.glob("*.ts"))
        ):
            languages.append("javascript")
        if (repo_path / "go.mod").exists() or any(repo_path.glob("*.go")):
            languages.append("go")
        if (repo_path / "Cargo.toml").exists() or any(repo_path.glob("*.rs")):
            languages.append("rust")
        return languages or ["python"]

    def run_tests(self, repo_path: Path, language: str) -> LanguageTestResult:
        if language == "python":
            return self._run_python(repo_path)
        elif language in ("javascript", "typescript"):
            return self._run_javascript(repo_path)
        elif language == "go":
            return self._run_go(repo_path)
        elif language == "rust":
            return self._run_rust(repo_path)
        else:
            return LanguageTestResult(
                language=language,
                build_passed=True,
                tests_passed=True,
                details=f"No automated harness for {language}",
            )

    def _run_python(self, repo_path: Path) -> LanguageTestResult:
        try:
            res = subprocess.run(
                ["pytest", "-q"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            passed = res.returncode == 0
            return LanguageTestResult(
                language="python",
                build_passed=True,
                tests_passed=passed,
                details=res.stdout or res.stderr,
            )
        except Exception as exc:
            return LanguageTestResult(
                language="python", build_passed=True, tests_passed=False, details=str(exc)
            )

    def _run_javascript(self, repo_path: Path) -> LanguageTestResult:
        if not (repo_path / "package.json").exists():
            return LanguageTestResult("javascript", True, True, "No package.json")
        try:
            res = subprocess.run(
                ["npm", "test"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return LanguageTestResult(
                language="javascript",
                build_passed=True,
                tests_passed=res.returncode == 0,
                details=res.stdout or res.stderr,
            )
        except Exception as exc:
            return LanguageTestResult("javascript", True, False, str(exc))

    def _run_go(self, repo_path: Path) -> LanguageTestResult:
        try:
            build = subprocess.run(
                ["go", "build", "./..."],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if build.returncode != 0:
                return LanguageTestResult("go", False, False, build.stderr)

            test = subprocess.run(
                ["go", "test", "./..."],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return LanguageTestResult(
                language="go",
                build_passed=True,
                tests_passed=test.returncode == 0,
                details=test.stdout or test.stderr,
            )
        except Exception as exc:
            return LanguageTestResult("go", False, False, str(exc))

    def _run_rust(self, repo_path: Path) -> LanguageTestResult:
        try:
            check = subprocess.run(
                ["cargo", "check"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if check.returncode != 0:
                return LanguageTestResult("rust", False, False, check.stderr)

            test = subprocess.run(
                ["cargo", "test"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return LanguageTestResult(
                language="rust",
                build_passed=True,
                tests_passed=test.returncode == 0,
                details=test.stdout or test.stderr,
            )
        except Exception as exc:
            return LanguageTestResult("rust", False, False, str(exc))
