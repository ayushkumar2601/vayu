"""Unit tests for multi-language test runner detection."""

from pathlib import Path
from crs.verification.language_runners import LanguageRunner


def test_language_detection(tmp_path: Path):
    runner = LanguageRunner()

    # Python repo
    py_repo = tmp_path / "py_repo"
    py_repo.mkdir()
    (py_repo / "main.py").write_text("print('hello')")
    assert runner.detect_languages(py_repo) == ["python"]

    # JS/TS repo
    js_repo = tmp_path / "js_repo"
    js_repo.mkdir()
    (js_repo / "package.json").write_text("{}")
    assert "javascript" in runner.detect_languages(js_repo)

    # Go repo
    go_repo = tmp_path / "go_repo"
    go_repo.mkdir()
    (go_repo / "go.mod").write_text("module example.com/test")
    assert "go" in runner.detect_languages(go_repo)

    # Rust repo
    rust_repo = tmp_path / "rust_repo"
    rust_repo.mkdir()
    (rust_repo / "Cargo.toml").write_text("[package]\nname=\"test\"")
    assert "rust" in runner.detect_languages(rust_repo)
