"""Unit tests for the Autonomous Fuzzing Harness Generator."""

from pathlib import Path
from crs.verification.fuzz_generator import FuzzGenerator


def test_fuzz_generator(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    app_py = repo / "app.py"
    app_py.write_text("def run(cmd):\n    pass\n", encoding="utf-8")

    fuzzer = FuzzGenerator()
    harness = fuzzer.generate_harness(app_py, "run")
    assert "PAYLOADS" in harness
    assert "fuzz()" in harness

    result = fuzzer.run_fuzz_session(repo, "app.py")
    assert result.iterations == 5
    assert result.vulnerability_reproduced is False
