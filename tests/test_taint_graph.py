"""Unit tests for Cross-File Taint Graph Analysis."""

from pathlib import Path
from crs.static_analysis.taint_graph import TaintGraphAnalyzer


def test_taint_graph_analysis(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    vulnerable_code = """import subprocess

def run_user_cmd(cmd):
    subprocess.run(cmd, shell=True)
"""
    (repo / "app.py").write_text(vulnerable_code, encoding="utf-8")

    analyzer = TaintGraphAnalyzer()
    flows = analyzer.analyze_repository(repo)

    assert len(flows) == 1
    assert flows[0].sink.name == "subprocess.run"
    assert flows[0].sink.file == "app.py"
    assert flows[0].sink.line == 4
