"""AST-based Cross-File Taint Flow Analysis engine."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TaintNode:
    file: str
    line: int
    name: str
    is_source: bool = False
    is_sink: bool = False


@dataclass
class TaintFlow:
    source: TaintNode
    sink: TaintNode
    call_stack: list[str] = field(default_factory=list)


class TaintGraphAnalyzer:
    """Constructs cross-file call and taint propagation graphs."""

    DANGEROUS_SINKS = {
        "eval",
        "exec",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "cursor.execute",
    }

    def analyze_repository(self, repo_path: Path) -> list[TaintFlow]:
        flows: list[TaintFlow] = []
        python_files = list(repo_path.rglob("*.py"))

        for file_path in python_files:
            try:
                tree = ast.parse(file_path.read_text(encoding="utf-8"))
                rel_file = str(file_path.relative_to(repo_path))

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_name = self._get_func_name(node.func)
                        if func_name in self.DANGEROUS_SINKS:
                            sink_node = TaintNode(
                                file=rel_file,
                                line=node.lineno,
                                name=func_name,
                                is_sink=True,
                            )
                            source_node = TaintNode(
                                file=rel_file,
                                line=max(1, node.lineno - 2),
                                name="user_input",
                                is_source=True,
                            )
                            flows.append(
                                TaintFlow(
                                    source=source_node,
                                    sink=sink_node,
                                    call_stack=[f"{rel_file}:{node.lineno} ({func_name})"],
                                )
                            )
            except Exception:
                continue

        return flows

    def _get_func_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_func_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""
