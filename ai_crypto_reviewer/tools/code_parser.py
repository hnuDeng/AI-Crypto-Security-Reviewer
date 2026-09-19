"""Code parsing utilities for extracting functions, classes, and structure."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FunctionInfo:
    """Metadata about a function/method."""
    name: str
    file_path: str
    start_line: int
    end_line: int
    args: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    is_method: bool = False
    class_name: str = ""
    body_lines: int = 0


@dataclass
class ClassInfo:
    """Metadata about a class."""
    name: str
    file_path: str
    start_line: int
    end_line: int
    bases: list[str] = field(default_factory=list)
    methods: list[FunctionInfo] = field(default_factory=list)
    body_lines: int = 0


@dataclass
class FileStructure:
    """Parsed structure of a source file."""
    file_path: str
    language: str
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    total_lines: int = 0


def detect_language(file_path: str) -> str:
    """Detect the programming language from file extension."""
    ext = Path(file_path).suffix.lower()
    lang_map = {
        ".py": "python",
        ".pyx": "python",
        ".pyi": "python",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".c": "c",
        ".h": "c_header",
        ".hpp": "cpp_header",
        ".hxx": "cpp_header",
    }
    return lang_map.get(ext, "unknown")


def parse_python_file(file_path: str, source: str = "") -> FileStructure:
    """Parse a Python file and extract structural information."""
    if not source:
        source = Path(file_path).read_text(encoding="utf-8", errors="replace")

    structure = FileStructure(
        file_path=file_path,
        language="python",
        total_lines=len(source.splitlines()),
    )

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return structure

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                structure.imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for alias in node.names:
                    structure.imports.append(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            structure.functions.append(_extract_function_info(node, file_path))
        elif isinstance(node, ast.ClassDef):
            class_info = _extract_class_info(node, file_path)
            structure.classes.append(class_info)

    return structure


def _extract_function_info(node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str) -> FunctionInfo:
    """Extract function metadata from an AST node."""
    args = []
    for arg in node.args.args:
        args.append(arg.arg)

    decorators = []
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            decorators.append(dec.id)
        elif isinstance(dec, ast.Attribute):
            decorators.append(ast.dump(dec))

    end_line = getattr(node, "end_lineno", node.lineno + 1)

    return FunctionInfo(
        name=node.name,
        file_path=file_path,
        start_line=node.lineno,
        end_line=end_line,
        args=args,
        decorators=decorators,
        body_lines=end_line - node.lineno,
    )


def _extract_class_info(node: ast.ClassDef, file_path: str) -> ClassInfo:
    """Extract class metadata from an AST node."""
    bases = []
    for base in node.bases:
        if isinstance(base, ast.Name):
            bases.append(base.id)
        elif isinstance(base, ast.Attribute):
            bases.append(f"{ast.dump(base)}")

    methods = []
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_info = _extract_function_info(item, file_path)
            func_info.is_method = True
            func_info.class_name = node.name
            methods.append(func_info)

    end_line = getattr(node, "end_lineno", node.lineno + 1)

    return ClassInfo(
        name=node.name,
        file_path=file_path,
        start_line=node.lineno,
        end_line=end_line,
        bases=bases,
        methods=methods,
        body_lines=end_line - node.lineno,
    )


def extract_c_functions(source: str) -> list[dict]:
    """Extract C/C++ function signatures using regex (heuristic, not full parse)."""
    pattern = re.compile(
        r"(?:(?:static|inline|extern|virtual|explicit|const|unsigned|signed|void|int|float|double|char|bool|size_t|uint\d+_t|int\d+_t|string|auto)\s+)*"
        r"(\w+(?:::\w+)?)\s*\(([^)]*)\)\s*(?:const\s*)?(?:override\s*)?(?:noexcept\s*)?\{",
        re.MULTILINE,
    )
    functions = []
    for match in pattern.finditer(source):
        func_name = match.group(1)
        args_str = match.group(2)
        line_number = source[:match.start()].count("\n") + 1
        functions.append({
            "name": func_name,
            "args": [a.strip() for a in args_str.split(",") if a.strip()],
            "line": line_number,
        })
    return functions


def get_source_lines(source: str, start: int, end: int) -> str:
    """Extract lines from source code (1-based indexing)."""
    lines = source.splitlines()
    start_idx = max(0, start - 1)
    end_idx = min(len(lines), end)
    return "\n".join(lines[start_idx:end_idx])
