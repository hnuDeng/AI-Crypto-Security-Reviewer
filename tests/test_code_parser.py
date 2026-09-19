"""Tests for the code parser tool."""

import pytest
from ai_crypto_reviewer.tools.code_parser import (
    detect_language,
    parse_python_file,
    extract_c_functions,
    get_source_lines,
)


class TestDetectLanguage:
    def test_python(self):
        assert detect_language("main.py") == "python"
        assert detect_language("utils.pyi") == "python"
        assert detect_language("ext.pyx") == "python"

    def test_cpp(self):
        assert detect_language("main.cpp") == "cpp"
        assert detect_language("main.cc") == "cpp"
        assert detect_language("main.cxx") == "cpp"

    def test_c(self):
        assert detect_language("main.c") == "c"

    def test_headers(self):
        assert detect_language("main.h") == "c_header"
        assert detect_language("main.hpp") == "cpp_header"

    def test_unknown(self):
        assert detect_language("main.java") == "unknown"
        assert detect_language("main.txt") == "unknown"


class TestParsePythonFile:
    def test_functions(self):
        source = """
def hello():
    pass

def add(a, b):
    return a + b
"""
        result = parse_python_file("test.py", source)
        assert len(result.functions) == 2
        assert result.functions[0].name == "hello"
        assert result.functions[1].name == "add"
        assert result.functions[1].args == ["a", "b"]

    def test_classes(self):
        source = """
class MyClass:
    def method(self):
        pass
"""
        result = parse_python_file("test.py", source)
        assert len(result.classes) == 1
        assert result.classes[0].name == "MyClass"
        assert len(result.classes[0].methods) == 1

    def test_imports(self):
        source = """
import os
from pathlib import Path
import json
"""
        result = parse_python_file("test.py", source)
        assert "os" in result.imports
        assert "pathlib.Path" in result.imports

    def test_syntax_error(self):
        source = "def broken(\n"
        result = parse_python_file("test.py", source)
        assert result.functions == []

    def test_decorators(self):
        source = """
@property
def value(self):
    return self._value
"""
        result = parse_python_file("test.py", source)
        assert len(result.functions) == 1
        assert "property" in result.functions[0].decorators

    def test_total_lines(self):
        source = "line1\nline2\nline3\n"
        result = parse_python_file("test.py", source)
        assert result.total_lines == 3


class TestExtractCFunctions:
    def test_simple_function(self):
        source = "int add(int a, int b) {\n    return a + b;\n}\n"
        funcs = extract_c_functions(source)
        assert len(funcs) >= 1
        assert funcs[0]["name"] == "add"

    def test_void_function(self):
        source = "void process(char* data) {\n    printf(data);\n}\n"
        funcs = extract_c_functions(source)
        assert len(funcs) >= 1
        assert funcs[0]["name"] == "process"

    def test_no_functions(self):
        source = "#include <stdio.h>\nint x = 5;\n"
        funcs = extract_c_functions(source)
        assert len(funcs) == 0


class TestGetSourceLines:
    def test_basic(self):
        source = "line1\nline2\nline3\nline4"
        result = get_source_lines(source, 2, 3)
        assert result == "line2\nline3"

    def test_out_of_bounds(self):
        source = "line1\nline2"
        result = get_source_lines(source, 0, 100)
        assert "line1" in result
        assert "line2" in result
