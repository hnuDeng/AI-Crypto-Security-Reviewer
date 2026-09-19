"""Tests for the memory checker tool."""

import pytest
from ai_crypto_reviewer.tools.memory_checker import MemoryChecker
from ai_crypto_reviewer.types import Severity


class TestMemoryChecker:
    def setup_method(self):
        self.checker = MemoryChecker()

    def test_detects_strcpy(self):
        source = 'strcpy(buffer, input);\n'
        findings = self.checker.analyze("test.c", source)
        assert any(f.rule_id == "MEM-STRCPY" for f in findings)

    def test_detects_strcat(self):
        source = 'strcat(buffer, suffix);\n'
        findings = self.checker.analyze("test.c", source)
        assert any(f.rule_id == "MEM-STRCAT" for f in findings)

    def test_detects_sprintf(self):
        source = 'sprintf(buffer, "%s", data);\n'
        findings = self.checker.analyze("test.c", source)
        assert any(f.rule_id == "MEM-SPRINTF" for f in findings)

    def test_detects_memory_leak(self):
        source = """
int* ptr = (int*)malloc(sizeof(int) * 10);
*ptr = 42;
return 0;
"""
        findings = self.checker.analyze("leak.c", source)
        assert any(f.rule_id == "MEM-LEAK" for f in findings)

    def test_no_leak_when_freed(self):
        source = """
int* ptr = (int*)malloc(sizeof(int) * 10);
*ptr = 42;
free(ptr);
return 0;
"""
        findings = self.checker.analyze("ok.c", source)
        leak_findings = [f for f in findings if f.rule_id == "MEM-LEAK"]
        assert len(leak_findings) == 0

    def test_detects_small_buffer(self):
        source = "char buf[32];\n"
        findings = self.checker.analyze("test.c", source)
        assert any(f.rule_id == "MEM-BUF-SMALL" for f in findings)

    def test_detects_format_string(self):
        source = 'printf(user_input);\n'
        findings = self.checker.analyze("test.c", source)
        assert any(f.rule_id == "MEM-FMTSTR" for f in findings)

    def test_detects_malloc_no_null_check(self):
        source = """
int* ptr = (int*)malloc(sizeof(int));
*ptr = 5;
"""
        findings = self.checker.analyze("test.c", source)
        null_findings = [f for f in findings if f.rule_id == "MEM-NULL"]
        assert len(null_findings) >= 1

    def test_no_findings_on_clean_code(self):
        source = """
#include <stdlib.h>
int main() {
    int* ptr = malloc(sizeof(int));
    if (ptr == NULL) return -1;
    *ptr = 42;
    free(ptr);
    ptr = NULL;
    return 0;
}
"""
        findings = self.checker.analyze("clean.c", source)
        # Should have no critical/high memory issues
        high_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_findings) == 0
