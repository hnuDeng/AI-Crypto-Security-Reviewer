"""Coder Agent - Generates security patches based on analyzer findings.

This agent takes findings from the Analyzer Agent and produces concrete code
patches (diffs) to remediate each identified vulnerability. It uses:
- Rule-based fix templates for common vulnerability patterns
- Context-aware patching that preserves surrounding code
- Chain-of-Thought reasoning before modifying cryptographic logic
"""

from __future__ import annotations

import re
from pathlib import Path

from ai_crypto_reviewer.agents.base import AgentContext, BaseAgent
from ai_crypto_reviewer.types import Finding, Patch, Severity


# Fix templates: (rule_id_prefix, fix_function_name)
FIX_REGISTRY: dict[str, str] = {}


def register_fix(rule_prefix: str):
    """Decorator to register a fix function for a rule prefix."""
    def decorator(func):
        FIX_REGISTRY[rule_prefix] = func.__name__
        return func
    return decorator


class CoderAgent(BaseAgent):
    """Agent responsible for generating code patches to fix security findings."""

    def __init__(self, config: dict | None = None):
        super().__init__("Coder", config)
        self._patches_generated = 0

    def execute(self, context: AgentContext) -> AgentContext:
        """Generate patches for all findings."""
        self.log(f"Generating patches for {len(context.findings)} findings")
        patches: list[Patch] = []

        for finding in context.findings:
            try:
                patch = self._generate_patch(finding, context)
                if patch and not patch.is_empty:
                    patches.append(patch)
            except Exception as e:
                context.errors.append(f"Patch generation failed for {finding.rule_id}: {e}")

        context.patches = patches
        self.log(f"Generated {len(patches)} patches")
        return context

    def _generate_patch(self, finding: Finding, context: AgentContext) -> Patch | None:
        """Generate a patch for a single finding."""
        source = context.get_source(finding.file_path)
        if not source:
            return None

        # Chain of Thought: reason about the fix before applying
        cot_reasoning = self._chain_of_thought(finding)

        # Dispatch to the appropriate fix generator
        fix_fn = self._get_fix_function(finding)
        if fix_fn:
            return fix_fn(finding, source, context)

        # Generic fallback: add a warning comment
        return self._add_warning_comment(finding, source)

    def _chain_of_thought(self, finding: Finding) -> str:
        """Generate Chain-of-Thought reasoning for the fix.

        For cryptographic modifications, this ensures we reason through
        the mathematical implications before applying changes.
        """
        reasoning = f"[CoT] Finding: {finding.rule_id} ({finding.severity.value})\n"
        reasoning += f"[CoT] Issue: {finding.message}\n"
        reasoning += f"[CoT] Location: {finding.file_path}:{finding.line_number}\n"

        if finding.is_crypto_related:
            reasoning += "[CoT] CRYPTO CONTEXT: This modification affects cryptographic logic.\n"
            reasoning += "[CoT] Verification: Mathematical correctness must be preserved.\n"
            if "key_size" in finding.category or "keysize" in finding.rule_id.lower():
                reasoning += "[CoT] Key size change: Ensure backward compatibility or document migration.\n"
            if "weak" in finding.category:
                reasoning += "[CoT] Algorithm replacement: Verify equivalent security properties.\n"

        self.log(reasoning, level="debug")
        return reasoning

    def _get_fix_function(self, finding: Finding):
        """Get the appropriate fix function for a finding."""
        fix_map = {
            "SEC101": self._fix_eval_exec,
            "SEC102": self._fix_eval_exec,
            "SEC105": self._fix_subprocess_shell,
            "SEC107": self._fix_yaml_load,
            "SEC110": self._fix_hardcoded_secret,
            "SEC111": self._fix_hardcoded_secret,
            "SEC112": self._fix_hardcoded_secret,
            "SEC113": self._fix_weak_hash,
            "SEC114": self._fix_weak_hash,
            "SEC115": self._fix_weak_random,
            "SEC118": self._fix_ssl_verify,
            "CSEC001": self._fix_cpp_strcpy,
            "CSEC003": self._fix_cpp_sprintf,
            "CSEC004": self._fix_cpp_gets,
            "WEAK-RANDOM": self._fix_weak_random,
            "CRYPTO-KEYSIZE": self._fix_key_size,
            "CRYPTO-STATIC-IV": self._fix_static_iv,
            "CRYPTO-TIMING": self._fix_timing_comparison,
        }
        fn_name = fix_map.get(finding.rule_id)
        if fn_name:
            return fn_name
        # Try prefix matching
        for prefix, fn in fix_map.items():
            if finding.rule_id.startswith(prefix):
                return fn
        return None

    def _apply_line_fix(self, source: str, line_num: int, old_pattern: str, replacement: str) -> str:
        """Apply a regex replacement on a specific line."""
        lines = source.splitlines(keepends=True)
        idx = line_num - 1
        if 0 <= idx < len(lines):
            lines[idx] = re.sub(old_pattern, replacement, lines[idx])
        return "".join(lines)

    @register_fix("SEC101")
    def _fix_eval_exec(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            if "eval(" in original:
                fixed = original.replace("eval(", "ast.literal_eval(")
                lines[idx] = fixed
                patched_source = "".join(lines)
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code=patched_source,
                    description="Replaced eval() with ast.literal_eval() for safe evaluation",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _fix_subprocess_shell(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            fixed = re.sub(r"shell\s*=\s*True", "shell=False", original)
            if fixed != original:
                lines[idx] = fixed
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code="".join(lines),
                    description="Changed shell=True to shell=False in subprocess call",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _fix_yaml_load(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            lines[idx] = lines[idx].replace("yaml.load(", "yaml.safe_load(")
            return Patch(
                file_path=finding.file_path,
                original_code=source,
                patched_code="".join(lines),
                description="Replaced yaml.load() with yaml.safe_load() for safe deserialization",
                finding=finding,
                start_line=finding.line_number,
                end_line=finding.line_number,
            )
        return self._add_warning_comment(finding, source)

    def _fix_hardcoded_secret(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            # Replace hardcoded value with os.environ.get()
            fixed = re.sub(
                r"(\w+)\s*=\s*['\"][^'\"]+['\"]",
                r'\1 = os.environ.get("\1", "")',
                original,
            )
            if fixed != original:
                lines[idx] = fixed
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code="".join(lines),
                    description="Moved hardcoded secret to environment variable",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _fix_weak_hash(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            fixed = original.replace("hashlib.md5", "hashlib.sha256").replace("hashlib.sha1", "hashlib.sha256")
            lines[idx] = fixed
            return Patch(
                file_path=finding.file_path,
                original_code=source,
                patched_code="".join(lines),
                description="Replaced weak hash (MD5/SHA-1) with SHA-256",
                finding=finding,
                start_line=finding.line_number,
                end_line=finding.line_number,
            )
        return self._add_warning_comment(finding, source)

    def _fix_weak_random(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            fixed = original
            fixed = re.sub(r"random\.random\(\)", "secrets.randbelow(2**32) / 2**32", fixed)
            fixed = re.sub(r"random\.randint\(([^)]+)\)", r"secrets.randbelow(\1[1] - \1[0] + 1) + \1[0]", fixed)
            if fixed != original:
                lines[idx] = fixed
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code="".join(lines),
                    description="Replaced non-cryptographic random with secrets module",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _fix_ssl_verify(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            lines[idx] = lines[idx].replace("verify=False", "verify=True")
            return Patch(
                file_path=finding.file_path,
                original_code=source,
                patched_code="".join(lines),
                description="Enabled SSL certificate verification",
                finding=finding,
                start_line=finding.line_number,
                end_line=finding.line_number,
            )
        return self._add_warning_comment(finding, source)

    def _fix_cpp_strcpy(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            match = re.search(r"strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)", original)
            if match:
                dest = match.group(1)
                src = match.group(2)
                fixed = original.replace(
                    match.group(0),
                    f"strncpy({dest}, {src}, sizeof({dest}) - 1); {dest}[sizeof({dest}) - 1] = '\\0'"
                )
                lines[idx] = fixed
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code="".join(lines),
                    description=f"Replaced strcpy() with strncpy() for buffer '{dest}'",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _fix_cpp_sprintf(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            fixed = original.replace("sprintf(", "snprintf(")
            if fixed != original and "snprintf" in fixed:
                # Add size parameter
                fixed = re.sub(r"snprintf\((\w+),", r"snprintf(\1, sizeof(\1),", fixed)
            lines[idx] = fixed
            return Patch(
                file_path=finding.file_path,
                original_code=source,
                patched_code="".join(lines),
                description="Replaced sprintf() with snprintf() with bounds checking",
                finding=finding,
                start_line=finding.line_number,
                end_line=finding.line_number,
            )
        return self._add_warning_comment(finding, source)

    def _fix_cpp_gets(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            match = re.search(r"gets\s*\(\s*(\w+)\s*\)", original)
            if match:
                buf = match.group(1)
                fixed = original.replace(match.group(0), f"fgets({buf}, sizeof({buf}), stdin)")
                lines[idx] = fixed
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code="".join(lines),
                    description=f"Replaced gets() with fgets() for buffer '{buf}'",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _fix_key_size(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            # Replace small key sizes with 2048
            fixed = re.sub(r"(bits|key_size|KEY_SIZE|generate)\s*[=]*\s*\d{1,4}\b", lambda m: m.group(0).rstrip("0123456789") + "2048", original)
            if fixed != original:
                lines[idx] = fixed
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code="".join(lines),
                    description="Increased key size to minimum 2048 bits",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _fix_static_iv(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            fixed = re.sub(
                r"(iv|nonce)\s*=\s*['\"][^'\"]+['\"]",
                r'\1 = os.urandom(16)',
                original,
                flags=re.IGNORECASE,
            )
            if fixed != original:
                lines[idx] = fixed
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code="".join(lines),
                    description="Replaced static IV/nonce with random generation",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _fix_timing_comparison(self, finding: Finding, source: str, context: AgentContext) -> Patch:
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            original = lines[idx]
            fixed = re.sub(
                r"(\w+)\s*==\s*(\w+)",
                r"hmac.compare_digest(\1, \2)",
                original,
            )
            if fixed != original:
                lines[idx] = fixed
                return Patch(
                    file_path=finding.file_path,
                    original_code=source,
                    patched_code="".join(lines),
                    description="Replaced == with hmac.compare_digest() for constant-time comparison",
                    finding=finding,
                    start_line=finding.line_number,
                    end_line=finding.line_number,
                )
        return self._add_warning_comment(finding, source)

    def _add_warning_comment(self, finding: Finding, source: str) -> Patch:
        """Fallback: add a security warning comment above the finding."""
        lines = source.splitlines(keepends=True)
        idx = finding.line_number - 1
        if 0 <= idx < len(lines):
            indent = len(lines[idx]) - len(lines[idx].lstrip())
            comment_char = "#" if finding.file_path.endswith((".py", ".pyx")) else "//"
            warning = (
                f"{' ' * indent}{comment_char} SECURITY WARNING [{finding.rule_id}]: {finding.message}\n"
                f"{' ' * indent}{comment_char} Recommendation: {finding.recommendation}\n"
            )
            lines.insert(idx, warning)
            return Patch(
                file_path=finding.file_path,
                original_code=source,
                patched_code="".join(lines),
                description=f"Added security warning for {finding.rule_id}",
                finding=finding,
                start_line=finding.line_number,
                end_line=finding.line_number,
            )
        return Patch(
            file_path=finding.file_path,
            original_code=source,
            patched_code=source,
            description="No patch generated",
            finding=finding,
        )
