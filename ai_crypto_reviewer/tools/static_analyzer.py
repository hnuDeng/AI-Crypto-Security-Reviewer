"""Security-focused static analysis tools for Python and C/C++ code."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ai_crypto_reviewer.types import Finding, Severity


def _try_run(cmd: list[str], timeout: int = 60) -> tuple[str, int]:
    """Run a subprocess command, return (output, returncode). Returns ("", -1) if tool not found."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return result.stdout + result.stderr, result.returncode
    except FileNotFoundError:
        return "", -1
    except subprocess.TimeoutExpired:
        return "[timeout]", -2
    except Exception as e:
        return f"[error: {e}]", -3


class PythonAnalyzer:
    """Static analysis for Python source files using AST-based checks and optional flake8/bandit."""

    SECURITY_PATTERNS: list[tuple[str, str, Severity, str, str]] = [
        # (regex_pattern, rule_id, severity, message, category)
        (r"\beval\s*\(", "SEC101", Severity.CRITICAL, "Use of eval() - arbitrary code execution risk", "injection"),
        (r"\bexec\s*\(", "SEC102", Severity.HIGH, "Use of exec() - arbitrary code execution risk", "injection"),
        (r"\b__import__\s*\(", "SEC103", Severity.HIGH, "Dynamic import via __import__()", "injection"),
        (r"\bos\.system\s*\(", "SEC104", Severity.HIGH, "Shell command execution via os.system()", "command_injection"),
        (r"\bsubprocess\b.*\bshell\s*=\s*True", "SEC105", Severity.MEDIUM, "Shell=True in subprocess - potential injection", "command_injection"),
        (r"\bpickle\.loads?\s*\(", "SEC106", Severity.HIGH, "Deserializing untrusted data with pickle", "deserialization"),
        (r"\byaml\.load\s*\([^)]*\)", "SEC107", Severity.HIGH, "Unsafe YAML loading - use yaml.safe_load()", "deserialization"),
        (r"\btempfile\.mktemp\s*\(", "SEC108", Severity.MEDIUM, "Insecure temp file - use mkstemp() instead", "race_condition"),
        (r"\bassert\s+", "SEC109", Severity.LOW, "Assert used for validation - removed in optimized mode", "validation"),
        (r"password\s*=\s*['\"]", "SEC110", Severity.CRITICAL, "Hardcoded password detected", "hardcoded_secret"),
        (r"secret\s*=\s*['\"][^'\"]{8,}['\"]", "SEC111", Severity.HIGH, "Hardcoded secret/token detected", "hardcoded_secret"),
        (r"api_key\s*=\s*['\"][^'\"]{8,}['\"]", "SEC112", Severity.HIGH, "Hardcoded API key detected", "hardcoded_secret"),
        (r"\bhashlib\.md5\b", "SEC113", Severity.MEDIUM, "MD5 is cryptographically broken - use SHA-256+", "weak_crypto"),
        (r"\bhashlib\.sha1\b", "SEC114", Severity.MEDIUM, "SHA-1 is deprecated for security - use SHA-256+", "weak_crypto"),
        (r"\brandom\.\w+\s*\(", "SEC115", Severity.MEDIUM, "Non-cryptographic PRNG - use secrets module for crypto", "weak_random"),
        (r"MD5|DES|RC4|Blowfish", "SEC116", Severity.HIGH, "Weak cryptographic algorithm referenced", "weak_crypto"),
        (r"\bSSLv[23]\b|\bPROTOCOL_SSLv[23]\b", "SEC117", Severity.HIGH, "Insecure SSL/TLS version", "insecure_transport"),
        (r"\bverify\s*=\s*False", "SEC118", Severity.HIGH, "SSL certificate verification disabled", "insecure_transport"),
        (r"chmod\b[^\n]{0,40}?0?777", "SEC119", Severity.MEDIUM, "World-readable/writable permissions (777)", "permissions"),
        (r"SELECT\s+.*\bFROM\b.*WHERE\b.*['\"]?\s*\+", "SEC120", Severity.CRITICAL, "Possible SQL injection via string concatenation", "injection"),
        (r"os\.path\.join\s*\([^)]*request\.", "SEC121", Severity.HIGH, "Path traversal risk - user input in file path", "path_traversal"),
        (r"requests\.get\s*\([^)]*request\.", "SEC122", Severity.HIGH, "SSRF risk - user-controlled URL in request", "ssrf"),
        (r"DEBUG\s*=\s*True", "SEC124", Severity.MEDIUM, "Debug mode enabled - disable in production", "configuration"),
        (r"marshal\.loads?\s*\(", "SEC125", Severity.HIGH, "Unsafe deserialization with marshal", "deserialization"),
        (r"shelve\.open\s*\(", "SEC126", Severity.MEDIUM, "shelve uses pickle internally - untrusted data risk", "deserialization"),
        (r"redirect\s*\(\s*request\.", "SEC127", Severity.MEDIUM, "Open redirect - user-controlled redirect target", "redirect"),
        (r"Access-Control-Allow-Origin.*\*", "SEC128", Severity.MEDIUM, "CORS wildcard header - allows any origin", "cors"),
        (r"@csrf_exempt", "SEC129", Severity.HIGH, "CSRF protection explicitly disabled", "csrf"),
        (r"subprocess\.call\s*\([^)]*shell\s*=\s*True", "SEC130", Severity.HIGH, "Shell injection via subprocess.call with shell=True", "command_injection"),
    ]

    def analyze(self, file_path: str, source: str = "") -> list[Finding]:
        """Analyze a Python file for security issues."""
        if not source:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")

        findings: list[Finding] = []

        for pattern, rule_id, severity, message, category in self.SECURITY_PATTERNS:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line_num = source[:match.start()].count("\n") + 1
                snippet = self._get_snippet(source, line_num)
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    file_path=file_path,
                    line_number=line_num,
                    category=category,
                    tool="python_analyzer",
                    code_snippet=snippet,
                    recommendation=self._get_recommendation(rule_id),
                ))

        # Check for cryptographic function implementations
        findings.extend(self._check_crypto_implementation(file_path, source))

        return findings

    def _check_crypto_implementation(self, file_path: str, source: str) -> list[Finding]:
        """Deep checks for cryptographic implementation issues."""
        findings = []
        lines = source.splitlines()
        source_lower = source.lower()

        # Detect custom crypto implementations and verify correctness
        if any(kw in source_lower for kw in ["def rsa_", "def encrypt", "def decrypt", "def mod_pow", "def is_prime"]):
            for i, line in enumerate(lines, 1):
                stripped = line.strip()

                # Check for hardcoded small prime factors
                if re.search(r"p\s*=\s*\d{1,6}\b", stripped) and "prime" in source_lower:
                    findings.append(Finding(
                        rule_id="CRYPTO001",
                        severity=Severity.CRITICAL,
                        message="Possible hardcoded small prime in cryptographic context",
                        file_path=file_path,
                        line_number=i,
                        category="weak_crypto",
                        tool="python_analyzer",
                        code_snippet=self._get_snippet(source, i),
                        recommendation="Use a cryptographically secure prime generation function with sufficient bit length (>=2048 bits for RSA).",
                        cwe_id="CWE-327",
                    ))

                # Check for pow() without modular reduction
                if "pow(" in stripped and "mod" not in stripped.lower() and "%" not in stripped:
                    findings.append(Finding(
                        rule_id="CRYPTO002",
                        severity=Severity.HIGH,
                        message="pow() without modular reduction in crypto context - risk of integer overflow",
                        file_path=file_path,
                        line_number=i,
                        category="integer_overflow",
                        tool="python_analyzer",
                        code_snippet=self._get_snippet(source, i),
                        recommendation="Use pow(base, exp, mod) for modular exponentiation.",
                        cwe_id="CWE-190",
                    ))

                # Check for math.gcd usage in RSA without timing attack protection
                if "math.gcd" in stripped and "rsa" in source_lower:
                    findings.append(Finding(
                        rule_id="CRYPTO003",
                        severity=Severity.MEDIUM,
                        message="math.gcd may be vulnerable to timing attacks in cryptographic context",
                        file_path=file_path,
                        line_number=i,
                        category="side_channel",
                        tool="python_analyzer",
                        code_snippet=self._get_snippet(source, i),
                        recommendation="Use a constant-time GCD implementation for cryptographic operations.",
                        cwe_id="CWE-208",
                    ))

        return findings

    @staticmethod
    def _get_snippet(source: str, line_num: int, context: int = 2) -> str:
        lines = source.splitlines()
        start = max(0, line_num - 1 - context)
        end = min(len(lines), line_num + context)
        return "\n".join(f"{'>' if i == line_num - 1 else ' '} {i+1:4d} | {lines[i]}" for i in range(start, end))

    @staticmethod
    def _get_recommendation(rule_id: str) -> str:
        recs = {
            "SEC101": "Replace eval() with ast.literal_eval() or a proper parser.",
            "SEC102": "Avoid exec(); refactor to use functions or importlib.",
            "SEC103": "Use importlib.import_module() instead of __import__().",
            "SEC104": "Use subprocess.run() with a list of arguments instead of os.system().",
            "SEC105": "Use subprocess.run() with shell=False and a list of arguments.",
            "SEC106": "Avoid pickle for untrusted data. Use JSON or a safe serialization format.",
            "SEC107": "Use yaml.safe_load() instead of yaml.load().",
            "SEC108": "Use tempfile.mkstemp() for secure temp file creation.",
            "SEC109": "Use proper validation with if/raise instead of assert.",
            "SEC110": "Move secrets to environment variables or a secrets manager.",
            "SEC111": "Move secrets to environment variables or a secrets manager.",
            "SEC112": "Move API keys to environment variables or a secrets manager.",
            "SEC113": "Use SHA-256 or SHA-3 instead of MD5.",
            "SEC114": "Use SHA-256 or SHA-3 instead of SHA-1.",
            "SEC115": "Use the secrets module for cryptographically secure random values.",
            "SEC116": "Replace with modern algorithms: AES-256-GCM, ChaCha20-Poly1305.",
            "SEC117": "Use TLS 1.2 or higher.",
            "SEC118": "Enable SSL certificate verification (verify=True).",
            "SEC119": "Use restrictive permissions (e.g., 0o600 for private files).",
            "SEC120": "Use parameterized queries to prevent SQL injection.",
            "SEC121": "Use os.path.basename() to strip directory components, and validate against an allowlist.",
            "SEC122": "Validate and sanitize URLs before passing to requests. Use allowlists for domains.",
            "SEC124": "Set DEBUG=False in production. Use environment variables to control debug mode.",
            "SEC125": "Avoid marshal for untrusted data. Use JSON or a safe serialization format.",
            "SEC126": "shelve uses pickle internally. Use JSON files or a proper database for untrusted data.",
            "SEC127": "Validate redirect targets against an allowlist of trusted URLs.",
            "SEC128": "Use specific origins instead of wildcard (*). Example: Access-Control-Allow-Origin: https://example.com",
            "SEC129": "Re-enable CSRF protection. Use @csrf_protect or ensure middleware handles it.",
            "SEC130": "Use subprocess.run() with shell=False and a list of arguments.",
        }
        return recs.get(rule_id, "Review and fix the identified security issue.")


class CppAnalyzer:
    """Static analysis for C/C++ source files using pattern matching and optional cppcheck."""

    SECURITY_PATTERNS: list[tuple[str, str, Severity, str, str]] = [
        (r"\bstrcpy\s*\(", "CSEC001", Severity.HIGH, "Buffer overflow risk - strcpy() has no bounds checking", "buffer_overflow"),
        (r"\bstrcat\s*\(", "CSEC002", Severity.HIGH, "Buffer overflow risk - strcat() has no bounds checking", "buffer_overflow"),
        (r"\bsprintf\s*\(", "CSEC003", Severity.HIGH, "Buffer overflow risk - use snprintf() instead", "buffer_overflow"),
        (r"\bgets\s*\(", "CSEC004", Severity.CRITICAL, "gets() is always unsafe - use fgets() instead", "buffer_overflow"),
        (r"\bmalloc\s*\([^)]*\)(?!\s*\))", "CSEC005", Severity.LOW, "malloc() without NULL check", "null_pointer"),
        (r"\bfree\s*\([^)]*\)", "CSEC006", Severity.LOW, "Verify no use-after-free after free()", "memory_safety"),
        (r"\bnew\s+\w+(?!\s*\()", "CSEC007", Severity.LOW, "Raw new without smart pointer - potential memory leak", "memory_leak"),
        (r"\bdelete\b(?!\s*\[\])", "CSEC008", Severity.LOW, "Raw delete - prefer smart pointers or containers", "memory_leak"),
        (r"\bsystem\s*\(", "CSEC009", Severity.HIGH, "Shell command execution via system()", "command_injection"),
        (r"\bscanf\s*\(", "CSEC010", Severity.MEDIUM, "scanf() can cause buffer overflows - use fgets()+parse", "buffer_overflow"),
        (r"\batoi\s*\(|\batol\s*\(|\batof\s*\(", "CSEC011", Severity.MEDIUM, "atoi/atol/atof have no error handling - use strtol etc.", "input_validation"),
        (r"(?:int|long|short|char)\s+\w+\s*=\s*\d+\s*\*", "CSEC012", Severity.MEDIUM, "Possible integer overflow in arithmetic expression", "integer_overflow"),
        (r"free\s*\(\s*(\w+)\s*\)", "CSEC013", Severity.LOW, "Verify no double-free after free()", "memory_safety"),
        (r"alloca\s*\(", "CSEC014", Severity.MEDIUM, "alloca() can cause stack overflow with large sizes", "stack_overflow"),
        (r"memcpy\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*strlen\s*\(", "CSEC016", Severity.HIGH, "memcpy with strlen does not include null terminator", "buffer_overflow"),
    ]

    def analyze(self, file_path: str, source: str = "") -> list[Finding]:
        if not source:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")

        findings = []
        for pattern, rule_id, severity, message, category in self.SECURITY_PATTERNS:
            for match in re.finditer(pattern, source):
                line_num = source[:match.start()].count("\n") + 1
                snippet = PythonAnalyzer._get_snippet(source, line_num)
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    file_path=file_path,
                    line_number=line_num,
                    category=category,
                    tool="cpp_analyzer",
                    code_snippet=snippet,
                    recommendation=self._get_recommendation(rule_id),
                ))

        findings.extend(self._check_crypto_implementation(file_path, source))
        return findings

    def _check_crypto_implementation(self, file_path: str, source: str) -> list[Finding]:
        findings = []
        lines = source.splitlines()
        source_lower = source.lower()

        if any(kw in source_lower for kw in ["rsa", "encrypt", "decrypt", "modpow", "is_prime", "gcd"]):
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if re.search(r"rand\(\)|srand\(", stripped):
                    findings.append(Finding(
                        rule_id="CCRYPTO001",
                        severity=Severity.CRITICAL,
                        message="Non-cryptographic PRNG (rand/srand) in cryptographic context",
                        file_path=file_path,
                        line_number=i,
                        category="weak_random",
                        tool="cpp_analyzer",
                        code_snippet=PythonAnalyzer._get_snippet(source, i),
                        recommendation="Use <random> with std::mt19937 or OS-provided /dev/urandom for crypto.",
                        cwe_id="CWE-338",
                    ))

                if re.search(r"int\s+\w+\s*=\s*\d+\s*\*\s*\d+", stripped):
                    findings.append(Finding(
                        rule_id="CCRYPTO002",
                        severity=Severity.HIGH,
                        message="Integer multiplication in crypto context - risk of overflow",
                        file_path=file_path,
                        line_number=i,
                        category="integer_overflow",
                        tool="cpp_analyzer",
                        code_snippet=PythonAnalyzer._get_snippet(source, i),
                        recommendation="Use __int128, GMP, or check for overflow before multiplication.",
                        cwe_id="CWE-190",
                    ))

        return findings

    @staticmethod
    def _get_recommendation(rule_id: str) -> str:
        recs = {
            "CSEC001": "Use strncpy() or strlcpy() with explicit buffer size.",
            "CSEC002": "Use strncat() or strlcat() with explicit buffer size.",
            "CSEC003": "Use snprintf() with explicit buffer size.",
            "CSEC004": "Remove gets() entirely - use fgets() with stdin.",
            "CSEC005": "Always check malloc() return value for NULL.",
            "CSEC006": "Set pointer to NULL after free() to prevent use-after-free.",
            "CSEC007": "Use std::unique_ptr or std::shared_ptr instead of raw new.",
            "CSEC008": "Use smart pointers or containers instead of raw delete.",
            "CSEC009": "Use execve() or fork()+exec() with explicit argument list.",
            "CSEC010": "Use fgets() to read input, then parse with sscanf or strtol.",
            "CSEC011": "Use strtol/strtoul with proper error checking.",
            "CSEC012": "Use safe integer arithmetic or check for overflow before operations.",
            "CSEC013": "Set pointer to NULL after free() to prevent double-free. Consider smart pointers.",
            "CSEC014": "Use std::vector or std::array instead of alloca() for stack allocation.",
            "CSEC016": "Use memcpy(dst, src, strlen(src) + 1) or strncpy() for null-terminated strings.",
        }
        return recs.get(rule_id, "Review and fix the identified security issue.")


def run_cppcheck(file_path: str) -> list[Finding]:
    """Run cppcheck on a C/C++ file if available."""
    cmd = ["cppcheck", "--enable=warning,performance,portability", "--quiet", "--error-exitcode=0", file_path]
    output, rc = _try_run(cmd)
    if rc == -1:
        return []  # cppcheck not installed

    findings = []
    pattern = re.compile(r"^(.+):(\d+):(\d+):\s*(\w+):\s*(.+)$", re.MULTILINE)
    severity_map = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "performance": Severity.LOW, "portability": Severity.LOW, "information": Severity.INFO}
    for match in pattern.finditer(output):
        findings.append(Finding(
            rule_id=f"CPPCHECK-{match.group(4).upper()}",
            severity=severity_map.get(match.group(4), Severity.INFO),
            message=match.group(5),
            file_path=match.group(1),
            line_number=int(match.group(2)),
            tool="cppcheck",
        ))
    return findings


def run_flake8(file_path: str) -> list[Finding]:
    """Run flake8 on a Python file if available."""
    cmd = ["python", "-m", "flake8", "--select=E,W,F", "--max-line-length=120", file_path]
    output, rc = _try_run(cmd)
    if rc == -1 or not output.strip():
        return []

    findings = []
    pattern = re.compile(r"^(.+):(\d+):(\d+):\s*(\w\d+)\s+(.+)$", re.MULTILINE)
    for match in pattern.finditer(output):
        code = match.group(4)
        sev = Severity.LOW
        if code.startswith("E"):
            sev = Severity.MEDIUM
        elif code.startswith("F"):
            sev = Severity.HIGH
        findings.append(Finding(
            rule_id=f"FLAKE8-{code}",
            severity=sev,
            message=match.group(5),
            file_path=match.group(1),
            line_number=int(match.group(2)),
            tool="flake8",
        ))
    return findings


def run_bandit(file_path: str) -> list[Finding]:
    """Run bandit on a Python file if available."""
    cmd = ["python", "-m", "bandit", "-f", "json", "-q", file_path]
    output, rc = _try_run(cmd)
    if rc == -1 or not output.strip():
        return []

    import json
    findings = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    severity_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    confidence_map = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}

    for result in data.get("results", []):
        findings.append(Finding(
            rule_id=f"BANDIT-{result.get('test_id', 'unknown')}",
            severity=severity_map.get(result.get("issue_severity", ""), Severity.INFO),
            message=result.get("issue_text", ""),
            file_path=result.get("filename", file_path),
            line_number=result.get("line_number", 0),
            category=result.get("test_name", ""),
            tool="bandit",
            cwe_id=f"CWE-{result.get('issue_cwe', {}).get('id', '')}" if result.get("issue_cwe") else "",
        ))
    return findings
