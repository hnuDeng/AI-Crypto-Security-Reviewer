"""Cryptographic implementation verification and weak algorithm detection."""

from __future__ import annotations

import re
from pathlib import Path

from ai_crypto_reviewer.types import Finding, Severity


# Known weak/insecure cryptographic parameters
WEAK_KEY_SIZES = {
    "rsa": {"min_bits": 2048, "recommended_bits": 4096},
    "dsa": {"min_bits": 2048, "recommended_bits": 3072},
    "dh": {"min_bits": 2048, "recommended_bits": 4096},
    "ecdsa": {"min_bits": 256, "recommended_bits": 384},
}

WEAK_ALGORITHMS = {
    "md5": ("CWE-328", "MD5 has known collision attacks"),
    "sha1": ("CWE-328", "SHA-1 has known collision attacks"),
    "des": ("CWE-327", "DES has a 56-bit key, trivially breakable"),
    "3des": ("CWE-327", "3DES is deprecated, use AES-256-GCM"),
    "rc4": ("CWE-327", "RC4 has known biases and is broken"),
    "blowfish": ("CWE-327", "Blowfish has a 64-bit block size, vulnerable to birthday attacks"),
    "ecb": ("CWE-327", "ECB mode does not provide semantic security"),
}

WEAK_RANDOM_SOURCES = [
    (r"\brandom\.random\s*\(", "Python random module is not cryptographically secure"),
    (r"\brandom\.randint\s*\(", "Python random.randint is not cryptographically secure"),
    (r"\brandom\.choice\s*\(", "Python random.choice is not cryptographically secure"),
    (r"\brandom\.getrandbits\s*\(", "Python random.getrandbits is not cryptographically secure"),
    (r"\brand\s*\(\)", "C/C++ rand() is not cryptographically secure"),
    (r"\bsrand\s*\(", "C/C++ srand() seeds a non-cryptographic PRNG"),
    (r"\bMath\.random\s*\(", "JavaScript Math.random() is not cryptographically secure"),
]

CRYPTO_FUNCTION_PATTERNS = [
    (r"def\s+(rsa_encrypt|rsa_decrypt|encrypt|decrypt)\s*\(", "crypto_function"),
    (r"def\s+(is_prime|fermat_test|miller_rabin)\s*\(", "primality_test"),
    (r"def\s+(mod_pow|modular_exponentiation|power_mod)\s*\(", "modular_arithmetic"),
    (r"def\s+(generate_key|keygen|gen_key|generate_prime)\s*\(", "key_generation"),
    (r"def\s+(sign|verify_signature|ecdsa_sign|dsa_sign)\s*\(", "digital_signature"),
    (r"def\s+(hash_password|hash_data|compute_hash)\s*\(", "hashing"),
    (r"void\s+(encrypt|decrypt|sign|verify|modpow)\s*\(", "crypto_function_c"),
]


class CryptoChecker:
    """Checks cryptographic implementations for common vulnerabilities and weaknesses."""

    def analyze(self, file_path: str, source: str = "") -> list[Finding]:
        if not source:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")

        findings: list[Finding] = []
        findings.extend(self._check_weak_algorithms(file_path, source))
        findings.extend(self._check_weak_random_sources(file_path, source))
        findings.extend(self._check_key_sizes(file_path, source))
        findings.extend(self._check_crypto_patterns(file_path, source))
        findings.extend(self._check_mathematical_correctness(file_path, source))
        return findings

    def _check_weak_algorithms(self, file_path: str, source: str) -> list[Finding]:
        findings = []
        source_lower = source.lower()
        lines = source.splitlines()

        for algo, (cwe, description) in WEAK_ALGORITHMS.items():
            pattern = re.compile(rf"\b{algo}\b", re.IGNORECASE)
            for match in pattern.finditer(source):
                context_start = max(0, match.start() - 50)
                context = source[context_start:match.end() + 50].lower()
                # Skip if in a comment about not using it
                if "do not use" in context or "deprecated" in context or "never" in context:
                    continue
                line_num = source[:match.start()].count("\n") + 1
                findings.append(Finding(
                    rule_id=f"WEAK-{algo.upper()}",
                    severity=Severity.HIGH if algo in ("md5", "des", "rc4") else Severity.MEDIUM,
                    message=f"Weak cryptographic algorithm: {algo.upper()} - {description}",
                    file_path=file_path,
                    line_number=line_num,
                    category="weak_algorithm",
                    tool="crypto_checker",
                    cwe_id=cwe,
                    recommendation=f"Replace {algo.upper()} with a modern algorithm (AES-256-GCM, SHA-256/3).",
                ))
        return findings

    def _check_weak_random_sources(self, file_path: str, source: str) -> list[Finding]:
        findings = []
        for pattern_str, message in WEAK_RANDOM_SOURCES:
            pattern = re.compile(pattern_str)
            for match in pattern.finditer(source):
                line_num = source[:match.start()].count("\n") + 1
                findings.append(Finding(
                    rule_id="WEAK-RANDOM",
                    severity=Severity.HIGH,
                    message=f"Non-cryptographic random source: {message}",
                    file_path=file_path,
                    line_number=line_num,
                    category="weak_random",
                    tool="crypto_checker",
                    cwe_id="CWE-338",
                    recommendation="Use os.urandom(), secrets module, or std::random_device for cryptographic purposes.",
                ))
        return findings

    def _check_key_sizes(self, file_path: str, source: str) -> list[Finding]:
        findings = []
        # Check for RSA key generation with small key sizes
        rsa_key_patterns = [
            (r"RSA\.generate\s*\(\s*(\d+)", "Python RSA.generate"),
            (r"generate_private_key.*?public_exponent.*?key_size\s*=\s*(\d+)", "Python cryptography"),
            (r"rsa\.newkeys\s*\(\s*(\d+)", "Python rsa.newkeys"),
            (r"bits\s*=\s*(\d+)", "Generic bits parameter"),
            (r"KEY_SIZE\s*=\s*(\d+)", "KEY_SIZE constant"),
            (r"key_size\s*=\s*(\d+)", "key_size parameter"),
        ]

        for pattern_str, context in rsa_key_patterns:
            for match in re.finditer(pattern_str, source, re.IGNORECASE):
                try:
                    bits = int(match.group(1))
                except (ValueError, IndexError):
                    continue
                line_num = source[:match.start()].count("\n") + 1
                if bits < 2048 and bits > 0:
                    findings.append(Finding(
                        rule_id="CRYPTO-KEYSIZE",
                        severity=Severity.CRITICAL if bits < 1024 else Severity.HIGH,
                        message=f"Insufficient key size: {bits} bits ({context}). Minimum safe: 2048 bits.",
                        file_path=file_path,
                        line_number=line_num,
                        category="weak_key_size",
                        tool="crypto_checker",
                        cwe_id="CWE-326",
                        recommendation="Use at least 2048-bit keys for RSA. 4096-bit recommended.",
                    ))
        return findings

    def _check_crypto_patterns(self, file_path: str, source: str) -> list[Finding]:
        """Check for insecure patterns in cryptographic code."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Check for static IV/nonce
            if re.search(r"(?:iv|nonce)\s*=\s*['\"]?\w{8,16}['\"]?", stripped, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="CRYPTO-STATIC-IV",
                    severity=Severity.CRITICAL,
                    message="Static IV/nonce detected - must be unique per encryption",
                    file_path=file_path,
                    line_number=i,
                    category="crypto_implementation",
                    tool="crypto_checker",
                    cwe_id="CWE-329",
                    recommendation="Generate IV/nonce randomly for each encryption operation using os.urandom().",
                ))

            # Check for missing padding in block cipher
            if re.search(r"AES|DES|Blowfish", stripped) and "padding" not in source.lower():
                if "ECB" in stripped or "CBC" in stripped:
                    findings.append(Finding(
                        rule_id="CRYPTO-PADDING",
                        severity=Severity.MEDIUM,
                        message="Block cipher mode may need explicit padding (or use GCM/CTR mode)",
                        file_path=file_path,
                        line_number=i,
                        category="crypto_implementation",
                        tool="crypto_checker",
                        recommendation="Use AES-GCM or AES-CTR which don't require padding.",
                    ))

            # Check for timing-unsafe comparison in crypto context
            if re.search(r"(?:token|signature|hash|mac|hmac)\s*==\s*", stripped):
                findings.append(Finding(
                    rule_id="CRYPTO-TIMING",
                    severity=Severity.HIGH,
                    message="Equality comparison on crypto values may be vulnerable to timing attacks",
                    file_path=file_path,
                    line_number=i,
                    category="side_channel",
                    tool="crypto_checker",
                    cwe_id="CWE-208",
                    recommendation="Use hmac.compare_digest() for constant-time comparison.",
                ))

        return findings

    def _check_mathematical_correctness(self, file_path: str, source: str) -> list[Finding]:
        """Check for common mathematical errors in crypto implementations."""
        findings = []
        source_lower = source.lower()

        # Check for Fermat primality test without sufficient iterations
        if "fermat" in source_lower:
            iter_match = re.search(r"(?:for|range)\s*\(\s*(\d+)", source)
            if iter_match:
                iters = int(iter_match.group(1))
                if iters < 20:
                    line_num = source[:iter_match.start()].count("\n") + 1
                    findings.append(Finding(
                        rule_id="CRYPTO-FERMAT-ITERS",
                        severity=Severity.HIGH,
                        message=f"Fermat test with only {iters} iterations - high false positive rate",
                        file_path=file_path,
                        line_number=line_num,
                        category="crypto_correctness",
                        tool="crypto_checker",
                        cwe_id="CWE-327",
                        recommendation="Use Miller-Rabin with at least 40 iterations, or use a deterministic test for the expected bit range.",
                    ))

        # Check for RSA with e=1 (trivial encryption)
        if re.search(r"e\s*=\s*1\b", source) and "rsa" in source_lower:
            match = re.search(r"e\s*=\s*1\b", source)
            if match:
                line_num = source[:match.start()].count("\n") + 1
                findings.append(Finding(
                    rule_id="CRYPTO-RSA-E1",
                    severity=Severity.CRITICAL,
                    message="RSA public exponent e=1 is insecure (ciphertext equals plaintext)",
                    file_path=file_path,
                    line_number=line_num,
                    category="crypto_correctness",
                    tool="crypto_checker",
                    cwe_id="CWE-327",
                    recommendation="Use e=65537 (0x10001) as the standard public exponent.",
                ))

        return findings
