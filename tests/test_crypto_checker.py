"""Tests for the crypto checker tool."""

import pytest
from ai_crypto_reviewer.tools.crypto_checker import CryptoChecker
from ai_crypto_reviewer.types import Severity


class TestCryptoChecker:
    def setup_method(self):
        self.checker = CryptoChecker()

    def test_detects_md5(self):
        source = "import hashlib\nh = hashlib.md5(b'data').hexdigest()\n"
        findings = self.checker.analyze("test.py", source)
        assert any("MD5" in f.message.upper() or "WEAK" in f.rule_id for f in findings)

    def test_detects_sha1(self):
        source = "h = hashlib.sha1(b'data').hexdigest()\n"
        findings = self.checker.analyze("test.py", source)
        assert any("SHA-1" in f.message or "SHA1" in f.message.upper() or "WEAK" in f.rule_id for f in findings)

    def test_detects_des(self):
        source = "cipher = DES.new(key)\n"
        findings = self.checker.analyze("test.py", source)
        assert any("DES" in f.message.upper() or "WEAK" in f.rule_id for f in findings)

    def test_detects_rc4(self):
        source = "cipher = RC4.new(key)\n"
        findings = self.checker.analyze("test.py", source)
        assert any("RC4" in f.message.upper() or "WEAK" in f.rule_id for f in findings)

    def test_detects_weak_random_in_crypto(self):
        source = """
def generate_nonce():
    return random.randint(0, 2**32)
"""
        findings = self.checker.analyze("crypto.py", source)
        assert any(f.rule_id == "WEAK-RANDOM" for f in findings)

    def test_detects_c_rand(self):
        source = "int key = rand();\n"
        findings = self.checker.analyze("test.c", source)
        assert any(f.rule_id == "WEAK-RANDOM" for f in findings)

    def test_detects_small_rsa_key(self):
        source = "key = RSA.generate(512)\n"
        findings = self.checker.analyze("rsa.py", source)
        key_findings = [f for f in findings if "key" in f.rule_id.lower() or "keysize" in f.rule_id.lower() or "KEYSIZE" in f.rule_id]
        assert len(key_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in key_findings)

    def test_detects_static_iv(self):
        source = 'iv = "fixed_iv_value_here"\n'
        findings = self.checker.analyze("aes.py", source)
        iv_findings = [f for f in findings if "STATIC" in f.rule_id.upper() or "IV" in f.rule_id.upper() or "IV" in f.message.upper()]
        assert len(iv_findings) >= 1

    def test_detects_timing_unsafe_comparison(self):
        source = "if token == expected_token:\n    authenticate()\n"
        findings = self.checker.analyze("auth.py", source)
        timing_findings = [f for f in findings if "TIMING" in f.rule_id.upper() or "timing" in f.message.lower()]
        assert len(timing_findings) >= 1

    def test_detects_rsa_e1(self):
        source = """
def rsa_keygen():
    e = 1
    n = p * q
    return (e, n)
"""
        findings = self.checker.analyze("bad_rsa.py", source)
        assert any("RSA" in f.rule_id and "E1" in f.rule_id for f in findings)

    def test_no_false_positive_on_safe_crypto(self):
        source = """
import hashlib
h = hashlib.sha256(b'data').hexdigest()
import secrets
token = secrets.token_hex(32)
"""
        findings = self.checker.analyze("safe.py", source)
        # Should not flag SHA-256 or secrets
        weak_findings = [f for f in findings if "WEAK" in f.rule_id]
        assert len(weak_findings) == 0

    def test_key_size_2048_ok(self):
        source = "key = RSA.generate(2048)\n"
        findings = self.checker.analyze("ok_rsa.py", source)
        keysize_findings = [f for f in findings if "KEYSIZE" in f.rule_id or "key_size" in f.rule_id.lower()]
        assert len(keysize_findings) == 0

    def test_detects_ecb_mode(self):
        source = "cipher = AES.new(key, AES.ECB)\n"
        findings = self.checker.analyze("aes.py", source)
        assert any("ECB" in f.message for f in findings)
