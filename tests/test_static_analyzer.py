"""Tests for the static analyzer tools."""

import os
import tempfile
import pytest
from ai_crypto_reviewer.tools.static_analyzer import PythonAnalyzer, CppAnalyzer
from ai_crypto_reviewer.types import Severity


class TestPythonAnalyzer:
    def setup_method(self):
        self.analyzer = PythonAnalyzer()

    def test_detects_eval(self):
        source = "result = eval(user_input)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC101" for f in findings)

    def test_detects_exec(self):
        source = "exec(code_string)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC102" for f in findings)

    def test_detects_os_system(self):
        source = "os.system('rm -rf /')\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC104" for f in findings)

    def test_detects_subprocess_shell(self):
        source = "subprocess.run('ls', shell=True)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC105" for f in findings)

    def test_detects_yaml_load(self):
        source = "data = yaml.load(file_handle)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC107" for f in findings)

    def test_detects_hardcoded_password(self):
        source = 'password = "super_secret_123"\n'
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC110" for f in findings)

    def test_detects_weak_md5(self):
        source = "h = hashlib.md5(data).hexdigest()\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC113" for f in findings)

    def test_detects_weak_sha1(self):
        source = "h = hashlib.sha1(data).hexdigest()\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC114" for f in findings)

    def test_detects_random_module(self):
        source = "val = random.randint(1, 100)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC115" for f in findings)

    def test_detects_ssl_verify_false(self):
        source = "requests.get(url, verify=False)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC118" for f in findings)

    def test_detects_pickle(self):
        source = "data = pickle.loads(untrusted_bytes)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC106" for f in findings)


    def test_detects_path_traversal(self):
        source = 'path = os.path.join(request.args.get("file"), "data")\n'
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC121" for f in findings)

    def test_detects_debug_mode(self):
        source = "DEBUG = True\n"
        findings = self.analyzer.analyze("settings.py", source)
        assert any(f.rule_id == "SEC124" for f in findings)

    def test_detects_marshal_loads(self):
        source = "data = marshal.loads(raw)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC125" for f in findings)

    def test_detects_csrf_exempt(self):
        source = "@csrf_exempt\ndef view():\n    pass\n"
        findings = self.analyzer.analyze("views.py", source)
        assert any(f.rule_id == "SEC129" for f in findings)

    def test_detects_subprocess_call_shell(self):
        source = "subprocess.call(cmd, shell=True)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC130" for f in findings)

    def test_no_false_positive_on_safe_code(self):
        source = "x = 1 + 2\nprint('hello')\n"
        findings = self.analyzer.analyze("test.py", source)
        assert len(findings) == 0

    def test_crypto_context_detection(self):
        source = """
def rsa_encrypt(e, n, message):
    p = 127  # prime factor
    q = 131  # prime factor
    return pow(message, e) % n
"""
        findings = self.analyzer.analyze("test.py", source)
        # Should detect hardcoded small prime and pow without mod
        crypto_findings = [f for f in findings if "CRYPTO" in f.rule_id]
        assert len(crypto_findings) >= 1

    def test_line_numbers_correct(self):
        source = "x = 1\ny = 2\nresult = eval(input())\n"
        findings = self.analyzer.analyze("test.py", source)
        eval_findings = [f for f in findings if f.rule_id == "SEC101"]
        assert len(eval_findings) == 1
        assert eval_findings[0].line_number == 3


class TestPythonAnalyzerExtended:
    def setup_method(self):
        self.analyzer = PythonAnalyzer()

    def test_detects_dynamic_import(self):
        source = "m = __import__('os')\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC103" for f in findings)

    def test_detects_insecure_tempfile(self):
        source = "path = tempfile.mktemp()\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC108" for f in findings)

    def test_detects_assert_validation(self):
        source = "assert user.is_admin\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC109" for f in findings)

    def test_detects_weak_algorithm_reference(self):
        source = "cipher = DES.new(key)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC116" for f in findings)

    def test_detects_insecure_tls(self):
        source = "ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC117" for f in findings)

    def test_detects_world_permissions(self):
        source = "os.chmod('file.txt', 0o777)\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC119" for f in findings)

    def test_detects_sql_injection_concat(self):
        source = "q = 'SELECT * FROM t WHERE id=' + user_id\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC120" for f in findings)

    def test_detects_ssrf(self):
        source = "resp = requests.get(request.args.get('url'))\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC122" for f in findings)

    def test_detects_shelve_usage(self):
        source = "db = shelve.open('cache')\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC126" for f in findings)

    def test_detects_open_redirect(self):
        source = "resp = redirect(request.args.get('next'))\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC127" for f in findings)

    def test_detects_cors_wildcard(self):
        source = "resp.headers['Access-Control-Allow-Origin'] = '*'\n"
        findings = self.analyzer.analyze("test.py", source)
        assert any(f.rule_id == "SEC128" for f in findings)


class TestCppAnalyzer:
    def setup_method(self):
        self.analyzer = CppAnalyzer()

    def test_detects_strcpy(self):
        source = 'strcpy(buffer, user_input);\n'
        findings = self.analyzer.analyze("test.cpp", source)
        assert any(f.rule_id == "CSEC001" for f in findings)

    def test_detects_gets(self):
        source = 'gets(buffer);\n'
        findings = self.analyzer.analyze("test.c", source)
        assert any(f.rule_id == "CSEC004" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_sprintf(self):
        source = 'sprintf(buffer, "%s", input);\n'
        findings = self.analyzer.analyze("test.c", source)
        assert any(f.rule_id == "CSEC003" for f in findings)

    def test_detects_system_call(self):
        source = 'system("rm -rf /");\n'
        findings = self.analyzer.analyze("test.c", source)
        assert any(f.rule_id == "CSEC009" for f in findings)

    def test_detects_rand_in_crypto(self):
        source = """
int generate_key() {
    int key = rand();  // for encrypt
    return key;
}
"""
        findings = self.analyzer.analyze("crypto.cpp", source)
        crypto_findings = [f for f in findings if "CCRYPTO" in f.rule_id]
        assert len(crypto_findings) >= 1

    def test_detects_alloca(self):
        source = "void* p = alloca(1024);\n"
        findings = self.analyzer.analyze("test.c", source)
        assert any(f.rule_id == "CSEC014" for f in findings)

    def test_detects_memcpy_strlen(self):
        source = "memcpy(dst, src, strlen(src));\n"
        findings = self.analyzer.analyze("test.c", source)
        assert any(f.rule_id == "CSEC016" for f in findings)

    def test_no_false_positive_clean_code(self):
        source = """
#include <vector>
int main() {
    std::vector<int> v = {1, 2, 3};
    return 0;
}
"""
        findings = self.analyzer.analyze("clean.cpp", source)
        assert len(findings) == 0
