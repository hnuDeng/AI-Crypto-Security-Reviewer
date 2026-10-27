import json
import subprocess
import sys


def test_offline_evaluation_runs_labeled_python_and_c_cases():
    result = subprocess.run(
        [sys.executable, "-m", "ai_crypto_reviewer.offline_evaluation"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["mode"] == "synthetic_offline"
    assert report["summary"]["cases"] >= 6
    cases = {case["id"]: case for case in report["cases"]}
    assert cases["eval-call"]["expected"] is True
    assert cases["eval-call"]["detected"] is True
    assert cases["safe-literal"]["expected"] is False
    assert cases["safe-literal"]["detected"] is False
    assert cases["unsafe-strcpy"]["expected"] is True
    assert cases["unsafe-strcpy"]["detected"] is True
    assert cases["bounded-copy"]["expected"] is False
    assert cases["bounded-copy"]["detected"] is False
    assert report["summary"]["false_positives"] == 0
    assert report["summary"]["false_negatives"] == 0
