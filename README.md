<div align="center">

# 🛡️ AI-Crypto-Security-Reviewer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**A rule-based code review and suggested-patch pipeline for Python and C/C++, with checks for common cryptographic and memory-safety patterns.**

[Report Bug](https://github.com/hnuDeng/AI-Crypto-Security-Reviewer/issues) · [Request Feature](https://github.com/hnuDeng/AI-Crypto-Security-Reviewer/issues)

</div>

---

## 📖 Table of Contents

- [About The Project](#about-the-project)
  - [Core Problem](#core-problem)
  - [Architecture](#architecture)
- [✨ Features](#-features)
- [🚀 Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [💻 Usage](#-usage)
  - [Command Line Interface (CLI)](#command-line-interface-cli)
  - [Python API](#python-api)
- [📊 Report Formats](#-report-formats)
- [🛠️ Tests](#️-tests)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 💡 About The Project

### Core Problem

The project combines pattern-based checks and optional external tools to flag selected security issues in source code. It proposes rule-based patches and reports available validation results. Detection and patching are heuristic: findings may contain false positives or omissions, and suggested changes require review and project-specific tests.

### Architecture

The system uses three software components (Analyzer ➡️ Coder ➡️ Tester). The built-in pipeline does not call a language model; crypto-related debug messages are fixed text, not mathematical proofs.

**Pipeline Flow:**
1. 🔍 **Analyzer Agent**: Scans code using pattern-based static analysis, cryptographic verification, memory safety analysis, and external tools (`cppcheck`, `flake8`, `bandit`).
2. ✍️ **Coder Agent**: Proposes patches or warning comments using rule-based templates.
3. 🧪 **Tester Agent**: Validates patches via syntax execution, sandbox execution, and regression testing.
4. 📄 **Output**: Detailed Review Report (JSON / SARIF).

Patch validation writes to a temporary copy of the selected directory or file. Target-relative paths and absolute paths inside that target map to the copy; parent traversal and paths outside the target are rejected. Python syntax checks read the patched copy, and single-file reviews run commands from the copy's temporary directory.

The sandbox provides a temporary filesystem copy, not operating-system, process, or network isolation. Test commands execute with the current user's host permissions. Only run tests from codebases you trust, or use a separately restricted environment for untrusted code.

---

## ✨ Features

- 🐍 **Python**: Rules for `eval`, `exec`, hardcoded secrets, weak crypto, SQL injection patterns, and more.
- ⚙️ **C/C++**: Rules for unbounded copies, format strings, allocation patterns, and more.
- 🔐 **Cryptography**: Pattern checks for selected weak algorithms, key sizes, randomness, and timing risks.
- 🛡️ **Memory Safety**: Heuristic checks for selected allocation, pointer and copy patterns.
- 🔄 **Fix Re-scan**: The `ValidationAgent` re-runs supported rules against proposed changes and flags ambiguous cases as unverified (can be disabled via `skip_fix_verification=True`).

---

## 🚀 Getting Started

### Prerequisites

- **Python**: `3.10` or higher
- Git

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/hnuDeng/AI-Crypto-Security-Reviewer.git
   cd AI-Crypto-Security-Reviewer
   ```

2. Install the package:
   ```bash
   # Basic installation
   pip install -e .
   
   # With development tools
   pip install -e ".[dev]"
   
   # With optional analysis tools
   pip install -e ".[dev,tools]"
   ```

---

## 💻 Usage

### Command Line Interface (CLI)

Run the reviewer directly from your terminal:

```bash
# Review a single file
ai-crypto-reviewer path/to/file.py

# Review a project with specific settings
ai-crypto-reviewer path/to/project/ --language python --min-severity high --verbose

# Run analysis only (no patching)
ai-crypto-reviewer path/to/project/ --no-patch

# Alternative module execution
python -m ai_crypto_reviewer path/to/project/
```

### Python API

Integrate the reviewer into your own Python scripts:

```python
from ai_crypto_reviewer.config import PipelineConfig
from ai_crypto_reviewer.orchestrator import SecurityReviewPipeline

# Configure the pipeline
config = PipelineConfig(
    target_path="path/to/code", 
    language="python", 
    min_severity="medium"
)

# Initialize and run
pipeline = SecurityReviewPipeline(config)
report = pipeline.run()

# Save the report
pipeline.save_report(report, "output/report.json")
```

---

## 📊 Report Formats

The pipeline supports two standard report formats for easy integration:

- **JSON** (Default): Full structured report (`review_report.json`).
- **SARIF v2.1.0**: Industry standard for CI/CD integration like GitHub Code Scanning or Azure DevOps (`review_report.sarif`).

JSON and SARIF report each proposed patch as `fix` or `warning` and include individual validation results. The overall validation, patch application, sandbox test-suite, and fix re-scan statuses distinguish `passed`, `failed`, and `not_run`; a syntax check alone does not imply the sandbox suite ran. A rule re-scan can confirm only that the supported detector no longer finds the mapped issue. Unsupported rules, ambiguous changes, warning-only patches, invalid Python, or patches that could not be applied are reported as unverified. Re-scanning is not a proof of security or semantic correctness.

When multiple patches target the same file, non-overlapping changes from the same original version are combined in the temporary copy before testing. Overlapping changes and stale source versions are rejected instead of silently overwriting one another. SARIF recommendations are informational properties, not machine-applicable fixes.

To save as SARIF via API:
```python
pipeline.save_sarif_report(report, 'output/report.sarif')
```

---

## 🛠️ Tests

### Offline rule regression

With the existing project dependencies installed, run the built-in, hand-written Python and C examples without an API key or external analysis tools:

```bash
python -m ai_crypto_reviewer.offline_evaluation
```

The JSON output reports expected and detected results for each rule-level example and counts matches, false positives, and false negatives. These eight synthetic examples are a functional regression check, not an estimate of real-world detection accuracy. They do not execute the sample source code.

From a virtual environment, install the development dependencies and run the test suite:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

GitHub Actions runs the same suite on Ubuntu and Windows with Python 3.10 and 3.12 for pushes and pull requests. The regression tests cover absolute patch paths, relative CLI targets, rejected paths outside the target, single-file targets, filenames containing quotes, and invalid syntax in patched copies. They also verify that the original source files remain unchanged.

To run only the patch-validation regression tests:

```bash
python -m pytest -q tests/test_sandbox.py tests/test_agents.py
```

---

## 🤝 Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
