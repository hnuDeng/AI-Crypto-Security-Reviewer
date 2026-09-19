<div align="center">

# 🛡️ AI-Crypto-Security-Reviewer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**An advanced, multi-agent code review and auto-remediation system optimized for deep logical vulnerabilities in C++ and Python codebases, with a specialized focus on cryptographic implementations.**

[Report Bug](https://github.com/yourusername/AI-Crypto-Security-Reviewer/issues) · [Request Feature](https://github.com/yourusername/AI-Crypto-Security-Reviewer/issues)

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

Traditional static analysis tools often fail to understand complex business logic, especially in algorithmic implementations and cryptographic engines (e.g., custom RSA implementations, primality testing algorithms). This project introduces an automated multi-agent pipeline capable of identifying memory management issues, algorithmic inefficiencies, and security flaws, generating verified patches.

### Architecture

The system uses a **three-agent pipeline** (Analyzer ➡️ Coder ➡️ Tester) with Chain-of-Thought reasoning before modifying any cryptographic logic.

**Pipeline Flow:**
1. 🔍 **Analyzer Agent**: Scans code using pattern-based static analysis, cryptographic verification, memory safety analysis, and external tools (`cppcheck`, `flake8`, `bandit`).
2. ✍️ **Coder Agent**: Generates patches using rule-based fix templates with Chain-of-Thought reasoning for crypto changes.
3. 🧪 **Tester Agent**: Validates patches via syntax execution, sandbox execution, and regression testing.
4. 📄 **Output**: Detailed Review Report (JSON / SARIF).

---

## ✨ Features (47 Detection Rules)

- 🐍 **Python (20 rules)**: `eval`, `exec`, hardcoded secrets, weak crypto, SQL injection, etc.
- ⚙️ **C/C++ (12 rules)**: Buffer overflows, format strings, memory leaks, etc.
- 🔐 **Cryptography (8 rules)**: Weak algorithms, key sizes, static IVs, timing attacks, etc.
- 🛡️ **Memory Safety (7 rules)**: Use-after-free, NULL dereference, unbounded copies, etc.
- 🔄 **Fix Verification**: The `ValidationAgent` automatically re-scans patched files to confirm original findings are resolved (can be disabled via `skip_fix_verification=True`).

---

## 🚀 Getting Started

### Prerequisites

- **Python**: `3.10` or higher
- Git

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/AI-Crypto-Security-Reviewer.git
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

To save as SARIF via API:
```python
pipeline.save_sarif_report(report, 'output/report.sarif')
```

---

## 🛠️ Tests

Run the test suite to ensure everything is working correctly:

```bash
python -m pytest tests/ -v
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
