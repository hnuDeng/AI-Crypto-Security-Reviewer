"""Package setup for AI Crypto Security Reviewer."""

from setuptools import setup, find_packages
from pathlib import Path

here = Path(__file__).parent
long_description = (here / "README.md").read_text(encoding="utf-8") if (here / "README.md").exists() else ""

setup(
    name="ai-crypto-security-reviewer",
    version="1.0.0",
    description="Multi-agent code review and auto-remediation system for cryptographic security",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="AI Crypto Security Team",
    url="https://github.com/hnuDeng/AI-Crypto-Security-Reviewer",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
        ],
        "tools": [
            "flake8>=6.0",
            "bandit>=1.7",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-crypto-reviewer=ai_crypto_reviewer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
    ],
)
