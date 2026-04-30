# AI-Crypto-Security-Reviewer

An advanced, multi-agent code review and auto-remediation system based on the [SWE-agent] framework, highly optimized for deep logical vulnerabilities in C++ and Python codebases.

## Core Problem Addressed
Traditional static analysis tools often fail to understand complex business logic, especially in algorithmic implementations and cryptographic engines (e.g., custom RSA implementations, primality testing algorithms). This project introduces an automated AI agent capable of long-chain reasoning to identify memory management issues, algorithmic inefficiencies, and security flaws, generating verified patches directly into the PR workflow.

## Architecture & Core Customizations
This project extends the robust Agent-Computer Interface (ACI) of SWE-agent with deep vertical optimizations for security auditing:

* **`sweagent/environment/swe_env.py` (Environment Injection):** Integrated security-specific static analyzers directly into the Docker sandbox. The agent can execute bash commands to run specific algorithm tests and parse the logs.
* **`sweagent/agent/agent.py` (Multi-Agent Orchestration):** Modified the standard event loop to support multi-agent collaboration (Analyzer -> Coder -> Tester). Optimized long-context memory management for tracking cross-file vulnerabilities.
* **`config/commands/security_aci.yaml` (Security-focused ACI):** Added specialized action commands tailored for cryptographic implementation reviews, ensuring the model uses Chain-of-Thought (CoT) before modifying any underlying mathematical logic.

## Status
Currently in the experimental phase. Heavy reliance on LLM long-context capabilities and multi-step reasoning generation.# AI-Crypto-Security-Reviewer
