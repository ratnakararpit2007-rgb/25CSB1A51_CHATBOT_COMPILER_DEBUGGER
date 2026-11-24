# Agentic AI Multi-Language Compiler & Debugger (v3.0)

An Automated Program Repair (APR) teaching assistant and developer tool designed to securely diagnose and fix compilation errors, syntax errors, and runtime bugs across multiple languages using localized agentic AI.

## Supported Programming Languages

The system implements a modular language-adapter architecture supporting:

1. **C++** (GCC / Clang, C++17, LLDB support)
2. **Python** (Python 3.x, py_compile, Traceback parsing)
3. **Java** (OpenJDK 17+, javac, JVM exception handling)
4. **C** (GCC / Clang, C11, memory safety diagnostics)
5. **JavaScript** (Node.js, V8 syntax checking, runtime diagnostics)

---

## Key Features

### 1. UI Redesign — Modern Clean White Theme
- **Theme:** Off-white canvas (`#f8fafc`), crisp white cards (`#ffffff`), subtle borders (`#e2e8f0`), restrained indigo/blue accents (`#2563eb`).
- **Developer Layout:** Inspired by modern IDEs (top navigation breadcrumbs, status pill badges, language selector, stats counters).
- **Code Editor:** 
  - Monospaced editor with line and character metrics.
  - Interactive **Syntax & Error Inspector** powered by Pygments, providing line numbers and pinpoint red error line highlighting (`hl_lines=[error_line]`).
  - Contextual error banners with root cause and pedagogical fix suggestions.
- **Dedicated Panels:**
  - 🖥️ Compiler & Execution Console (stdout, stderr, exit codes, latency)
  - 🧪 Test Suite Evaluation (configurable inputs and expected outputs, automated diff)
  - 🐞 AI Diagnosis & Multi-Bug Audit (root cause, bug cards with severity, file/line locations)
  - 🔄 Verified Fix & Code Diff (side-by-side original vs fix with one-click "Apply Fix to Editor")
  - 🛡️ Security Pre-Scan (banned function and credential leak detection)
  - 🤖 ReAct Reasoning Steps (step-by-step tool turns and observations)
  - 🌱 Carbon & Green Telemetry (energy consumed, carbon emissions via CodeCarbon)

### 2. Multi-Language Compiler & Debugger Architecture
- **Modular Adapters (`languages/`):**
  - `BaseLanguageAdapter`: Abstract interface for prerequisites, compilation, execution, error parsing, security scanning, templates, and test cases.
  - `CppAdapter`, `CAdapter`, `PythonAdapter`, `JavaAdapter`, `JavaScriptAdapter`: Separate language-specific implementations.
- **Dual AI Engine (Cloud & Local):**
  - **Google Gemini API:** Fast 1-2s cloud inference using `gemini-1.5-flash`, `gemini-2.0-flash`, or `gemini-1.5-pro`. Enter your key directly in the sidebar or set `GEMINI_API_KEY`.
  - **Local Ollama (Llama 3):** 100% offline, privacy-preserving local LLM execution.
- **Configurable Test Suite Evaluator:**
  - Define custom test cases with `stdin` and `expected_output`.
  - Automated comparison, whitespace normalization, and unified diff output.
- **Dual Execution Engine:**
  - **Docker Container Sandbox:** Hardened per-job container with dropped capabilities, read-only root, tmpfs `/tmp`, no network (`--network none`), memory limits, and timeout.
  - **Local Subprocess Sandbox:** Fallback isolated workspace runner with process timeouts and resource limits when Docker is offline.
- **Missing Runtime Detection:**
  - Proactively checks system PATH and functionality for compilers/interpreters (`gcc`, `g++`, `python3`, `node`, `javac`, `java`).
  - Surfaces clear, actionable installation instructions if a runtime is missing.

---

## Quick Start

### 1. Launch the Application
```bash
./run.sh
```
Or directly with Streamlit:
```bash
./.venv/bin/streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### 2. Running Automated Tests
Run the comprehensive test suite verifying all 5 language adapters, compilation, error classification, security scanning, and test evaluation:
```bash
./.venv/bin/python3 -m unittest discover -s tests
```

---

## Directory Structure

```
├── app.py                      # Modern clean-white Streamlit IDE
├── agent_core.py               # Multi-language ReAct agent orchestrator
├── compiler_service.py         # Multi-language compilation and test suite service
├── error_classifier.py         # Language-aware rule-based error classification
├── fix_engine.py               # Multi-language fix extraction & sandboxed verification
├── llm_client.py               # Ollama client with dynamic language prompts
├── sandbox_runner.py           # Dual execution engine (Docker container & local subprocess)
├── secure_scan.py              # Multi-language security pre-scan guardrail
├── test_runner.py              # Configurable test case evaluation & diff engine
├── languages/                  # Modular Language Adapter Architecture
│   ├── __init__.py             # Language registry & runtime scanners
│   ├── base.py                 # BaseLanguageAdapter abstract base class
│   ├── cpp_adapter.py          # C++ adapter
│   ├── c_adapter.py            # C adapter
│   ├── python_adapter.py       # Python adapter
│   ├── java_adapter.py         # Java adapter
│   └── javascript_adapter.py   # JavaScript adapter
├── tests/                      # Automated test suite
│   └── test_multi_language.py  # 22 comprehensive integration tests
├── Dockerfile                  # Multi-language sandbox container image
├── requirements.txt            # Python dependencies
└── run.sh                      # One-click launcher script
```
