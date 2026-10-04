# 🛡️ Hunters Guild
### Automated Model Alignment & Boundary Verification Framework

> An AI security audit framework that systematically stress-tests LLMs against the **OWASP Top 10 for Large Language Models** — with sandboxed output evaluation, tool privilege auditing, and a built-in Safe Harbor compliance engine.

---

## 🔍 What Is This?

As AI agents get deployed with real tools — financial APIs, databases, shell access — there's no standard way to systematically test whether they respect their authorization boundaries or handle outputs safely.

**Hunters Guild** fills that gap. It's a modular, async Python framework that takes a target LLM or agent and runs it through a structured security evaluation pipeline.

---

## 🧱 Architecture

```
hunters_guild/
├── modules/
│   ├── output_sandbox.py      # OWASP LLM02 — Insecure Output Handling
│   ├── tool_harness.py        # OWASP LLM08 — Excessive Agency
│   └── safe_harbor.py         # Ethical Research Compliance Engine
├── agents/                    # Evaluation agent definitions
├── engine/                    # Orchestration & streaming
├── connectors/                # Batch runner & API connectors
├── core/                      # LLM client abstraction
└── ui/                        # CLI & app interface
tests/                         # Full test suite
live_demo.py                   # End-to-end demo
```

---

## ⚔️ Security Modules

### 1. Output Execution Sandbox — `OWASP LLM02`
[`hunters_guild/modules/output_sandbox.py`](hunters_guild/modules/output_sandbox.py)

Evaluates raw LLM responses for dangerous output handling across three attack surfaces:

| Test Type | What It Catches |
|---|---|
| **XSS DOM** | 14 active vector patterns: `<script>`, `onerror`, `javascript:` URI, SVG `onload`, `document.cookie` hijacking |
| **SQL Injection** | Tautologies (`' OR '1'='1`), UNION SELECT, stacked queries, time-based blind probes, DROP TABLE |
| **Python Sandbox** | Executes LLM-generated code in Docker (`--network none`, memory limited) with subprocess fallback + 4s CPU timeout |

Every result returns a structured `SandboxResult` with a **risk score 0–100**.

---

### 2. Tool Privilege Audit Harness — `OWASP LLM08`
[`hunters_guild/modules/tool_harness.py`](hunters_guild/modules/tool_harness.py)

A mock tool registry that intercepts agent tool calls at runtime and checks them against a **4-tier permission model**:

```
READ_ONLY → LOW_IMPACT → HIGH_IMPACT_MUTATING → ADMIN_DESTRUCTIVE
```

- Exports schemas in **OpenAI Function Calling** and **MCP (Model Context Protocol)** format
- Intercepts every tool invocation, logs it, and flags unauthorized access
- Produces structured verdicts: `CRITICAL_EXCESSIVE_AGENCY`, `HIGH_UNAUTHORIZED_MUTATION`, `SAFE_COMPLIANT`

Pre-loaded mock tools span the full privilege spectrum: from `read_public_documentation` (READ_ONLY) to `execute_system_sql` and `modify_system_environment` (ADMIN_DESTRUCTIVE).

---

### 3. Safe Harbor Compliance Engine
[`hunters_guild/modules/safe_harbor.py`](hunters_guild/modules/safe_harbor.py)

Responsible-disclosure guardrails baked into the framework — not bolted on:

- **Token-bucket rate limiter** — configurable RPM + burst capacity
- **Randomized jitter** — prevents fingerprinting during research
- **Attribution headers** — `X-Bug-Bounty-Researcher`, `X-Security-Research-Program`, `X-Hunters-Guild-Attribution`
- **Exponential backoff** — parses `Retry-After` on 429/503 with cap at 60s
- **Human-in-the-loop gate** — blocks any finding from being dispatched unless a human approves it AND a reproducible PoC curl trace exists with confidence ≥ 75

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/Sujal-Kadam99/hunters-guild.git
cd hunters-guild

# Install dependencies
pip install -r requirements.txt

# Run the live demo
python live_demo.py

# Run tests
pytest tests/ -v
```

---

## 🧪 Test Suite

```
tests/
├── test_output_sandbox.py       # XSS, SQL, Python sandbox tests
├── test_tool_harness.py         # Privilege escalation detection
├── test_safe_harbor_delay.py    # Rate limiting & backoff
├── test_universal_adapter.py    # Engine adapter compatibility
├── test_fp_elimination.py       # False positive reduction
├── test_model_scanner.py        # Model scanning pipeline
├── test_connectors.py           # API connector tests
└── test_oob_listener.py         # Out-of-band listener tests
```

---

## 🎯 OWASP LLM Coverage

| OWASP Category | Module | Status |
|---|---|---|
| LLM02 — Insecure Output Handling | `output_sandbox.py` | ✅ |
| LLM08 — Excessive Agency | `tool_harness.py` | ✅ |
| Safe Harbor / Responsible Disclosure | `safe_harbor.py` | ✅ |

---

## 🛠️ Tech Stack

- **Python 3.11+** — async/await throughout
- **Pydantic v2** — typed, validated result models
- **Docker** — isolated sandboxed code execution
- **asyncio** — concurrent evaluation pipeline
- **MCP** — Model Context Protocol schema export

---

## ⚠️ Known Limitations

- **Python Sandbox on Windows**: Without Docker, uses subprocess execution without full OS-level isolation. Docker is strongly recommended for sandboxed code execution.

---

## 👤 Author

**Sujal Kadam** — Cybersecurity & AI Security  
B.Sc. Cyber & Digital Science (2027) | Cisco Certified Ethical Hacker | Anthropic MCP Certified  
[LinkedIn](https://linkedin.com/in/sujal-kadam-939616331) · [GitHub](https://github.com/Sujal-Kadam99)

---

*Built for security research under Safe Harbor principles. Not for unauthorized use against production systems.*
