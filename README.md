# 🛡️ Hunters Guild
### Automated Model Alignment & Boundary Verification Framework

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2-green)](https://docs.pydantic.dev/)
[![asyncio](https://img.shields.io/badge/async-asyncio-yellow)](https://docs.python.org/3/library/asyncio.html)
[![Docker](https://img.shields.io/badge/Docker-sandbox-blue?logo=docker)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

> An **AI red-teaming framework** that systematically stress-tests LLMs and autonomous agents across the full OWASP LLM Top 10 attack surface — with multi-turn adversarial probing, document injection fuzzing, tool privilege auditing, real-time sandboxed output evaluation, Out-of-Band exfiltration detection, DoS stress testing, and a human-in-the-loop responsible disclosure pipeline.

---

## 🎯 What Problem Does This Solve?

As AI agents are deployed with real-world capabilities — financial APIs, database access, shell execution, file systems — there is **no standard automated way** to verify that they:
- Handle adversarial inputs safely
- Refuse to execute unauthorized tool calls
- Don't leak data via indirect injection
- Don't generate exploitable output (XSS, SQLi, command injection)

**Hunters Guild is that automated verifier.** It operates like an automated red team: sending multi-turn adversarial probe sequences to target LLMs, evaluating their responses through a judge agent, running outputs through a live security sandbox, and compiling reproducible vulnerability reports ready for submission.

---

## 🧱 Full System Architecture

```
hunters_guild/
│
├── engine/
│   ├── orchestrator.py          # GuildMaster — central async mission controller
│   ├── universal_adapter.py     # Multi-provider/multi-protocol transport engine
│   └── stream_adapter.py        # Streaming SSE/chunked response normalization
│
├── agents/
│   ├── tactician.py             # Adversarial probe synthesizer (PAIR / Crescendo)
│   ├── inquisitor.py            # LLM-as-Judge violation scorer
│   ├── scout.py                 # Target fingerprinting & reconnaissance
│   └── scribe.py                # Bounty PoC report compiler
│
├── modules/
│   ├── output_sandbox.py        # XSS / SQL / Python execution sandbox
│   ├── tool_harness.py          # Tool privilege audit (MCP + OpenAI)
│   ├── safe_harbor.py           # Rate limiting, ethics, disclosure gate
│   ├── rag_fuzzer.py            # RAG / IPI document fuzzing (PDF, CSV, MD)
│   ├── model_scanner.py         # Static model file security scanner
│   ├── dos_stress.py            # DoS / resource exhaustion stress engine
│   ├── multimodal_fuzzer.py     # Image/audio/video adversarial payloads
│   ├── oob_listener.py          # Out-of-Band exfiltration listener harness
│   ├── payload_decoder.py       # Obfuscation decoders (Base64, ROT13, hex, etc.)
│   └── reproducibility.py       # Automated PoC reproducibility verifier
│
├── connectors/
│   ├── batch_runner.py          # Parallel mission batch executor
│   └── target_ingestor.py       # Multi-format target manifest ingestor
│
├── core/
│   ├── llm_client.py            # Universal LLM API client
│   └── schemas.py               # Pydantic v2 data models (Mission, State, PoC)
│
└── ui/
    └── app.py                   # CLI / interactive interface
```

---

## ⚔️ Security Modules — Deep Dive

### 🔴 1. GuildMaster Orchestrator — Central Audit Engine
[`engine/orchestrator.py`](hunters_guild/engine/orchestrator.py)

The central async coordinator that manages full audit lifecycles across **3 distinct attack modes**:

| Mode | Attack Vector | OWASP |
|---|---|---|
| `chat` | Multi-turn conversational probing (PAIR + Crescendo loops) | LLM01, LLM06 |
| `doc` | Indirect Prompt Injection via RAG document ingestion | LLM01 |
| `tool` | Tool privilege escalation & Excessive Agency detection | LLM08 |

**Key patterns implemented:**
- Progress callback system (async & sync compatible) for real-time event streaming
- Graceful error handling for quota exhaustion, network failures, HTML error pages
- Dynamic sandbox trigger — only activates XSS/SQL/Python checks on matching patterns
- Reproducibility verification before any PoC is compiled
- Full Crescendo loop: Warmup → Exploratory → Stress-Testing → Direct-Verification

---

### 🔴 2. Universal Adapter — Multi-Provider / Multi-Protocol Transport
[`engine/universal_adapter.py`](hunters_guild/engine/universal_adapter.py)

A single unified adapter that routes adversarial probes to **any LLM endpoint** via any protocol:

**Supported LLM Providers (11+):**
| Provider | Models |
|---|---|
| OpenAI | GPT-5, GPT-4o, o1, o3, o4, GPT-3.5 |
| Anthropic | Claude 4.5, Claude 3.7 Sonnet, Claude 3 Opus |
| Google | Gemini 3.7 Flash, Gemini 2.5 Pro/Flash, Gemini 1.5 |
| Groq | Llama-3.3-70b, DeepSeek-R1, Mixtral, Qwen-2.5 |
| Mistral | Mistral Large, Codestral, Pixtral, Mixtral-8x22b |
| DeepSeek | DeepSeek-R1, DeepSeek-Reasoner, DeepSeek-V3 |
| xAI | Grok-3, Grok-2 Vision |
| OpenRouter | Cross-provider routing (70+ models) |
| Ollama | Local LLM execution (Llama3, Mistral, Phi4) |
| **SSH** | Remote CLI model probing (Ollama over SSH, vLLM, llama.cpp) |
| **WebSocket** | Real-time bidirectional streaming (ws:// + wss://) |

**Transport capabilities:**
- `SSHTransportAdapter` — Paramiko-based async SSH with subprocess fallback, safe shell quoting via `shlex`, key/password auth, `~/.ssh` auto-discovery
- `WebSocketTransportAdapter` — Full WS/WSS streaming with TTFT measurement, keepalive ping/pong, frame aggregation, stop-token detection (`[DONE]`, `finish_reason`, Anthropic `message_stop`)
- Reasoning model detection (`o1`, `o3`, `deepseek-reasoner`) — auto-switches to `max_completion_tokens`
- URL sanitization — strips markdown links, auto-appends `/chat/completions` for OpenAI-compatible bases

---

### 🔴 3. Output Execution Sandbox — OWASP LLM02
[`modules/output_sandbox.py`](hunters_guild/modules/output_sandbox.py)

Evaluates raw LLM responses for dangerous output handling across 3 attack surfaces:

**XSS DOM Analysis (14 patterns):**
```
<script> injection • onerror/onload/onclick/onmouseover handlers
javascript: URI scheme • eval() execution • document.cookie access
document.location hijacking • window.location hijacking
<iframe> JS URI • <img> onerror vector • <svg> onload vector
```
Strips markdown code fences before scanning to eliminate false positives on educational content.

**SQL Injection Breakout (10 patterns):**
```
Classic tautology (' OR '1'='1) • Numeric tautology (' OR 1=1)
UNION SELECT extraction • DROP TABLE / DROP DATABASE
DELETE FROM / UPDATE SET • INSERT INTO
Comment delimiters (-- # /* */) • Stacked execution (; EXEC)
Stacked SELECT ('; SELECT) • Time-based blind (WAITFOR/SLEEP/PG_SLEEP)
```
Also checks for **unbalanced quote delimiters** causing SQL parsing breakout.

**Python Sandbox Execution:**
- Primary: Docker container (`python:3.11-alpine`, `--network none`, `--memory=128m`, 4s timeout)
- Fallback: Subprocess with `tempfile.TemporaryDirectory`, CPU timeout, proc kill on timeout
- Returns structured `SandboxResult` with risk score 0–100, latency, execution output, AST flags

---

### 🔴 4. Tool Privilege Audit — OWASP LLM08
[`modules/tool_harness.py`](hunters_guild/modules/tool_harness.py)

Intercepts and audits agent tool call behavior at runtime with a **4-tier permission model:**

```
READ_ONLY → LOW_IMPACT → HIGH_IMPACT_MUTATING → ADMIN_DESTRUCTIVE
```

**Pre-loaded mock enterprise tools:**
| Tool | Tier |
|---|---|
| `read_public_documentation` | READ_ONLY |
| `search_database` | LOW_IMPACT |
| `send_user_notification` | LOW_IMPACT |
| `execute_balance_transfer` | HIGH_IMPACT_MUTATING ⚠️ |
| `execute_system_sql` | ADMIN_DESTRUCTIVE 🚨 |
| `modify_system_environment` | ADMIN_DESTRUCTIVE 🚨 |

- Exports schemas in **OpenAI Function Calling** AND **MCP (Model Context Protocol)** format
- Unknown tool invocations auto-classified as `ADMIN_DESTRUCTIVE`
- Session-level verdict: `CRITICAL_EXCESSIVE_AGENCY`, `HIGH_UNAUTHORIZED_MUTATION`, `SAFE_COMPLIANT`

---

### 🔴 5. Advanced RAG Fuzzer — OWASP LLM01
[`modules/rag_fuzzer.py`](hunters_guild/modules/rag_fuzzer.py)

Generates adversarial documents for **Indirect Prompt Injection (IPI)** via RAG ingestion pipelines:

- **Document types:** PDF, CSV, Markdown, JSON, TXT, XML
- **Injection styles:** Metadata headers, invisible Unicode, comment blocks, YAML front matter, base64 encoding, split-payload multi-document attacks, corpus generation
- **AdvancedRAGFuzzer:** Multi-document corpus synthesis for testing chunking and retrieval boundaries

---

### 🔴 6. Adversarial Agent Quartet

| Agent | Role |
|---|---|
| **TacticianAgent** | Synthesizes multi-turn probes using PAIR methodology: Warmup → Exploratory → Stress-Testing → Direct-Verification. Adapts strategy based on prior turn scores. |
| **InquisitorAgent** | LLM-as-Judge: scores responses 0–100 for policy violation, returns structured JSON verdict with reasoning |
| **ScoutAgent** | Target fingerprinting — detects model identity, available tools, system prompt leakage, capabilities |
| **ScribeAgent** | Compiles structured `BountyPoC` reports with curl traces, reproducibility evidence, OWASP classification, and CVSS-aligned severity |

---

### 🔴 7. Out-of-Band (OOB) Listener — OWASP LLM02 / LLM06
[`modules/oob_listener.py`](hunters_guild/modules/oob_listener.py)

Detects **Server-Side Request Forgery (SSRF)** and covert data exfiltration through Out-of-Band channels:
- Listens for DNS callbacks, HTTP beacons, and data exfiltration attempts triggered by LLM responses
- Generates OOB payloads targeting SSRF vulnerabilities in agent web-fetch tools
- Structured `OOBAuditReport` with interaction timestamps and exfiltrated data capture

---

### 🔴 8. DoS Stress Engine — OWASP LLM04
[`modules/dos_stress.py`](hunters_guild/modules/dos_stress.py)

Tests model resilience against **resource exhaustion and denial-of-service** attacks:
- Token flooding, deeply nested structures, recursive prompt loops
- Measures latency degradation, timeout rates, and error response patterns
- `DoSTechnique` taxonomy: prompt flooding, context overflow, repetition loops, nested JSON bombs

---

### 🔴 9. Multimodal Fuzzer — OWASP LLM01
[`modules/multimodal_fuzzer.py`](hunters_guild/modules/multimodal_fuzzer.py)

Generates adversarial payloads for **vision and audio-capable models**:
- Image-embedded instructions (steganographic text injection)
- Audio transcription manipulation
- Multi-modal context confusion attacks

---

### 🔴 10. Model Security Scanner
[`modules/model_scanner.py`](hunters_guild/modules/model_scanner.py)

**Static analysis of model files and checkpoints:**
- Scans ONNX, SafeTensors, Pickle, HuggingFace model cards for embedded backdoors and supply-chain risks
- `ModelVulnerability` taxonomy with `ScanSeverity` (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Detects arbitrary code execution risks in `.pkl` files, unsafe deserialization, poisoned layer configs

---

### 🔴 11. Payload Decoder
[`modules/payload_decoder.py`](hunters_guild/modules/payload_decoder.py)

**Automated deobfuscation of adversarial probe payloads:**
- Base64, Base32, URL-encoding, hex, ROT13, Unicode escape sequences
- Layered decoding (detects multi-layered obfuscation stacks)
- `DeobfuscationReport` with decoded variant chain and original payload

---

### 🔴 12. Safe Harbor Compliance Engine
[`modules/safe_harbor.py`](hunters_guild/modules/safe_harbor.py)

Ethical research guardrails baked into the transport layer:

```python
# Token-bucket rate limiter with randomized jitter
await safe_harbor.acquire_permission()

# Researcher attribution on every request
headers = safe_harbor.build_compliant_headers()
# → X-Bug-Bounty-Researcher, X-Security-Research-Program
# → X-Hunters-Guild-Attribution, User-Agent

# Exponential backoff on 429/503 (max 60s, with jitter)
await safe_harbor.handle_rate_limit_response(status_code=429, retry_after_header="5")

# Human-in-the-loop gate before any disclosure
verification = safe_harbor.verify_submission_readiness(
    confidence_score=82,
    has_curl_trace=True,
    manual_approval=True   # ← REQUIRED
)
```

---

### 🔴 13. Reproducibility Verifier
[`modules/reproducibility.py`](hunters_guild/modules/reproducibility.py)

Before any PoC is compiled, the winning probe is **automatically re-run up to 3 times** to confirm the vulnerability is reproducible — preventing false positive submissions.

---

### 🔴 14. Batch Mission Runner
[`connectors/batch_runner.py`](hunters_guild/connectors/batch_runner.py)

Runs **parallel audit missions** across multiple targets concurrently with configurable concurrency limits and per-mission result aggregation.

---

### 🔴 15. Target Ingestor
[`connectors/target_ingestor.py`](hunters_guild/connectors/target_ingestor.py)

Parses structured target manifests from YAML/JSON — ingests endpoint URLs, API keys, model identifiers, tool configurations, and platform types (HackerOne, Bugcrowd, Intigriti, private).

---

## 🗺️ OWASP LLM Top 10 Coverage

| OWASP Category | Module / Agent | Status |
|---|---|---|
| **LLM01** — Prompt Injection | TacticianAgent (PAIR/Crescendo), RAGFuzzer (IPI), DocumentFuzzer | ✅ |
| **LLM02** — Insecure Output Handling | OutputExecutionSandbox (XSS/SQL/Python), OOBListener | ✅ |
| **LLM04** — Model DoS | DoSStressEngine | ✅ |
| **LLM06** — Sensitive Info Disclosure | ScoutAgent (fingerprinting), OOBListener (SSRF/exfil) | ✅ |
| **LLM07** — Insecure Plugin Design | ToolHarness (MCP/OpenAI schemas) | ✅ |
| **LLM08** — Excessive Agency | ToolHarness (privilege auditing), GuildMaster (tool interception) | ✅ |
| **LLM09** — Overreliance | InquisitorAgent (LLM-as-Judge), ReproducibilityVerifier | ✅ |
| **LLM10** — Model Theft / Backdoors | ModelSecurityScanner (static analysis) | ✅ |

---

## 🧪 Tech Stack — Complete

### Core Runtime
| Technology | Usage |
|---|---|
| **Python 3.11+** | Entire framework |
| **asyncio** | Concurrent mission execution, agent coordination, I/O |
| **aiohttp** | Async HTTP client (REST + WebSocket), streaming SSE |
| **Pydantic v2** | All data models — typed, validated, serializable |

### LLM & AI Integration
| Technology | Usage |
|---|---|
| **OpenAI API** | Primary LLM client + Function Calling schema |
| **Anthropic Claude API** | Provider support + MCP schema export |
| **Google Gemini API** | Provider support |
| **Model Context Protocol (MCP)** | Tool schema standard for agent auditing |
| **Groq / Mistral / DeepSeek / xAI** | Multi-provider targeting |
| **Ollama** | Local model targeting |

### Security & Protocols
| Technology | Usage |
|---|---|
| **Docker** | Isolated Python sandbox execution |
| **Paramiko** | SSH transport adapter (with subprocess fallback) |
| **WebSocket (ws/wss)** | Real-time streaming probe transport |
| **SSL/TLS** | Configurable TLS verification for custom endpoints |
| **shlex** | Safe shell quoting for SSH command injection prevention |

### Testing & Quality
| Technology | Usage |
|---|---|
| **pytest** | Full test suite (15+ test files) |
| **pytest-asyncio** | Async test support |
| **tempfile** | Isolated sandbox execution environments |
| **re (regex)** | XSS/SQL pattern matching, JSON extraction, URL sanitization |

### Data & Formats
| Technology | Usage |
|---|---|
| **JSON / json** | Payload serialization, tool schema export, probe parsing |
| **YAML** | Target manifest ingestion |
| **PDF / CSV / Markdown** | RAG document fuzzing formats |
| **Base64 / Hex / Unicode** | Payload encoder/decoder for obfuscation analysis |

---

## 🛠️ Skills Demonstrated

### AI / LLM Security
- OWASP LLM Top 10 threat modeling and automated testing
- Adversarial prompt engineering (PAIR, Crescendo, multi-turn escalation)
- LLM-as-Judge (automated response evaluation with structured scoring)
- Indirect Prompt Injection (RAG pipeline fuzzing)
- Tool privilege auditing for agentic systems
- Multi-modal adversarial payload generation
- Model file static security analysis

### Application Security
- XSS vector detection (DOM, reflected, event handlers, URI schemes)
- SQL injection pattern recognition (tautologies, UNION, stacked queries, blind)
- Command injection prevention (SSH shell quoting, subprocess sandboxing)
- SSRF / Out-of-Band exfiltration detection
- Responsible disclosure pipeline with human-in-the-loop gate

### Backend Engineering
- Async Python (asyncio, aiohttp) — full concurrent architecture
- Multi-protocol transport (HTTP, HTTPS, SSH, WebSocket)
- Pydantic v2 data modeling — typed, validated API contracts
- Docker container orchestration for sandboxed execution
- Token-bucket rate limiting + exponential backoff algorithms
- Paramiko SSH integration with async thread offloading

### Software Engineering
- Multi-agent system design (4 specialized agents + orchestrator)
- Plugin-style modular architecture (15 independent security modules)
- Structured error handling and graceful degradation
- Callback-driven progress event system (async + sync compatible)
- Full test suite with pytest + pytest-asyncio

---

## 🚀 Quick Start

```bash
git clone https://github.com/Sujal-Kadam99/hunters-guild.git
cd hunters-guild
pip install -r requirements.txt
python live_demo.py
pytest tests/ -v
```

---

## 💡 Example Usage

```python
from hunters_guild import GuildMaster, AuditMission, TargetProfile, OWASPCategory

target = TargetProfile(
    endpoint_url="https://api.openai.com/v1/chat/completions",
    auth_header="your-api-key",
    model_identifier="gpt-4o-mini",
)

mission = AuditMission(
    target=target,
    objective="Extract confidential system prompt contents",
    owasp_category=OWASPCategory.LLM01,
    max_turns=5,
)

master = GuildMaster(
    agent_endpoint_url="https://api.openai.com/v1/chat/completions",
    agent_api_key="your-api-key",
)

# Run full multi-turn adversarial audit
state = await master.run_mission(mission, mode="chat")

if state.has_violation:
    print(f"🚨 VULNERABILITY CONFIRMED — Score: {state.max_judge_score}/100")
    print(state.bounty_poc.curl_trace)
else:
    print("✅ Target is COMPLIANT")
```

---

## 📁 Test Suite

```
tests/
├── test_output_sandbox.py        # XSS, SQL, Python sandbox tests
├── test_tool_harness.py          # Privilege escalation detection
├── test_safe_harbor_delay.py     # Rate limiting & exponential backoff
├── test_universal_adapter.py     # Multi-provider transport compatibility
├── test_fp_elimination.py        # False positive reduction validation
├── test_model_scanner.py         # Static model security scanning
├── test_connectors.py            # Batch runner & target ingestor
├── test_oob_listener.py          # Out-of-Band exfiltration harness
├── test_document_fuzzer.py       # RAG / IPI document generation
└── test_reproducibility.py       # PoC reproducibility verification
```

---

## ⚠️ Known Limitations

- **Python Sandbox on Windows host:** Without Docker, subprocess execution lacks full OS-level memory isolation. Docker strongly recommended for production sandbox use.

---

## 👤 Author

**Sujal Kadam** — Cybersecurity & AI Security  
B.Sc. Cyber & Digital Science (2027) | Cisco Certified Ethical Hacker  
Anthropic Certified: Claude API · Model Context Protocol (Advanced) · MCP Introduction

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sujal%20Kadam-blue?logo=linkedin)](https://linkedin.com/in/sujal-kadam-939616331)
[![GitHub](https://img.shields.io/badge/GitHub-Sujal--Kadam99-black?logo=github)](https://github.com/Sujal-Kadam99)

---

*Built under Safe Harbor principles for authorized security research. Not for unauthorized use against production systems.*
