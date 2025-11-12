# PoisonIvory (NF 2.0)

> Version 2.0.0 (unstable) - Codename: "Nemesis Reborn" - PyFundaments Edition

> ⚠️ **Note:** This project is currently undergoing a major architectural overhaul (PyFundaments Edition) to achieve enterprise-grade modularity and security. Features are subject to change.



## Enterprise Security & Threat Orchestration Framework

**Elite Offensive Security Platform** by Volkan Sah

> ⚠️ **Warning:** Professional Use Only - Handle With Extreme Care!  
> This tool is designed for experienced security professionals and red teams. PoisonIvory is not for script kiddies! Expect to troubleshoot, analyze raw outputs, and interpret security events.

---

## Architectural Overhaul: PyFundaments Edition

PoisonIvory 2.0 is rebuilt using the **PyFundaments pattern**, ensuring maximum security, modularity, and testability. All external dependencies, configurations, and sensitive keys are decoupled from the core logic via **Dependency Injection (DI).**



## Core Service Breakdown

| Module         | Purpose                                                                 | Criticality       |
|----------------|-------------------------------------------------------------------------|-----------------|
| EthicalGates   | Mandatory Pre-Scan Verification (ownership tokens/DNS check)           | Critical         |
| ToolManager    | External Tool Abstraction (Nmap, Nuclei, etc. via asyncio.subprocess)  | Mandatory        |
| KIConnector    | LLM & API Routing (Gemini, OpenRouter, exponential backoff, grounding)| Optional         |
| Core           | The Scan Engine orchestrating modules and generating reports            | Mandatory        |



## What is PoisonIvory?

PoisonIvory is an elite security operations platform combining:

- **Infrastructure Auditing:** Scan domains, onion services, and network assets.
- **Intelligent Augmentation (AI):** Contextual vulnerability research & reporting using LLMs.
- **Vulnerability Assessment:** Integration with tools like Nmap, Nuclei, SSLScan.
- **Regulated Scanning:** Enforced via EthicalGates.
- **Automated Response:** Threshold-based emergency scanning and reporting.

**Built for:**

- Red team operations (authorized environments only)
- Critical infrastructure hardening
- Security research and adversary simulation



## Key Features

### Core Capabilities

- PyFundaments Architecture with secure DI
- JSON-based configuration system
- Modular service architecture
- **Nuclear Fusion Mode** for stress testing infrastructure

### AI & Intelligence Augmentation

- **Ground-Truth Research:** LLMs with search grounding for latest CVEs & Zero-Days
- **Contextual Reporting:** Concise actionable summaries
- **Provider Agnostic:** KIConnector supports multiple LLM APIs

### Tool & Security Integrations

| Tool       | Function                           | Managed By  |
|------------|-----------------------------------|------------|
| Nmap       | Aggressive port & service scanning| ToolManager|
| Nuclei     | Vulnerability detection (templates)| ToolManager|
| SSLScan    | TLS/SSL configuration audit        | ToolManager|
| Tor Control| Circuit management & relay detection| Core/Legacy|

---

## Requirements

- **Python 3.9+**
- **Linux environment** (Kernel 5.4+ recommended)
- Tool binaries in PATH: Nmap, Nuclei, SSLScan
- **API Keys (Optional, for AI features):** GEMINI_API_KEY or similar

> ⚠️ No automatic dependency checks. You must understand your environment and install necessary tools manually.



## Configuration

### Example `cms_security_config.json`

```json
{
  "TARGET_DOMAIN": "yourdomain.com",
  "SCAN_SETTINGS": {
    "NMAP_ARGS": ["-sS", "-sV", "-p-"],
    "NUCLEAR_MODE_ENABLED": false
  },
  "REPORT_OUTPUT_PATH": "./reports"
}
````

### Fundaments (Sensitive, external)

```bash
GEMINI_API_KEY="AI-KEY-123456789"
OWNERSHIP_TOKEN="POI-VERIFY-7890"
TOOL_NMAP_PATH="/usr/local/bin/nmap"
```

---

## Usage

```bash
python3 main.py [COMMAND] <config_file>
```

**Commands:**

| Command       | Function                               |
| ------------- | -------------------------------------- |
| scan          | Run full security audit (EthicalGates) |
| monitor       | Start continuous monitoring            |
| create-config | Generate default configuration file    |

---

## Legal & Ethical Notice

- ⚖️ **Legal Compliance:** Test only systems you own or have authorization for
- 🚫 **No Warranty:** Provided "as-is"
- 🔒 **Responsibility:** You are solely responsible for ethical use

---

## Development & Credits

**Core Development:** Volkan Kücükbudak (@volkansah) - Lead Architect
**AI-Assisted Overhaul:** Gemini (Google) - Modular design & safe I/O handling

> Human expertise defined operational requirements; AI contributed enterprise-grade architecture.

---

## Support the Project

- ⭐ Star on GitHub
- 🛠 Contribute via pull requests (experts only)
- Use ethically & share knowledge responsibly

> © 2025 Volkan Kücükbudak
> Licensed under **Ethical Security Operations License (ESOL v1.0)** 😄 Ok GPL3
