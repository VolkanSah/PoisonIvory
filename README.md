# PoisonIvory - Nemesis//NF

###### > Version 1.4.0 - beta - Codename: "Nemesis Reborn" - Security Patterns v.2026
![PoisonIvory](ivory.jpg)
> Dual License: ESOL v1.0 + GPLv3

### Advanced Security & Threat Monitoring (DIY)

> [!WARNING]
> Professional Use Only - Handle With Extreme Care!
> This tool is designed for **experienced security professionals and red/blue teams**. It provides a battle-tested (mini)framework for infrastructure hardening, threat detection, and offensive security research.
> **PoisonIvory is not for script kiddies!** It intentionally requires deep technical knowledge to operate effectively. Expect to troubleshoot missing dependencies, analyze raw outputs, and interpret security events.


## What is PoisonIvory?

PoisonIvory is an elite security operations (micro) framework/boilerplate that combines a range of capabilities to conduct deep security audits and provide continuous threat monitoring within an authorized environment. It is designed to emulate advanced adversarial techniques for for defensive learning and expansion according to ypur own needs.

* **Infrastructure Auditing** - Comprehensive scanning of domains, onion services, and network assets.
* **AI-Era Threat Detection** - Real-time detection of LLM prompt injection, AI agent hijacking, quantum harvesting attacks.
* **Vulnerability Assessment** - Integration with industry-standard assessment tools (Nmap, Nuclei, SSLScan, etc.).
* **Tor Circuit Management** - Active monitoring and defense against malicious Tor relays.
* **Automated Response** - Threshold-based emergency scanning and detailed forensic reporting.
* **Blue Team Integration** - Framework for continuous monitoring and collection of Threat Intelligence within your own security perimeter.

Built for:
- Red/Blue team operations (authorized environments only).
- Critical infrastructure hardening and compliance checks.
- Security research and adversary simulation in the AI/Quantum era.
- Training of elite security professionals.


## Key Features

### Core Capabilities
- JSON-based configuration system for enterprise deployment.
- Modular architecture supporting custom security workflows.
- **Nuclear Fusion Mode** for stress testing infrastructure limits under controlled conditions.
- **SecurityPatterns2026 Class** with 150+ patterns for modern threats.
- **Risk Scoring System** - Automatic CRITICAL/HIGH/MEDIUM/LOW classification.
- Preserves original architecture while enhancing security and performance.

### Security Integrations
| Tool | Function |
|---|---|
| Nmap | Aggressive port scanning and service enumeration. |
| Nuclei | Fast and customizable vulnerability detection based on templates. |
| SSLScan | Detailed audit of TLS/SSL configurations and protocol weaknesses. |
| Tor Control | Circuit management and automated renewal for testing isolation. |
| Scapy/Raw | Flexible, low-level packet monitoring and payload analysis. |
| **OpenVAS** | Support for external, comprehensive vulnerability assessment via API (if configured). |

### Advanced Operations
- **2026 Threat Patterns** - LLM injection, AI agent attacks, quantum harvesting, container escape.
- Automatic emergency scanning on high-confidence threat detection.
- Continuous monitoring with periodic health checks and DNS rebinding protection.
- Comprehensive JSON reporting for forensic analysis.
- **Anti-loop mechanisms** for stable Tor circuit renewal.

---

## Requirements

### Mandatory
- Python 3.9+ (3.11+ recommended)
- Linux environment (Kernel 5.4+ recommended)
- Root privileges are required for Nuclear Mode kernel-level operations.

### Security Tools (Partial List)
```bash
# Minimum Core dependencies needed
nmap nikto sslscan testssl.sh

# Minimum Python modules needed
requests stem scapy ipaddress 
```

> **Expert Notice**
> No automatic dependency checks are included - this is intentional. You are expected to:
>
> 1.  Understand your environment and legal scope.
> 2.  Install necessary tools, including advanced scanners like **Nuclei, Wapiti, and OpenVAS**.
> 3.  Resolve errors through analysis.
> 4.  Modify configurations for your operational needs.


## Configuration

### Minimum Example `cms_security_config.json`

```json
{
  "domain": "yourdomain.com",
  "onion_address": "youronionaddress.onion",
  "tor_control_port": 9051,
  "tor_password": "your_tor_password",
  "output_dir": "security_reports",
  "alert_threshold": 5,
  "malicious_relays": ["ABCD1234EFGH5678", "IJKL91011MNOP1213"],
  "malicious_patterns": ["(?i)(malware|exploit|ransomware)", "(?i)(wp-admin|phpmyadmin)"],
  "nuclear_mode": false
}
```

> **Configuration Note: SecurityPatterns2026**
> The 2026 patterns are **hardcoded** in the `SecurityPatterns2026` class and include AI/LLM threats, quantum attacks, container escape vectors, and modern supply chain attacks. No configuration needed for these advanced patterns.

-----

## Usage

### Command Structure (Preserved Original Interface)

```bash
PoisonIvory.py [COMMAND] <config_file>
```

### Operations

| Command | Function |
|---|---|
| `scan` | Run full security audit (port scanning and vulnerability assessment). |
| `monitor` | Start continuous monitoring of network traffic and system health. |
| `create-config`| Generate default configuration file. |

### Nuclear Mode Activation

Enable `nuclear_mode` in your configuration file for high-intensity operations. When enabled, PoisonIvory will:

  - Increase network buffer sizes (requires root).
  - Use aggressive scanning parameters (`-T5 --min-rate 5000`).
  - Allocate additional system resources.
  - Reduce monitoring intervals.

Example warning at startup:

```text
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! NUCLEAR MODE ACTIVATED - EXPECT SYSTEM INSTABILITY !!
!!    Target servers may experience disruption       !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Examples

**Run security audit:**

```bash
PoisonIvory.py scan config.json
```

**Start continuous monitoring:**

```bash
PoisonIvory.py monitor config.json
```

-----

## Design Philosophy

PoisonIvory embodies three core principles:

1.  **Expert-Centric**

      - No GUIs, no hand-holding, no "easy mode".
      - Raw terminal output and JSON reports only.
      - Errors are learning opportunities, not bugs to be automatically fixed.

2.  **Original Architecture Preserved**

      - Nuclear Fusion Edition maintains Volkan's original code structure.
      - Critical security fixes integrated without over-engineering.
      - Seamless upgrade path for existing users.

3.  **Offense-Informed Defense**

      - Adversary-emulating techniques for robust defense development.
      - Threshold-based automatic countermeasures.
      - Tor circuit warfare capabilities with anti-loop protection.

-----

## Legal & Ethical Notice

  - ⚖️ **Legal Compliance**: This tool must **only** be used on systems you own or for which you have **explicit written authorization** (Scope of Work).
  - 🚫 **No Warranty**: This software is provided "as-is" without guarantees of any kind.
  - 🔒 **Responsibility**: You are solely responsible for understanding and complying with all local laws and ethical guidelines regarding security testing.
  - ⛔ **Consequences**: Unauthorized scanning, active exploitation, or **traffic interception (Packet Sniffing)** on systems you do not own is illegal and may lead to severe legal penalties.

-----

## What's New in Version 1.4.0 ?

### Critical Security Enhancements

  - **SecurityPatterns2026 Class** - Complete overhaul with 150+ modern patterns
  - **AI/LLM Threat Detection** - Prompt injection, agent hijacking, shadow AI
  - **Quantum-Era Security** - Post-quantum harvesting, weak PQC migration detection
  - **Container Security** - Escape vectors, Kubernetes API protection
  - **Risk Scoring System** - Automatic CRITICAL/HIGH/MEDIUM/LOW classification

### Nuclear Mode Improvements

  - Enhanced kernel-level network optimizations.
  - Better resource allocation and memory management.
  - Improved stability with proper error handling.

### Enterprise Fixes

  - **Command injection vulnerabilities** - All `shell=True` removed
  - **DNS rebinding protection** - Full SSRF mitigation implemented
  - **Thread-safe operations** - Locking for concurrent monitoring
  - **IP validation** - Proper `ipaddress` module usage


## Changelog (Updates)

### v1.3.1 → v1.4.0 

| Feature | v1.3.1 (2025) | v1.4.0 (2026) |
|---|---|---|
| Security Patterns | Basic SQLi/XSS/CMDi | 150+ AI/Quantum/Container patterns |
| Threat Detection | Traditional web attacks | + LLM injection, AI agent hijacking |
| Risk Assessment | Binary (malicious/clean) | 4-level scoring (CRITICAL→LOW) |
| Cryptography Focus | TLS/SSL weaknesses | + Post-quantum harvesting detection |
| Container Security | Limited | ext. Escape vectors, K8s API protection |
| Command Safety | Some shell=True usage | + All shell=False, proper sanitization |
| DNS Protection | Basic | ext. Full rebinding protection |

### New Threat Categories in 1.4.0
1. **AI/LLM Security** - Prompt injection, agent manipulation
2. **Quantum Cryptography** - Harvesting attacks, migration gaps
3. **Container & Cloud Native** - Escape vectors, K8s security
4. **Deepfake & Identity** - Synthetic fraud detection
5. **Supply Chain 2026** - AI-generated malicious packages


## Development & Credits

### Core Development

  - **Volkan Kücükbudak** ([@volkansah](https://github.com/volkansah)) - Lead Architect

### AI-Assisted Development 
  - **DeepSeek** - Help to write this README.md after 5 tries! WTF (DS was to lazy)
  - **Claude 4.5** - Architectural review and pattern validation after 12 tries!.

> This project represents a human-AI collaboration where:
>
>   - Human expertise defined operational requirements and security boundaries.


## Support the Project

If you value this work:

1.  Give a ⭐ on [GitHub](https://github.com/VolkanSah/PoisonIvory)
2.  Contribute through pull requests (experts only)
3.  Sponsor ongoing development
4.  Most importantly: **Use ethically and share knowledge responsibly**

<!-- end list -->

```text
Copyright © 2008-2026 Volkan Kücükbudak
Dual Licensed: ESOL v1.0 (Ethical) + GPLv3
```

> **PoisonIvory Nuclear Fusion Edition - Version 1.4.0**
> Codename: "Nemesis Reborn"  
> Release Date: December 25.12.2025
> Patterns Version: v.2026

---

###  PoisonIvory Statement: Nemesis Fusion Philosophy

### I. The Duality of the Blade

PoisonIvory is neither shield nor sword alone — it is tempered steel. In today's cybersphere, the divide between defense (Blue) and offense (Red/Black) is shaped by context, not by tools. Ivory exists in the grey zone: defending the weak and exposing the reckless.

### II. Camouflage Through Integrity

Truly powerful tools don't need loud names. PoisonIvory hides as what systems crave most: a vigilant monitor. This mimicry isn't for malice — it demonstrates that trust in digital infrastructure must be earned through verification, not granted by a harmless process name.

### III. The Nuclear Option: Controlled Escalation

When diplomacy fails and perimeters collapse, Ivory enters Nuclear Fusion mode.

* The kernel is tuned for transparency, not destruction.
* Speed is used to outrun the shadows.
* Anyone invoking this mode accepts full responsibility for the instability born from illuminating truth inside a compromised system.

### IV. Reflexive Autonomy (The Missing Piece)

Defense must move at the speed of light, not the speed of man. Ivory is designed to react reflexively—an automated immune response to digital pathogens. It does not wait for permission to survive; it scales its aggression based on the threat it observes.

### V. The Tor Paradox

We use anonymity to increase accountability. By rotating identities, Ivory evades automated tracking by the adversary, buying the human operator the most precious resource in a crisis: **Time.**

### VI. The Final Instance (Forensic Resistance)

A tool that sees everything must leave no trace that could be weaponized against the innocent. PoisonIvory is gas—filling the void, scanning every corner, and vanishing upon contact, taking its secrets to the grave.


> **"In the fusion of offense and defense lies the only true security."**

