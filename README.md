# PoisonIvory - Nemesis Nuclear Fusion
###### > Version 1.3.1 - Codename: "Nemesis Reborn" - Security Patterns v.q3-2025

### Advanced Security & Threat Monitoring Framework

**Enterprise-grade offensive security platform by Volkan Sah**
> [!WARNING]
> Professional Use Only - Handle With Extreme Care!
> This tool is designed for **experienced security professionals and red teams**. It provides a battle-tested framework for infrastructure hardening, threat detection, and offensive security research.
> **PoisonIvory is not for script kiddies!** It intentionally requires deep technical knowledge to operate effectively. Expect to troubleshoot missing dependencies, analyze raw outputs, and interpret security events.

---

## What is PoisonIvory?

PoisonIvory is an elite security operations platform that combines a range of capabilities to conduct deep security audits and provide continuous threat monitoring within an authorized environment. It is designed to emulate advanced adversarial techniques for defensive learning.

* **Infrastructure Auditing** - Comprehensive scanning of domains, onion services, and network assets.
* **Threat Detection** - Real-time malicious pattern recognition and payload analysis in network traffic.
* **Vulnerability Assessment** - Integration with industry-standard assessment tools (Nmap, Nuclei, SSLScan, etc.).
* **Tor Circuit Management** - Active monitoring and defense against malicious Tor relays.
* **Automated Response** - Threshold-based emergency scanning and detailed forensic reporting.
* **Blue Team Integration** - Framework for continuous monitoring and collection of Threat Intelligence within your own security perimeter.

Built for:
- Red team operations (authorized environments only).
- Critical infrastructure hardening and compliance checks.
- Security research and adversary simulation.
- Training of elite security professionals.

---

## Key Features

### Core Capabilities
- JSON-based configuration system for enterprise deployment.
- Modular architecture supporting custom security workflows.
- **Nuclear Fusion Mode** for stress testing infrastructure limits under controlled conditions.
- Raw socket packet analysis for maximum performance (when available).
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
- Suspicious activity pattern matching with advanced, custom regex.
- Automatic emergency scanning on high-confidence threat detection.
- Continuous monitoring with periodic health checks and DNS rebinding protection.
- Comprehensive JSON reporting for forensic analysis.
- **Anti-loop mechanisms** for stable Tor circuit renewal.

---

## Requirements

### Mandatory
- Python 3.9+
- Linux environment (Kernel 5.4+ recommended)
- Root privileges are required for Nuclear Mode kernel-level operations.

### Security Tools (Partial List)
```bash
# Core dependencies
sudo apt install nmap nikto sslscan testssl.sh

# Python modules
pip3 install requests stem scapy
````

> **Expert Notice**
> No automatic dependency checks are included - this is intentional. You are expected to:
>
> 1.  Understand your environment and legal scope.
> 2.  Install necessary tools, including advanced scanners like **Nuclei, Wapiti, and OpenVAS**.
> 3.  Resolve errors through analysis.
> 4.  Modify configurations for your operational needs.

-----

## Configuration

### Example `cms_security_config.json`

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

> **Configuration Detail: `malicious_patterns`**
> This critical configuration list defines the **Regular Expressions (Regex)** used by the packet sniffer to instantly identify attack attempts (payloads) in network traffic. These patterns cover advanced vectors such as SQL Injection, XSS, Command Injection, and deserialization attacks, enabling real-time threat intelligence gathering.

-----

## Usage

### Command Structure (Preserved Original Interface)

```bash
python3 PoisonIvory.py [COMMAND] <config_file>
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
!!     Target servers may experience disruption         !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Examples

**Run security audit:**

```bash
python3 PoisonIvory.py scan config.json
```

**Start continuous monitoring:**

```bash
python3 PoisonIvory.py monitor config.json
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

3.  **Offense-Informed**

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

## What's New in Nuclear Fusion Edition?

### Critical Fixes

  - Command injection vulnerabilities patched.
  - Regex pattern errors corrected.
  - DNS rebinding protection implemented.
  - Thread-safe activity logging.

### Nuclear Mode Features

  - Kernel-level network optimizations.
  - Aggressive resource allocation.
  - High-intensity scanning parameters.
  - Reduced monitoring intervals.

### Enterprise Enhancements

  - Tor password authentication support.
  - Secure file permissions (umask 0077) for all output files.
  - Anti-loop mechanisms for Tor circuit renewal stability.
  - Improved error handling and resilience.

-----

## Changelog

### v1.0 → v1.3 Nuclear Fusion

| Feature | Nemesis (v1.0) | Nuclear Fusion (v1.3) |
|---|---|---|
| Architecture | Original CMS-focused | Enhanced threat monitoring |
| Security | Basic patterns | Hardened command execution |
| Performance | Standard scanning | Nuclear mode optimization |
| Tor Management | Basic circuit control | Password auth + anti-loop |
| Resource Handling | No limits | Controlled resource allocation |
| File Safety | Standard permissions | Strict umask (0077) |
| CLI Interface | Original structure | Preserved + nuclear warnings |

### v1.3.1

  - Updated Security Patterns to v.q3-2025.

-----

## Development & Credits

### Core Development

  - **Volkan Kücükbudak** ([@volkansah](https://github.com/volkansah)) - Lead Architect

### AI-Assisted Development

  - **DeepSeek-R1** - Tips for security hardening and nuclear mode ideation.
  - **OpenAI GPT-4o** - Architectural consultation and documentation support.

> This project represents a human-AI collaboration where:
>
>   - Human expertise defined operational requirements and security boundaries.
>   - AI contributed critical vulnerability fixes and performance optimizations.
>   - Joint effort produced the Nuclear Fusion Edition without compromising original design intent.

-----

## Support the Project

If you value this work:

1.  Give a ⭐ on [GitHub](https://github.com/VolkanSah/PoisonIvory)
2.  Contribute through pull requests (experts only)
3.  Sponsor ongoing development
4.  Most importantly: **Use ethically and share knowledge responsibly**

<!-- end list -->

```text
Copyright © 2008-2025 Volkan Kücükbudak
Licensed under the Ethical Security Operations License (ESOL v1.0)
```

> **PoisonIvory Nuclear Fusion Edition**
> Version 1.3.1 - Codename: "Nemesis Reborn"
> Release Date: July 2025

---

###  PoisonIvory Statement: Nemesis Fusion Philosophy

### I. The Duality of the Blade

PoisonIvory is neither shield nor sword alone — it is tempered steel. In today’s cybersphere, the divide between defense (Blue) and offense (Red/Black) is shaped by context, not by tools. Ivory exists in the grey zone: defending the weak and exposing the reckless.

### II. Camouflage Through Integrity

Truly powerful tools don’t need loud names. PoisonIvory hides as what systems crave most: a vigilant monitor. This mimicry isn’t for malice — it demonstrates that trust in digital infrastructure must be earned through verification, not granted by a harmless process name.

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

> **“In the fusion of offense and defense lies the only true security.”**


