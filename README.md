
# PoisonIvory (NF1.3)
###### > Version 2.0.0(dev) - Codename: "Nemesis Reborn" + AI Feature
![ Security](ivory.jpg)

> [!NOTE]  
> Not testet, not finished! Working on the idea. 

### Advanced Security & Threat Monitoring Framework  

**Enterprise-grade offensive security platform by Volkan Sah**  
> [!WARNING]  
> Professional Use Only - Handle With Extreme Care!  
> This tool is designed for **experienced security professionals and red teams**. It provides a battle-tested framework for infrastructure hardening, threat detection, and offensive security research.  
> **PoisonIvory is not for script kiddies!** It intentionally requires deep technical knowledge to operate effectively. Expect to troubleshoot missing dependencies, analyze raw outputs, and interpret security events.  

---

## What is PoisonIvory?  

PoisonIvory is an elite security operations platform that combines:  

* **Infrastructure Auditing** - Comprehensive scanning of domains, onion services, and network assets  
* **Threat Detection** - Real-time malicious pattern recognition in network traffic  
* **Vulnerability Assessment** - Integration with industry tools (Nmap, Nuclei, SSLScan, etc.)  
* **Tor Warfare** - Circuit management and malicious relay detection  
* **Automated Response** - Threshold-based emergency scanning and reporting  

Built for:  
- Red team operations (authorized environments only)  
- Critical infrastructure hardening  
- Security research and adversary simulation  
- Training of elite security professionals  

---

## Key Features  

### Core Capabilities  
- JSON-based configuration system for enterprise deployment  
- Modular architecture supporting custom security workflows  
- **Nuclear Fusion Mode** for stress testing infrastructure limits  
- Raw socket packet analysis for maximum performance (when available)  
- Preserves original architecture while enhancing security and performance  

### Security Integrations  
| Tool          | Function                     |  
|---------------|------------------------------|  
| Nmap          | Aggressive port scanning     |  
| Nuclei        | Vulnerability detection      |  
| SSLScan       | TLS/SSL configuration audit  |  
| Tor Control   | Circuit management           |  
| Scapy/Raw     | Flexible packet monitoring   |  

### Advanced Operations  
- Suspicious activity pattern matching with custom regex  
- Automatic emergency scanning on threat detection  
- Continuous monitoring with periodic health checks  
- Comprehensive JSON reporting for forensic analysis  
- **Anti-loop mechanisms** for Tor circuit renewal  

---

## Requirements  

### Mandatory  
- Python 3.9+  
- Linux environment (Kernel 5.4+ recommended)  
- Root privileges for nuclear mode operations  

### Security Tools (Partial List)  
```bash
# Core dependencies
sudo apt install nmap nikto sslscan testssl.sh

# Python modules
pip3 install requests stem scapy
```

> **Expert Notice**  
> No automatic dependency checks are included - this is intentional. You are expected to:  
> 1. Understand your environment  
> 2. Install necessary tools  
> 3. Resolve errors through analysis  
> 4. Modify configurations for your operational needs  

---

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

> **Note**: The configuration now supports the `nuclear_mode` option for enabling high-intensity operations.

---

## Usage  

### Command Structure (Preserved Original Interface)  
```bash
python3 PoisonIvory.py [COMMAND] <config_file>
```

### Operations  
| Command       | Function                                  |  
|---------------|-------------------------------------------|  
| `scan`        | Run full security audit                   |  
| `monitor`     | Start continuous monitoring               |  
| `create-config`| Generate default configuration file      |  

### Nuclear Mode Activation  
Enable `nuclear_mode` in your configuration file for high-intensity operations. When enabled, PoisonIvory will:  
- Increase network buffer sizes (requires root)  
- Use aggressive scanning parameters (`-T5 --min-rate 5000`)  
- Allocate additional system resources  
- Reduce monitoring intervals  

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
python3 PoisonIvory.py scan config.json
```

**Start continuous monitoring:**  
```bash
python3 PoisonIvory.py monitor config.json
```

**Generate default configuration:**  
```bash
python3 PoisonIvory.py create-config
```

**Nuclear Mode Example (edit config first):**  
```json
{
  ...,
  "nuclear_mode": true
}
```

---

## Design Philosophy  

PoisonIvory embodies three core principles:  

1. **Expert-Centric**  
   - No GUIs, no hand-holding, no "easy mode"  
   - Raw terminal output and JSON reports only  
   - Errors are learning opportunities, not bugs to be automatically fixed  

2. **Original Architecture Preserved**  
   - Nuclear Fusion Edition maintains Volkan's original code structure  
   - Critical security fixes integrated without over-engineering  
   - Seamless upgrade path for existing users  

3. **Offense-Informed**  
   - Adversary-emulating techniques  
   - Threshold-based automatic countermeasures  
   - Tor circuit warfare capabilities with anti-loop protection  

---

## Legal & Ethical Notice  

- ⚖️ **Legal Compliance**: Use only on systems you own or have explicit written authorization to test  
- 🚫 **No Warranty**: This software is provided "as-is" without guarantees of any kind  
- 🔒 **Responsibility**: You are solely responsible for understanding local laws and ethical guidelines  
- ⛔ **Consequences**: Unauthorized scanning or traffic interception is illegal in most jurisdictions  

---

## What's New in Nuclear Fusion Edition?  

### Critical Fixes  
- Command injection vulnerabilities patched  
- Regex pattern errors corrected  
- DNS rebinding protection  
- Thread-safe activity logging  

### Nuclear Mode Features  
- Kernel-level network optimizations  
- Aggressive resource allocation  
- High-intensity scanning parameters  
- Reduced monitoring intervals  

### Enterprise Enhancements  
- Tor password authentication support  
- Secure file permissions (umask 0077)  
- Anti-loop mechanisms for Tor circuit renewal  
- Improved error handling and resilience  

---

## Changelog  

### v1.0 → v1.3 Nuclear Fusion  
| Feature                | Nemesis (v1.0)         | Nuclear Fusion (v1.3)       |  
|------------------------|------------------------|-----------------------------|  
| Architecture           | Original CMS-focused   | Enhanced threat monitoring  |  
| Security               | Basic patterns         | Hardened command execution  |  
| Performance            | Standard scanning      | Nuclear mode optimization   |  
| Tor Management         | Basic circuit control  | Password auth + anti-loop   |  
| Resource Handling      | No limits              | Controlled resource allocation |  
| File Safety            | Standard permissions   | Strict umask (0077)         |  
| CLI Interface          | Original structure     | Preserved + nuclear warnings |  

---

## Development & Credits  

### Core Development  
- **Volkan Kücükbudak** ([@volkansah](https://github.com/volkansah)) - Lead Architect  

### AI-Assisted Development  
- **DeepSeek-R1** - Tipps for Security hardening and nuclear mode idea 
- **OpenAI GPT-4o** - Architectural consultation and documentation  

> This project represents a human-AI collaboration where:  
> - Human expertise defined operational requirements and security boundaries  
> - AI contributed critical vulnerability fixes and performance optimizations  
> - Joint effort produced the Nuclear Fusion Edition without compromising original design intent  

---

## Support the Project  

If you value this work:  
1. Give a ⭐ on [GitHub](https://github.com/VolkanSah/PoisonIvory)  
2. Contribute through pull requests (experts only)  
3. Sponsor ongoing development  
4. Most importantly: **Use ethically and share knowledge responsibly**  

```text
Copyright © 2025 Volkan Kücükbudak
Licensed under the Ethical Security Operations License (ESOL v1.0) 😄 Ok GPL3
```

> **PoisonIvory Nuclear Fusion Edition**  
> Version 2.0.0 unstable - Codename: "Nemesis Reborn"  
> Release Date: 24/Aug 2025
