
![ Security](ivory.jpg)

# PoisonIvory - Nemesis Version 1.0 
### CMS Security & Tor Monitoring Framework

**Advanced offensive security & monitoring tool by Volkan Sah**
> [!WARNING]
> Professional Use Only — Read Carefully!
> This tool is designed for **experienced security professionals** and researchers. It provides a modular framework for comprehensive security monitoring, CMS analysis, and Tor traffic observation.
> **PoisonIvory is not a beginner script!** It intentionally lacks automated dependency checks or full error handling to prevent misuse by unskilled users. Errors, missing components, or crashes are part of the intended learning curve.

[Nemesis Nuclear Fusion Version](https://github.com/VolkanSah/PoisonIvory/tree/Nemesis-Nuclear)



##  What is PoisonIvory?

PoisonIvory is a powerful, modular security tool that combines:

* Full CMS security scanning
* Comprehensive port, web, and SSL/TLS analysis
* Vulnerability assessment using tools like Nmap, Nuclei, Wapiti, OpenVAS
* Tor traffic monitoring and malicious relay detection
* Continuous suspicious activity logging
* Automated emergency scans on threshold events

It can be used for:
-  Offensive security research (authorized environments only)
-  Hardening your own infrastructure
-  Educational purposes for security experts


## Features

* CMS domain & onion address monitoring
* Modular port, web, SSL/TLS & vulnerability scanning
* Integration with industry tools: Nmap, Nikto, Dirb, Gobuster, WhatWeb, SSLScan, testssl.sh, Nuclei, Wapiti, OpenVAS
* Suspicious traffic detection via regex patterns
* Emergency scans on repeated incidents
* Tor circuit management and relay blacklist support
* Continuous monitoring mode with automated reporting


## Requirements

PoisonIvory depends on several external tools:

* Python 3.x
* `scapy` (optional, for packet sniffing)
* `stem` (optional, for Tor interaction)
* Nmap, Nikto, Dirb/Gobuster, WhatWeb, SSLScan, testssl.sh, Nuclei, Wapiti, OpenVAS

**Important:**
No automatic dependency check is included — this is intentional. You are expected to understand your environment, install necessary tools, and deal with errors appropriately.


##  Usage

1. Clone the repository
2. Run `python3 PoisonIvory.py create-config` to generate a default config (soon!)
3. Edit the configuration file to match your target
4. Run scans or start continuous monitoring:

   ```bash
   python3 PoisonIvory.py scan <config_file>  
   python3 PoisonIvory.py monitor <config_file>  
   ```

For detailed options and functionality, read the code — this tool is made for people who *actually read* code.


## Legal & Ethical Notice

* This tool must only be used in authorized environments (your own systems or with explicit permission)
* Unauthorized scanning or interception of traffic is **illegal** in most jurisdictions
* The author takes no responsibility for misuse, damage, or legal consequences
* You are responsible for understanding local laws and ethical guidelines


##  Design Philosophy

PoisonIvory intentionally exposes the user to errors if tools are missing or misconfigured.
This serves two purposes:

1. To prevent unskilled individuals from using the tool recklessly
2. To encourage real learning through troubleshooting and analysis

**If you don’t know how to handle a stack trace, you should not run this tool.**


## Why No GUI? No Installer? No Pretty Stats?

Because real-world security doesn’t work through clicky dashboards.
If you need colors and icons, you’re in the wrong place.
This tool is for terminal warriors who prefer raw output, log files, and clean reports.


##  Disclaimer

This software is provided **as-is**, without warranty or guarantees of any kind.
The author cannot be held responsible for any damage, legal trouble, or misuse.
**Use responsibly. Think before you scan. Learn before you execute.**


## ❤️ Support & Respect

If you appreciate this work:

* Give a ⭐ on [On this Repo (PoisonIvory)](https://github.com/VolkanSah/PoisonIvory)
* Consider sponsoring development
* Or just… stay ethical and sharp

## Copyright
[Volkan Kücükbudak](https://github.com/volkansah)

#### Note
This README.md was crafted with the help of OpenAI's GPT-4o — powered by AI, perfected by humans.
