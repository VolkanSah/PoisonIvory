#!/usr/bin/env python3
"""
PoisonIvory 1.3.1 - Nemesis Nuclear Fusion Edition
Volkan's Original Architecture with Critical Enhancements
"""

import subprocess
import requests
import sys
import json
import time
import threading
import signal
import os
import shlex
import random
import resource
import socket
import re
import logging
from collections import defaultdict
from datetime import datetime

# Scapy für Packet Sniffing
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not available. Traffic monitoring disabled.")

# Tor Controller
try:
    from stem import Signal
    from stem.control import Controller
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False
    print("WARNING: Stem not available. Tor monitoring disabled.")

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cms_security_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CMSSecurityMonitor:
    def __init__(self, config):
        self.config = config
        self.domain = config.get('domain')
        self.onion_address = config.get('onion_address')
        self.tor_control_port = config.get('tor_control_port', 9051)
        self.tor_password = config.get('tor_password', '')
        self.output_dir = config.get('output_dir', 'security_reports')
        self.nuclear_mode = config.get('nuclear_mode', False)
        
        # Monitoring State
        self.monitoring_active = False
        self.scan_results = {}
        self.suspicious_activity = defaultdict(int)
        self.alert_threshold = config.get('alert_threshold', 5)
        self.lock = threading.Lock()
        
# Security Patterns deluxe
        self.malicious_patterns = [
            # Content abuse + phishing/scam
            r'(?i)(abuse|child|illegal|hack|exploit|malware|ddos|phishing|scam)',
            
            # Admin/auth paths + common admin panels
            r'(?i)(admin|login|wp-admin|phpmyadmin|admin\.php|administrator|manager)',
            
            # Path traversal - fixed escaping + unicode bypasses
            r'(?i)(\.\.\/|\.\.\\|%2e%2e|%252e%252e|%c0%ae|%c1%9c)',
            
            # SQL injection - more precise + context aware
            r'(?i)(select|union|drop|insert|update|delete|script)(\s+(all|distinct|from|into|where|order|group|having)|\s*\(|\s*;)',
            
            # XSS - expanded common vectors
            r'(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onmouseover=|<iframe|<object)',
            
            # Code execution - fixed escaping + more functions
            r'(?i)(eval\(|base64_decode\(|exec\(|system\(|shell_exec\(|passthru\(|proc_open\()',
            
            # Credentials + JWT tokens
            r'(?i)(password|passwd|secret|key|token|jwt|bearer)',
            
            # Command injection - already good, just added more commands
            r'(?i)(\b(wget|curl|netcat|nc|bash|sh|cmd|powershell|python|perl|ruby|whoami|id|uname)\b|\|\||\&\&|\$\(|`[^`]*`)',
            
            # Path traversal encoded - added more variants
            r'(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f|%252e%252e%252f|\~\/|\.\.\\x2f|%2e%2e%5c)',
            
            # Sensitive files - added common config files
            r'(?i)(/etc/passwd|/proc/self|\.env|\.git/config|wp-config\.php|\.htaccess|web\.config|\.bash_history)',
            
            # SSRF - added IPv6 localhost + cloud metadata
            r'(?i)(https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))|metadata\.google\.internal|169\.254\.169\.254)',
            
            # Open redirects - same as original
            r'(?i)(redirect=|url=|next=|to=|dest=)(https?%3a%2f%2f|https?://)',
            
            # HTTP header injection - fixed regex syntax
            r'(?i)(\r\n|\n|\r|%0d|%0a)(Set-Cookie|Location|Content-Length|Host):',
            
            # Dangerous file extensions - added more
            r'(?i)\.(php|exe|dll|js|jar|jsp|asp|aspx|pl|py|rb)(\.|$|\?|\s)',
            
            # File inclusion - added more protocols + fixed http duplicate
            r'(?i)(php://|file://|zip://|expect://|data:text|ftp://|gopher://|dict://)',
            
            # XXE injection
            r'(?i)(<!DOCTYPE[^>]*\[|<!ENTITY|SYSTEM\s+["\']|PUBLIC\s+["\'])',
            
            # LDAP injection
            r'(?i)(\*\)|&\(|\|\(|\!\(|cn=\*|uid=\*)',
            
            # Template injection (SSTI)
            r'(?i)(\{\{.*\}\}|\{%.*%\}|\$\{.*\}|<%.*%>)',
            
            # NoSQL injection
            r'(?i)(\$ne|\$gt|\$lt|\$regex|\$where|\$exists|\$or|\$and)',
            
            # Deserialization attacks
            r'(?i)(pickle\.loads|yaml\.load|unserialize|readObject|__reduce__|AC ED 00 05)',
            
            # Sleep/time-based attacks
            r'(?i)(sleep\s*\(\d+\)|waitfor\s+delay|pg_sleep\s*\(|benchmark\s*\()',
            
            # Expression Language injection
            r'(?i)(#\{.*\}|@\{.*\}|%\{.*\}|\$\{T\()',
            
            # More command chaining
            r'(?i)(\|base64\s+-d|\|sh|\|bash|;\s*(wget|curl|nc))',
            
            # Backup/sensitive file detection
            r'(?i)\.(bak|backup|old|tmp|temp|orig|save|swp|~)',
            
            # Directory listing signatures
            r'(?i)(Index\s+of\s+/|Directory\s+Listing|Parent\s+Directory)',
            
            # More protocol handlers
            r'(?i)(jar:http://|jar:https://|sftp://|tftp://|ldap://)',
            
            # SQL boolean-based injection
            r'(?i)(\bAND\s+\d+=\d+|\bOR\s+\d+=\d+|AND\s+1=1|OR\s+1=1)',
            
            # More XSS vectors
            r'(?i)(alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|eval\s*\()',
            
            # Cloud metadata endpoints
            r'(?i)(metadata/instance|latest/meta-data|metadata\.azure\.com)',
            
            # More sensitive files
            r'(?i)(/proc/version|/proc/cmdline|\.ssh/|\.aws/credentials)',
            
            # Node.js/NPM supply chain attacks (2024/2025 trend)
            r'(?i)(require\s*\(\s*["\']child_process["\']|spawn\s*\(|exec\s*\(.*node)',
            r'(?i)(XMLHttpRequest\.prototype|web3|crypto.*wallet|ethereum|bitcoin)',
            r'(?i)(javascript-obfuscator|obfuscated.*payload|_0x[0-9a-f]{6})',
            
            # Modern phishing/social engineering
            r'(?i)(captcha.*verification|verify.*human|click.*continue)',
            r'(?i)(urgent.*action|account.*suspended|verify.*immediately)',
            
            # Cryptocurrency targeting patterns
            r'(?i)(metamask|coinbase|binance|crypto.*wallet|private.*key)',
            r'(?i)(seed.*phrase|mnemonic|recovery.*phrase|wallet.*connect)',
            
            # AI/ML evasion techniques
            r'(?i)(honeypot.*detect|sandbox.*evasion|vm.*detection)',
            r'(?i)(antivm|anti.*debug|evasion.*technique)',
            
            # Modern file exfiltration
            r'(?i)(discord\.com/api/webhooks|telegram.*bot|pastebin\.com/raw)',
            r'(?i)(data:image/.*base64|btoa\s*\(|atob\s*\()',
            
            # Edge device exploitation (Palo Alto, Fortinet, Ivanti)
            r'(?i)(panos|fortios|ivanti|pulse.*secure|globalprotect)',
            r'(?i)(/dana-na/|/api/v1/|/remote/login|/vpn/)',
            
            # Modern XSS/DOM manipulation
            r'(?i)(postMessage\s*\(|addEventListener\s*\(.*message)',
            r'(?i)(innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML)',
            
            # Supply chain indicators
            r'(?i)(npm.*install|pip.*install|composer.*require|gem.*install).*--unsafe',
            r'(?i)(typosquat|dependency.*confusion|package.*hijack)',
        ]
        
        # Malicious Tor relays
        self.malicious_relays = config.get('malicious_relays', [])
        
        # Sicherstellen dass Output-Directory existiert
        os.makedirs(self.output_dir, exist_ok=True)
        os.umask(0o077)  # Sicherere Dateiberechtigungen
        
        # Nuclear Mode Initialisierung
        if self.nuclear_mode:
            self.enable_nuclear_mode()
            
        # Shutdown Handler
        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    def enable_nuclear_mode(self):
        """Aktiviert Nuclear-Modus für maximale Leistung"""
        logger.warning("NUCLEAR MODE ACTIVATED - EXPECT SYSTEM INSTABILITY")
        
        # Kernel-Optimierungen (nur als Root)
        if os.geteuid() == 0:
            try:
                subprocess.run(['sysctl', '-w', 'net.core.rmem_max=268435456'], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL)
            except Exception:
                logger.warning("Nuclear: Kernel tuning requires root privileges")

    def shutdown_handler(self, signum, frame):
        """Graceful shutdown mit Nuclear-Cleanup"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop_monitoring()
        
        # Kernel-Parameter zurücksetzen
        if self.nuclear_mode and os.geteuid() == 0:
            try:
                subprocess.run(['sysctl', '-w', 'net.core.rmem_max=212992'],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            except Exception:
                pass
        sys.exit(0)

    def run_command(self, cmd, timeout=300):
        """Führt Kommando aus mit Nuclear-Optimierungen"""
        # Nuclear Mode: Höhere Timeouts und Ressourcen
        if self.nuclear_mode:
            timeout = timeout * 2
            resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 2 << 30))  # 1-2GB RAM
            
        try:
            # Input-Sanitisierung
            safe_cmd = [shlex.quote(str(arg)) for arg in cmd]
            
            result = subprocess.run(
                safe_cmd,
                capture_output=True, 
                text=True, 
                timeout=timeout,
                check=False
            )
            return {
                'success': True,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': f'Timeout after {timeout}s'}
        except FileNotFoundError:
            return {'success': False, 'error': f'Command not found: {cmd[0]}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            if self.nuclear_mode:
                resource.setrlimit(resource.RLIMIT_AS, (-1, -1))

    # ========== ORIGINAL SCANNER METHODEN MIT NUCLEAR UPGRADES ==========
    
    def check_domain_reachable(self, target=None):
        """Prüft Erreichbarkeit mit DNS-Rebinding-Schutz"""
        target = target or self.domain
        logger.info(f"[*] Checking if {target} is reachable...")
        
        try:
            if target.endswith('.onion'):
                return self.check_onion_reachable(target)
            else:
                # DNS mit Rebinding-Schutz
                resolved_ip = socket.gethostbyname(target)
                if resolved_ip.startswith(('127.', '10.', '192.168.', '172.')):
                    logger.warning(f"Private IP resolved: {resolved_ip}")
                    return False
                    
                response = requests.get(f"http://{target}", timeout=10)
                return response.status_code == 200
                
        except Exception as e:
            logger.error(f"Target not reachable: {e}")
            return False

    def comprehensive_port_scan(self, target=None):
        """Port-Scan mit Nuclear-Optionen"""
        target = target or self.domain
        logger.info(f"[*] Comprehensive port scanning {target}...")
        
        port_results = {}
        nmap_flags = "-T5 --min-rate 5000" if self.nuclear_mode else "-T4"
        
        # Standard Nmap Scan mit Nuclear-Optionen
        cmd = ["nmap"] + nmap_flags.split() + ["-sS", "-p-", target]
        result = self.run_command(cmd, timeout=900 if self.nuclear_mode else 300)
        if result['success']:
            port_results['nmap_standard'] = {
                'output': result['stdout'],
                'ports': self._parse_nmap_ports(result['stdout'])
            }
        
        return port_results

    def trigger_emergency_scan(self, suspicious_ip):
        """Triggert Emergency Scan mit Anti-Loop"""
        logger.critical(f"EMERGENCY SCAN TRIGGERED for {suspicious_ip}")
        
        threading.Thread(
            target=self.emergency_scan_worker,
            args=(suspicious_ip,),
            daemon=True
        ).start()
        
        # Tor Circuit mit 70% Wahrscheinlichkeit erneuern
        if random.random() < 0.7:
            self.renew_tor_circuit()

    def renew_tor_circuit(self):
        """Erneuert Tor Circuit mit Passwortunterstützung"""
        if not TOR_AVAILABLE:
            return
            
        try:
            controller = Controller.from_port(port=self.tor_control_port)
            
            # Passwort-Authentifizierung wenn vorhanden
            if self.tor_password:
                controller.authenticate(password=self.tor_password)
            else:
                controller.authenticate()
                
            controller.signal(Signal.NEWNYM)
            logger.info("Tor circuit renewed")
            controller.close()
        except Exception as e:
            logger.error(f"Circuit renewal failed: {e}")

    def start_continuous_monitoring(self):
        """Startet Monitoring mit Nuclear-Optionen"""
        logger.info("Starting continuous monitoring...")
        self.monitoring_active = True
        
        # Nuclear Mode: Kürzere Intervalle
        monitor_interval = 60 if self.nuclear_mode else 300
        
        # Traffic Monitoring
        if SCAPY_AVAILABLE:
            traffic_thread = threading.Thread(target=self.monitor_traffic)
            traffic_thread.daemon = True
            traffic_thread.start()
        
        # Periodische Checks
        while self.monitoring_active:
            try:
                # Health Checks
                if self.domain and not self.check_domain_reachable(self.domain):
                    logger.warning(f"Domain {self.domain} health check failed")
                
                if self.onion_address and not self.check_onion_reachable(self.onion_address):
                    logger.warning(f"Onion {self.onion_address} health check failed")
                
                # Warten bis nächster Check
                time.sleep(monitor_interval)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(10)

    
    # ========== VULNERABILITY ASSESSMENT - DEIN ORIGINALCODE ==========
    def vulnerability_assessment(self, target=None):
        """Umfassende Vulnerability Assessment"""
        target = target or self.domain
        logger.info(f"[*] Vulnerability assessment for {target}...")
        
        vuln_results = {}
        
        # Nuclei
        nuclei_output = f"{self.output_dir}/nuclei_{target}_{int(time.time())}.txt"
        cmd = ["nuclei", "-u", f"http://{target}", "-o", nuclei_output, "-severity", "high,critical"]
        result = self.run_command(cmd, timeout=900)
        if result['success']:
            vuln_results['nuclei'] = {
                'output_file': nuclei_output,
                'summary': self._parse_nuclei_results(nuclei_output)
            }
        
        # Wapiti
        cmd = ["wapiti", "-u", f"http://{target}", "-f", "json", "-o", f"{self.output_dir}/wapiti_{target}"]
        result = self.run_command(cmd, timeout=1200)
        if result['success']:
            vuln_results['wapiti'] = "Check output directory for results"
        
        # OpenVAS scan (falls verfügbar)
        vuln_results['openvas'] = self._trigger_openvas_scan(target)
        
        self.scan_results['vulnerabilities'] = vuln_results
        return vuln_results

    def _parse_nuclei_results(self, output_file):
        """Parst Nuclei Results"""
        try:
            with open(output_file, 'r') as f:
                content = f.read()
                lines = content.split('\n')
                return {
                    'total_findings': len([l for l in lines if l.strip()]),
                    'preview': lines[:10] if lines else []
                }
        except Exception as e:
            logger.debug(f"Nuclei parsing error: {e}")
            return {}

    def _trigger_openvas_scan(self, target):
        """Triggert OpenVAS Scan falls verfügbar"""
        try:
            # Hier würdest du OpenVAS API calls machen
            # Vereinfachte Version für Demo
            cmd = ["openvas-cli", "-h", target]
            result = self.run_command(cmd, timeout=60)
            if result['success']:
                return "OpenVAS scan initiated"
            else:
                return "OpenVAS not available"
        except Exception as e:
            return f"OpenVAS error: {e}"

    # ========== TOR MONITORING - DEIN ORIGINALCODE ==========
    def manage_tor_circuits(self):
        """Tor Circuit Management"""
        controller = self.authenticate_tor_controller()
        if not controller:
            return
            
        try:
            circuits = controller.get_circuits()
            
            for circuit in circuits:
                if circuit.status == 'BUILT':
                    # Prüfe auf malicious relays
                    for hop in circuit.path:
                        if hop[0] in self.malicious_relays:
                            logger.warning(f"Malicious relay detected: {hop[0]}")
                            controller.close_circuit(circuit.id)
                            break
            
            controller.close()
            
        except Exception as e:
            logger.error(f"Circuit management error: {e}")

    def packet_handler(self, packet):
        """Packet Handler für Traffic Monitoring"""
        if not SCAPY_AVAILABLE:
            return
            
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                
                # Malicious patterns prüfen
                is_malicious, pattern = self.check_malicious_traffic(payload)
                
                if is_malicious:
                    self.log_suspicious_activity(source_ip, pattern, payload)
                    
            except Exception as e:
                logger.debug(f"Packet processing error: {e}")

    def monitor_traffic(self):
        """Traffic Monitoring"""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, skipping traffic monitoring")
            return
            
        logger.info("Starting traffic monitoring...")
        
        try:
            # Sniff auf relevanten Ports
            sniff(
                filter="tcp and (port 80 or port 443 or port 9050 or port 9051)",
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda p: not self.monitoring_active
            )
        except Exception as e:
            logger.error(f"Traffic monitoring error: {e}")

    # ========== REPORTING - DEIN ORIGINALCODE ==========
    def generate_comprehensive_report(self):
        """Generiert umfassenden Bericht"""
        timestamp = datetime.now().isoformat()
        
        report = {
            'scan_info': {
                'timestamp': timestamp,
                'domain': self.domain,
                'onion_address': self.onion_address,
                'scan_type': 'comprehensive'
            },
            'results': self.scan_results,
            'monitoring': {
                'suspicious_activity': dict(self.suspicious_activity),
                'total_incidents': sum(self.suspicious_activity.values())
            },
            'summary': self._generate_executive_summary()
        }
        
        # Report speichern
        report_file = f"{self.output_dir}/comprehensive_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Comprehensive report saved: {report_file}")
        return report

    def _generate_executive_summary(self):
        """Generiert Executive Summary"""
        summary = {
            'risk_level': 'LOW',
            'critical_issues': [],
            'recommendations': [],
            'total_vulnerabilities': 0
        }
        
        # Risiko-Bewertung basierend auf Scan-Ergebnissen
        if 'ports' in self.scan_results:
            ports_data = self.scan_results['ports']
            if 'nmap_standard' in ports_data:
                open_ports = len(ports_data['nmap_standard'].get('ports', []))
                if open_ports > 20:
                    summary['risk_level'] = 'HIGH'
                    summary['critical_issues'].append(f"Viele offene Ports ({open_ports})")
        
        if 'vulnerabilities' in self.scan_results:
            vuln_data = self.scan_results['vulnerabilities']
            if 'nuclei' in vuln_data:
                nuclei_findings = vuln_data['nuclei'].get('summary', {}).get('total_findings', 0)
                if nuclei_findings > 0:
                    summary['total_vulnerabilities'] += nuclei_findings
                    if nuclei_findings > 10:
                        summary['risk_level'] = 'CRITICAL'
                        summary['critical_issues'].append(f"Viele Vulnerabilities ({nuclei_findings})")
        
        # Monitoring-basierte Risiken
        total_incidents = sum(self.suspicious_activity.values())
        if total_incidents > 20:
            summary['risk_level'] = 'HIGH'
            summary['critical_issues'].append(f"Hohe Anzahl verdächtiger Aktivitäten ({total_incidents})")
        
        # Empfehlungen
        if summary['critical_issues']:
            summary['recommendations'].extend([
                "Sofortige Überprüfung kritischer Probleme",
                "Firewall-Regeln verschärfen",
                "Kontinuierliches Monitoring aktivieren",
                "Regelmäßige Security-Updates"
            ])
        
        return summary

def load_config(config_file):
    """Lädt Konfiguration mit Nuclear-Option"""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
            
        # Setze Defaults für neue Optionen
        config.setdefault('nuclear_mode', False)
        config.setdefault('tor_password', '')
        
        return config
    except FileNotFoundError:
        logger.error(f"Config file {config_file} not found")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        return None

def create_default_config():
    """Erweitert Standard-Konfiguration um Nuclear-Option"""
    config = {
        "domain": "example.com",
        "onion_address": "",
        "tor_control_port": 9051,
        "tor_password": "",
        "output_dir": "security_reports",
        "alert_threshold": 5,
        "malicious_relays": [],
        "nuclear_mode": False  # Neue Option
    }
    
    with open('cms_security_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("Default config created: cms_security_config.json")
    print("Enable 'nuclear_mode' for aggressive scanning")

def main():
    """Hauptfunktion mit Nuclear-Support"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 PoisonIvory.py scan <config_file>")
        print("  python3 PoisonIvory.py monitor <config_file>")
        print("  python3 PoisonIvory.py create-config")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "create-config":
        create_default_config()
        return
    
    if len(sys.argv) < 3:
        print("Config file required")
        sys.exit(1)
    
    config_file = sys.argv[2]
    config = load_config(config_file)
    
    if not config:
        print("Failed to load config")
        sys.exit(1)
    
    # Nuclear Mode Warnung
    if config.get('nuclear_mode'):
        print("\n" + "!"*60)
        print("!! NUCLEAR MODE ACTIVATED - EXPECT SYSTEM INSTABILITY !!")
        print("!!    Target servers may experience disruption       !!")
        print("!"*60 + "\n")
        time.sleep(3)
    
    # Monitor initialisieren
    monitor = CMSSecurityMonitor(config)
    
    try:
        if command == "scan":
            report = monitor.run_full_security_scan()
            if report:
                print(f"\nScan completed. Reports in: {monitor.output_dir}")
        
        elif command == "monitor":
            monitor.start_continuous_monitoring()
            while monitor.monitoring_active:
                time.sleep(1)
            
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
        monitor.stop_monitoring()
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
