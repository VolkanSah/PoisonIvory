
#!/usr/bin/env python3
"""
PoisonIvory 1.0
Integriertes Tool für umfassende Sicherheitsüberwachung
"""

import subprocess
import requests
import sys
import json
import time
import threading
import signal
import os
from datetime import datetime
import socket
import ssl
import concurrent.futures
import logging
from collections import defaultdict
import re

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
        self.output_dir = config.get('output_dir', 'security_reports')
        
        # Monitoring State
        self.monitoring_active = False
        self.scan_results = {}
        self.suspicious_activity = defaultdict(int)
        self.alert_threshold = config.get('alert_threshold', 5)
        
        # Security Patterns
        self.malicious_patterns = [
            r'(?i)(abuse|child|illegal|hack|exploit|malware|ddos)', # Keywords
            r'(?i)(admin|login|wp-admin|phpmyadmin|admin\.php)', # Admins
            r'(?i)(\.\.\/|\.\.\\|%2e%2e|%252e%252e)',  # Directory traversal
            r'(?i)(select|union|drop|insert|update|delete|script)',  # SQL injection
            r'(?i)(<script|javascript:|vbscript:|onload=|onerror=)',  # XSS
            r'(?i)(eval\(|base64_decode|exec\(|system\()',  # Code execution
            r'(?i)(password|passwd|secret|key|token)',  # Credential harvesting
                # Command Injection (OS-Kommandos)
            r'(?i)(\b(wget|curl|netcat|nc|bash|sh|cmd|powershell|python|perl)\b|\|\||\&\&|\$\(|\`)',
                # Path Traversal (erweitert)
            r'(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f|%252e%252e%252f|\~\/|\.\.\\x2f)',  # URL-kodierte Varianten
                # Sensible Dateien/Zugriffe
            r'(?i)(/etc/passwd|/proc/self|\.env|\.git/config|wp-config\.php|\.htaccess)',
                # SSRF (Server-Side Request Forgery)
            r'(?i)(https?://(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))|metadata\.google\.internal)',
                # Open Redirect
            r'(?i)(redirect=|url=|next=|to=|dest=)(https?%3a%2f%2f|https?://)', #  %3a%2f%2f = :// URL-kodiert
                # HTTP Header Injection
            r'(?i)(\r\n|\n|\r|\%0d|\%0a)(Set-Cookie|Location|Content-Length|:)',
                # File Upload-Bypass
            r'(?i)\.(php|exe|dll|js|jar|jsp)(\.|$|\?|\s)',  # Gefährliche Dateierweiterungen
                # LFI/RFI (Local/Remote File Include)
            r'(?i)(php://|file://|zip://|expect://|data:text|http://)',
        ]
        
        # Malicious Tor relays
        self.malicious_relays = config.get('malicious_relays', [])
        
        # Sicherstellen dass Output-Directory existiert
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Shutdown Handler
        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    def shutdown_handler(self, signum, frame):
        """Graceful shutdown"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop_monitoring()
        sys.exit(0)

    def run_command(self, cmd, timeout=300):
        """Führt Kommando aus mit verbesserter Fehlerbehandlung"""
        try:
            result = subprocess.run(
                cmd, 
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

    # ========== SECURITY SCANNER METHODS ==========
    
    def check_domain_reachable(self, target=None):
        """Prüft ob Domain/Onion erreichbar ist"""
        target = target or self.domain
        logger.info(f"[*] Checking if {target} is reachable...")
        
        try:
            if target.endswith('.onion'):
                # Onion-Service über Tor testen
                return self.check_onion_reachable(target)
            else:
                # Normale Domain
                socket.gethostbyname(target)
                response = requests.get(f"http://{target}", timeout=10)
                return response.status_code == 200
                
        except Exception as e:
            logger.error(f"Target nicht erreichbar: {e}")
            return False

    def check_onion_reachable(self, onion_address):
        """Prüft Onion-Service Erreichbarkeit"""
        if not TOR_AVAILABLE:
            logger.warning("Tor not available, skipping onion check")
            return False
            
        try:
            session = requests.Session()
            session.proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
            
            response = session.get(f"http://{onion_address}", timeout=30)
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Onion check failed: {e}")
            return False

    def comprehensive_port_scan(self, target=None):
        """Umfassender Port-Scan mit verschiedenen Techniken"""
        target = target or self.domain
        logger.info(f"[*] Comprehensive port scanning {target}...")
        
        port_results = {}
        
        # Standard Nmap Scan
        cmd = ["nmap", "-sS", "-T4", "-p-", "--top-ports=1000", target]
        result = self.run_command(cmd)
        if result['success']:
            port_results['nmap_standard'] = {
                'output': result['stdout'],
                'ports': self._parse_nmap_ports(result['stdout'])
            }
        
        # Aggressive Scan
        cmd = ["nmap", "-A", "-T4", "-p", "1-1000", target]
        result = self.run_command(cmd)
        if result['success']:
            port_results['nmap_aggressive'] = {
                'output': result['stdout'],
                'services': self._parse_nmap_services(result['stdout'])
            }
        
        # UDP Scan (Top Ports)
        cmd = ["nmap", "-sU", "-T4", "--top-ports=100", target]
        result = self.run_command(cmd, timeout=600)
        if result['success']:
            port_results['nmap_udp'] = {
                'output': result['stdout'],
                'udp_ports': self._parse_nmap_ports(result['stdout'])
            }
        
        self.scan_results['ports'] = port_results
        return port_results

    def _parse_nmap_ports(self, output):
        """Parst Nmap Port Output"""
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                if 'open' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ports.append(parts[0])
        return ports

    def _parse_nmap_services(self, output):
        """Parst Nmap Service Information"""
        services = {}
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    services[port] = service
        return services

    def comprehensive_web_scan(self, target=None):
        """Umfassender Web-Scan"""
        target = target or self.domain
        logger.info(f"[*] Comprehensive web scanning {target}...")
        
        web_results = {}
        
        # Nikto Scan
        cmd = ["nikto", "-h", f"http://{target}", "-Format", "txt"]
        result = self.run_command(cmd, timeout=600)
        if result['success']:
            web_results['nikto'] = {
                'output': result['stdout'],
                'vulns': self._parse_nikto_vulns(result['stdout'])
            }
        
        # Dirb/Dirbuster für Directory Discovery
        cmd = ["dirb", f"http://{target}", "-w"]
        result = self.run_command(cmd, timeout=400)
        if result['success']:
            web_results['dirb'] = result['stdout']
        
        # WhatWeb für Fingerprinting
        cmd = ["whatweb", target, "-a", "3"]
        result = self.run_command(cmd)
        if result['success']:
            web_results['whatweb'] = result['stdout']
        
        # Gobuster als Alternative zu Dirb
        cmd = ["gobuster", "dir", "-u", f"http://{target}", "-w", "/usr/share/wordlists/dirb/common.txt"]
        result = self.run_command(cmd, timeout=300)
        if result['success']:
            web_results['gobuster'] = result['stdout']
        
        self.scan_results['web'] = web_results
        return web_results

    def _parse_nikto_vulns(self, output):
        """Parst Nikto Vulnerabilities"""
        vulns = []
        for line in output.split('\n'):
            if '+ ' in line and ('OSVDB' in line or 'CVE' in line or 'Server:' in line):
                vulns.append(line.strip())
        return vulns

    def comprehensive_ssl_scan(self, target=None):
        """Umfassender SSL/TLS Scan"""
        target = target or self.domain
        logger.info(f"[*] Comprehensive SSL scanning {target}...")
        
        ssl_results = {}
        
        # SSLScan
        cmd = ["sslscan", "--no-colour", target]
        result = self.run_command(cmd)
        if result['success']:
            ssl_results['sslscan'] = {
                'output': result['stdout'],
                'weaknesses': self._parse_ssl_weaknesses(result['stdout'])
            }
        
        # Testssl.sh
        testssl_file = f"{self.output_dir}/testssl_{target}_{int(time.time())}.json"
        cmd = ["testssl.sh", "--jsonfile-pretty", testssl_file, target]
        result = self.run_command(cmd, timeout=600)
        if result['success']:
            ssl_results['testssl'] = {
                'output_file': testssl_file,
                'summary': "Detailed results in JSON file"
            }
        
        # SSL Labs API (falls verfügbar)
        try:
            ssl_labs_result = self._check_ssl_labs(target)
            if ssl_labs_result:
                ssl_results['ssl_labs'] = ssl_labs_result
        except Exception as e:
            logger.debug(f"SSL Labs check failed: {e}")
        
        self.scan_results['ssl'] = ssl_results
        return ssl_results

    def _parse_ssl_weaknesses(self, output):
        """Parst SSL Schwachstellen"""
        weaknesses = []
        weak_indicators = ['SSLv2', 'SSLv3', 'RC4', 'DES', 'MD5', 'NULL', 'EXPORT']
        
        for line in output.split('\n'):
            for indicator in weak_indicators:
                if indicator in line and ('Accepted' in line or 'Enabled' in line):
                    weaknesses.append(line.strip())
        return weaknesses

    def _check_ssl_labs(self, target):
        """SSL Labs API Check"""
        try:
            api_url = f"https://api.ssllabs.com/api/v3/analyze?host={target}&publish=off&all=done"
            response = requests.get(api_url, timeout=30)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"SSL Labs API error: {e}")
        return None

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

    # ========== TOR MONITORING METHODS ==========
    
    def authenticate_tor_controller(self):
        """Tor Controller Authentication"""
        if not TOR_AVAILABLE:
            return None
            
        try:
            controller = Controller.from_port(port=self.tor_control_port)
            controller.authenticate()
            return controller
        except Exception as e:
            logger.error(f"Tor authentication failed: {e}")
            return None

    def check_malicious_traffic(self, request_data):
        """Prüft Traffic auf malicious patterns"""
        request_str = str(request_data).lower()
        
        for pattern in self.malicious_patterns:
            if re.search(pattern, request_str):
                return True, pattern
        return False, None

    def log_suspicious_activity(self, source_ip, pattern, request_data):
        """Loggt verdächtige Aktivitäten"""
        timestamp = datetime.now().isoformat()
        
        activity_log = {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'pattern_matched': pattern,
            'request_data': str(request_data)[:500],
            'target': self.domain or self.onion_address
        }
        
        # In File loggen
        activity_file = f"{self.output_dir}/suspicious_activity.jsonl"
        with open(activity_file, 'a') as f:
            f.write(json.dumps(activity_log) + '\n')
        
        # Counter erhöhen
        self.suspicious_activity[source_ip] += 1
        
        logger.warning(f"Suspicious activity from {source_ip}: {pattern}")
        
        # Auto-Scan triggern wenn Threshold erreicht
        if self.suspicious_activity[source_ip] >= self.alert_threshold:
            self.trigger_emergency_scan(source_ip)

    def trigger_emergency_scan(self, suspicious_ip):
        """Triggert Emergency Security Scan"""
        logger.critical(f"EMERGENCY SCAN TRIGGERED for {suspicious_ip}")
        
        # Schneller Scan des verdächtigen IPs
        threading.Thread(
            target=self.emergency_scan_worker,
            args=(suspicious_ip,),
            daemon=True
        ).start()
        
        # Tor Circuit erneuern
        self.renew_tor_circuit()

    def emergency_scan_worker(self, target_ip):
        """Emergency Scanner Worker"""
        try:
            logger.info(f"Emergency scan starting for {target_ip}")
            
            # Schneller Nmap-Scan
            cmd = ["nmap", "-sS", "-T5", "--top-ports=100", target_ip]
            result = self.run_command(cmd, timeout=120)
            
            if result['success']:
                timestamp = int(time.time())
                emergency_report = {
                    'timestamp': timestamp,
                    'target_ip': target_ip,
                    'scan_type': 'emergency',
                    'nmap_results': result['stdout'],
                    'open_ports': self._parse_nmap_ports(result['stdout'])
                }
                
                # Report speichern
                report_file = f"{self.output_dir}/emergency_scan_{target_ip}_{timestamp}.json"
                with open(report_file, 'w') as f:
                    json.dump(emergency_report, f, indent=2)
                
                logger.info(f"Emergency scan completed: {report_file}")
                
        except Exception as e:
            logger.error(f"Emergency scan failed: {e}")

    def renew_tor_circuit(self):
        """Erneuert Tor Circuit"""
        controller = self.authenticate_tor_controller()
        if controller:
            try:
                controller.signal(Signal.NEWNYM)
                logger.info("Tor circuit renewed")
                controller.close()
            except Exception as e:
                logger.error(f"Circuit renewal failed: {e}")

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

    # ========== MAIN CONTROL METHODS ==========
    
    def run_full_security_scan(self, target=None):
        """Führt kompletten Security Scan aus"""
        target = target or self.domain or self.onion_address
        logger.info(f"Starting full security scan for {target}")
        
        if not self.check_domain_reachable(target):
            logger.error(f"Target {target} not reachable")
            return None
        
        # Alle Scans parallel ausführen
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.comprehensive_port_scan, target): 'ports',
                executor.submit(self.comprehensive_web_scan, target): 'web',
                executor.submit(self.comprehensive_ssl_scan, target): 'ssl',
                executor.submit(self.vulnerability_assessment, target): 'vulns'
            }
            
            for future in concurrent.futures.as_completed(futures):
                scan_type = futures[future]
                try:
                    result = future.result()
                    logger.info(f"{scan_type} scan completed")
                except Exception as e:
                    logger.error(f"{scan_type} scan failed: {e}")
        
        return self.generate_comprehensive_report()

    def start_continuous_monitoring(self):
        """Startet kontinuierliches Monitoring"""
        logger.info("Starting continuous monitoring...")
        self.monitoring_active = True
        
        # Traffic Monitoring in separatem Thread
        if SCAPY_AVAILABLE:
            traffic_thread = threading.Thread(target=self.monitor_traffic)
            traffic_thread.daemon = True
            traffic_thread.start()
        
        # Periodic Scans
        self.periodic_monitoring()

    def periodic_monitoring(self):
        """Periodische Monitoring-Checks"""
        while self.monitoring_active:
            try:
                # Health Check
                if self.domain:
                    healthy = self.check_domain_reachable(self.domain)
                    if not healthy:
                        logger.warning(f"Domain {self.domain} health check failed")
                
                if self.onion_address:
                    healthy = self.check_onion_reachable(self.onion_address)
                    if not healthy:
                        logger.warning(f"Onion {self.onion_address} health check failed")
                
                # Suspicious Activity Report
                if self.suspicious_activity:
                    logger.info(f"Suspicious activity: {dict(self.suspicious_activity)}")
                
                # Tor Circuit Management
                if TOR_AVAILABLE and self.onion_address:
                    self.manage_tor_circuits()
                
                # Warten bis nächster Check
                time.sleep(300)  # 5 Minuten
                
            except Exception as e:
                logger.error(f"Periodic monitoring error: {e}")
                time.sleep(60)

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

    def stop_monitoring(self):
        """Stoppt Monitoring"""
        logger.info("Stopping monitoring...")
        self.monitoring_active = False

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
    """Lädt Konfiguration aus JSON-File"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Config file {config_file} not found")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        return None

def create_default_config():
    """Erstellt Standard-Konfiguration"""
    config = {
        "domain": "example.com",
        "onion_address": "",
        "tor_control_port": 9051,
        "output_dir": "security_reports",
        "alert_threshold": 5,
        "malicious_relays": [],
        "monitoring_enabled": True,
        "scan_interval": 3600
    }
    
    with open('cms_security_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("Default config created: cms_security_config.json")
    print("Please edit the configuration file before running the scanner.")

def main():
    """Hauptfunktion"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 PoisonIvory.py scan <config_file>")
        print("  python3 PoisonIvory.pyy monitor <config_file>")
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
    
    # Monitor initialisieren
    monitor = CMSSecurityMonitor(config)
    
    try:
        if command == "scan":
            # Einmaliger Scan
            report = monitor.run_full_security_scan()
            if report:
                print(f"\nScan completed. Report saved to: {monitor.output_dir}")
                summary = report['summary']
                print(f"Risk Level: {summary['risk_level']}")
                print(f"Critical Issues: {len(summary['critical_issues'])}")
                print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        
        elif command == "monitor":
            # Kontinuierliches Monitoring
            monitor.start_continuous_monitoring()
            
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

