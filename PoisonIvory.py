
#!/usr/bin/env python3
"""
PoisonIvory 1.1
Integriertes Tool für umfassende Sicherheitsüberwachung.
Refaktoriert mit Fokus auf Stabilität, Effizienz und Sicherheit.
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
import ssl
import concurrent.futures
import logging
from collections import defaultdict
import re
import xml.etree.ElementTree as ET

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
        logging.FileHandler('poison_ivory.log'),
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
        self.tor_socks_port = config.get('tor_socks_port', 9050)
        self.wordlist_path = config.get('wordlist_path')
        self.output_dir = config.get('output_dir', 'security_reports')
        
        self.monitoring_active = False
        self.scan_results = {}
        self.suspicious_activity = defaultdict(int)
        self.alert_threshold = config.get('alert_threshold', 5)
        self.activity_lock = threading.Lock()

        self.malicious_patterns = [
            r'(?i)(abuse|child|illegal|hack|exploit|malware|ddos)',
            r'(?i)(admin|login|wp-admin|phpmyadmin|admin\.php)',
            r'(?i)(\.\./|\.\.\\|%2e%2e|%252e%252e)',
            r'(?i)(select\s.*from|union\s.*select|drop\s.*table|insert\s.*into|update\s.*set)',
            r'(?i)(<script|javascript:|vbscript:|onload=|onerror=)',
            r'(?i)(eval\(|base64_decode|exec\(|system\()',
            r'(?i)(password|passwd|secret|key|token)',
            r'(?i)(\b(wget|curl|netcat|nc|bash|sh|cmd|powershell|python|perl)\b|\|\||\&\&|\$\(|\`)',
            r'(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f|%252e%252e%252f|\~/|\.\.\\x2f)',
            r'(?i)(/etc/passwd|/proc/self|\.env|\.git/config|wp-config\.php|\.htaccess)',
            r'(?i)(https?://(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))|metadata\.google\.internal)',
            r'(?i)(redirect=|url=|next=|to=|dest=)(https?%3a%2f%2f|https?://)',
            r'(?i)(\r\n|\n|\r|\%0d|\%0a)(Set-Cookie|Location|Content-Length|:)',
            r'(?i)\.(php|exe|dll|js|jar|jsp)(\.|$|\?|\s)',
            r'(?i)(php://|file://|zip://|expect://|data:text|http://)',
        ]
        
        self.compiled_patterns = []
        for pattern in self.malicious_patterns:
            try:
                self.compiled_patterns.append((re.compile(pattern), pattern))
            except re.error as e:
                logger.warning(f"Invalid regex pattern skipped: {pattern} - {e}")

        self.malicious_relays = config.get('malicious_relays', [])
        os.makedirs(self.output_dir, exist_ok=True)
        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    def shutdown_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop_monitoring()
        sys.exit(0)

    def run_command(self, cmd, timeout=300):
        if not isinstance(cmd, list) or not cmd:
            return {'success': False, 'error': 'Invalid command format'}
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            return {'success': True, 'stdout': result.stdout, 'stderr': result.stderr, 'returncode': result.returncode}
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': f'Timeout after {timeout}s for command: {" ".join(cmd)}'}
        except FileNotFoundError:
            return {'success': False, 'error': f'Command not found: {cmd[0]}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ========== SECURITY SCANNER METHODS ==========
    def check_domain_reachable(self, target=None):
        target = target or self.domain
        logger.info(f"[*] Checking if {target} is reachable...")
        try:
            if target.endswith('.onion'):
                return self.check_onion_reachable(target)
            else:
                response = requests.get(f"https://{target}", timeout=15, allow_redirects=True)
                response.raise_for_status()
                return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Target nicht erreichbar: {e}")
            return False

    def check_onion_reachable(self, onion_address):
        if not TOR_AVAILABLE:
            logger.warning("Tor not available, skipping onion check")
            return False
        session = requests.Session()
        try:
            session.proxies = {'http': f'socks5h://127.0.0.1:{self.tor_socks_port}', 'https': f'socks5h://127.0.0.1:{self.tor_socks_port}'}
            response = session.get(f"http://{onion_address}", timeout=45)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"Onion check failed: {e}")
            return False
        finally:
            session.close()

    def comprehensive_port_scan(self, target=None):
        target = target or self.domain
        logger.info(f"[*] Comprehensive port scanning {target}...")
        port_results = {}
        cmd = ["nmap", "-sS", "-T4", "--top-ports=1000", "-oX", "-", target]
        result = self.run_command(cmd)
        if result['success'] and result['stdout']:
            port_results['nmap_standard'] = self._parse_nmap_xml(result['stdout'])
        self.scan_results['ports'] = port_results
        return port_results

    def _parse_nmap_xml(self, xml_output):
        try:
            root = ET.fromstring(xml_output)
            results = {'ports': [], 'services': {}}
            for port_elem in root.findall('.//port'):
                state = port_elem.find('state').get('state')
                if state == 'open':
                    port_id = port_elem.get('portid')
                    protocol = port_elem.get('protocol')
                    port_str = f"{port_id}/{protocol}"
                    results['ports'].append(port_str)
                    service_elem = port_elem.find('service')
                    if service_elem is not None:
                        service_name = service_elem.get('name', 'unknown')
                        product = service_elem.get('product', '')
                        version = service_elem.get('version', '')
                        results['services'][port_str] = f"{service_name} {product} {version}".strip()
            return results
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return {'error': 'XML parsing failed'}

    def comprehensive_web_scan(self, target=None):
        target = target or self.domain
        logger.info(f"[*] Comprehensive web scanning {target}...")
        web_results = {}
        cmd = ["nikto", "-h", f"https://{target}", "-Format", "json"]
        result = self.run_command(cmd, timeout=600)
        if result['success'] and result['stdout']:
            web_results['nikto'] = self._parse_nikto_json(result['stdout'])
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            cmd = ["gobuster", "dir", "-u", f"https://{target}", "-w", self.wordlist_path, "-t", "50"]
            result = self.run_command(cmd, timeout=400)
            if result['success']:
                web_results['gobuster'] = result['stdout']
        else:
            logger.warning("Wordlist for Gobuster not configured or found. Skipping directory scan.")
        cmd = ["whatweb", target, "-a", "3"]
        result = self.run_command(cmd)
        if result['success']:
            web_results['whatweb'] = result['stdout']
        self.scan_results['web'] = web_results
        return web_results

    def _parse_nikto_json(self, json_output):
        try:
            data = json.loads(json_output)
            return {'host': data.get('host'), 'ip': data.get('ip'), 'port': data.get('port'), 'vulnerabilities': [v for v in data.get('vulnerabilities', [])]}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Nikto JSON: {e}")
            return {'error': 'JSON parsing failed'}

    def comprehensive_ssl_scan(self, target=None):
        target = target or self.domain
        logger.info(f"[*] Comprehensive SSL scanning {target}...")
        ssl_results = {}
        cmd = ["sslscan", "--no-colour", target]
        result = self.run_command(cmd)
        if result['success']:
            ssl_results['sslscan'] = {'output': result['stdout'], 'weaknesses': self._parse_ssl_weaknesses(result['stdout'])}
        testssl_file = f"{self.output_dir}/testssl_{target}_{int(time.time())}.json"
        cmd = ["testssl.sh", "--jsonfile-pretty", testssl_file, target]
        result = self.run_command(cmd, timeout=600)
        if result['success']:
            ssl_results['testssl'] = {'output_file': testssl_file, 'summary': "Detailed results in JSON file"}
        try:
            ssl_labs_result = self._check_ssl_labs(target)
            if ssl_labs_result:
                ssl_results['ssl_labs'] = ssl_labs_result
        except Exception as e:
            logger.debug(f"SSL Labs check failed: {e}")
        self.scan_results['ssl'] = ssl_results
        return ssl_results

    def _parse_ssl_weaknesses(self, output):
        weaknesses = []
        weak_indicators = ['SSLv2', 'SSLv3', 'RC4', 'DES', 'MD5', 'NULL', 'EXPORT']
        for line in output.split('\n'):
            for indicator in weak_indicators:
                if indicator in line and ('Accepted' in line or 'Enabled' in line):
                    weaknesses.append(line.strip())
        return weaknesses

    def _check_ssl_labs(self, target):
        try:
            api_url = f"https://api.ssllabs.com/api/v3/analyze?host={target}&publish=off&all=done"
            response = requests.get(api_url, timeout=30)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"SSL Labs API error: {e}")
        return None

    def vulnerability_assessment(self, target=None):
        target = target or self.domain
        logger.info(f"[*] Vulnerability assessment for {target}...")
        vuln_results = {}
        nuclei_output = f"{self.output_dir}/nuclei_{target}_{int(time.time())}.json"
        cmd = ["nuclei", "-u", f"https://{target}", "-o", nuclei_output, "-json", "-severity", "high,critical"]
        result = self.run_command(cmd, timeout=900)
        if result['success']:
            vuln_results['nuclei'] = {'output_file': nuclei_output, 'summary': self._parse_nuclei_results(nuclei_output)}
        cmd = ["wapiti", "-u", f"https://{target}", "-f", "json", "-o", f"{self.output_dir}/wapiti_{target}"]
        result = self.run_command(cmd, timeout=1200)
        if result['success']:
            vuln_results['wapiti'] = "Check output directory for results"
        vuln_results['openvas'] = self._trigger_openvas_scan(target)
        self.scan_results['vulnerabilities'] = vuln_results
        return vuln_results

    def _parse_nuclei_results(self, output_file):
        try:
            with open(output_file, 'r') as f:
                lines = f.readlines()
            findings = [json.loads(line) for line in lines if line.strip()]
            return {'total_findings': len(findings), 'preview': findings[:5]}
        except Exception as e:
            logger.debug(f"Nuclei parsing error: {e}")
            return {}

    def _trigger_openvas_scan(self, target):
        logger.warning("OpenVAS integration is a placeholder and not functional.")
        logger.warning("A real implementation would require using the Greenbone Management Protocol (GMP) API.")
        return "OpenVAS scan not implemented."

    # ========== TOR MONITORING METHODS ==========
    def authenticate_tor_controller(self):
        if not TOR_AVAILABLE: return None
        try:
            controller = Controller.from_port(port=self.tor_control_port)
            controller.authenticate()
            return controller
        except Exception as e:
            logger.error(f"Tor authentication failed: {e}")
            return None

    def check_malicious_traffic(self, request_data):
        request_str = str(request_data).lower()
        for compiled_pattern, original_pattern in self.compiled_patterns:
            if compiled_pattern.search(request_str):
                return True, original_pattern
        return False, None

    def log_suspicious_activity(self, source_ip, pattern, request_data):
        timestamp = datetime.now().isoformat()
        activity_log = {'timestamp': timestamp, 'source_ip': source_ip, 'pattern_matched': pattern, 'request_data': str(request_data)[:500], 'target': self.domain or self.onion_address}
        activity_file = f"{self.output_dir}/suspicious_activity.jsonl"
        with open(activity_file, 'a') as f:
            f.write(json.dumps(activity_log) + '\n')
        with self.activity_lock:
            self.suspicious_activity[source_ip] += 1
            current_count = self.suspicious_activity[source_ip]
        logger.warning(f"Suspicious activity from {source_ip} (Count: {current_count}): Matched '{pattern}'")
        if current_count == self.alert_threshold:
            self.trigger_emergency_scan(source_ip)

    def trigger_emergency_scan(self, suspicious_ip):
        logger.critical(f"EMERGENCY SCAN TRIGGERED for {suspicious_ip}")
        threading.Thread(target=self.emergency_scan_worker, args=(suspicious_ip,), daemon=True).start()
        self.renew_tor_circuit()

    def emergency_scan_worker(self, target_ip):
        try:
            logger.info(f"Emergency scan starting for {target_ip}")
            cmd = ["nmap", "-sS", "-T5", "--top-ports=100", "-oX", "-", target_ip]
            result = self.run_command(cmd, timeout=120)
            if result['success']:
                timestamp = int(time.time())
                parsed_results = self._parse_nmap_xml(result['stdout'])
                emergency_report = {'timestamp': timestamp, 'target_ip': target_ip, 'scan_type': 'emergency', 'nmap_results': parsed_results}
                report_file = f"{self.output_dir}/emergency_scan_{target_ip}_{timestamp}.json"
                with open(report_file, 'w') as f:
                    json.dump(emergency_report, f, indent=2)
                logger.info(f"Emergency scan completed: {report_file}")
        except Exception as e:
            logger.error(f"Emergency scan failed: {e}")

    def renew_tor_circuit(self):
        controller = self.authenticate_tor_controller()
        if controller:
            try:
                controller.signal(Signal.NEWNYM)
                logger.info("Tor circuit renewed")
            except Exception as e:
                logger.error(f"Circuit renewal failed: {e}")
            finally:
                controller.close()

    def packet_handler(self, packet):
        if not SCAPY_AVAILABLE: return
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                is_malicious, pattern = self.check_malicious_traffic(payload)
                if is_malicious:
                    self.log_suspicious_activity(source_ip, pattern, payload)
            except Exception as e:
                logger.debug(f"Packet processing error: {e}")

    def monitor_traffic(self):
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, skipping traffic monitoring")
            return
        logger.info("Starting traffic monitoring...")
        try:
            sniff(filter="tcp and (port 80 or port 443 or port 9050 or port 9051)", prn=self.packet_handler, store=0, stop_filter=lambda p: not self.monitoring_active)
        except Exception as e:
            logger.error(f"Traffic monitoring error: {e}")

    # ========== MAIN CONTROL METHODS ==========
    def run_full_security_scan(self, target=None):
        target = target or self.domain or self.onion_address
        logger.info(f"Starting full security scan for {target}")
        if not self.check_domain_reachable(target):
            logger.error(f"Target {target} not reachable")
            return None
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
                    future.result()
                    logger.info(f"{scan_type} scan completed")
                except Exception as e:
                    logger.error(f"{scan_type} scan failed: {e}")
        return self.generate_comprehensive_report()

    def start_continuous_monitoring(self):
        logger.info("Starting continuous monitoring...")
        self.monitoring_active = True
        if SCAPY_AVAILABLE:
            traffic_thread = threading.Thread(target=self.monitor_traffic, daemon=True)
            traffic_thread.start()
        self.periodic_monitoring()

    def periodic_monitoring(self):
        scan_interval = self.config.get('scan_interval', 300)
        while self.monitoring_active:
            try:
                if self.domain and not self.check_domain_reachable(self.domain):
                    logger.warning(f"Domain {self.domain} health check failed")
                if self.onion_address and not self.check_onion_reachable(self.onion_address):
                    logger.warning(f"Onion {self.onion_address} health check failed")
                if self.suspicious_activity:
                    logger.info(f"Suspicious activity: {dict(self.suspicious_activity)}")
                if TOR_AVAILABLE and self.onion_address:
                    self.manage_tor_circuits()
                time.sleep(scan_interval)
            except Exception as e:
                logger.error(f"Periodic monitoring error: {e}")
                time.sleep(60)

    def manage_tor_circuits(self):
        controller = self.authenticate_tor_controller()
        if not controller: return
        try:
            for circuit in controller.get_circuits():
                if circuit.status == 'BUILT':
                    for hop in circuit.path:
                        if hop[0] in self.malicious_relays:
                            logger.warning(f"Malicious relay detected: {hop[0]}")
                            controller.close_circuit(circuit.id)
                            break
        except Exception as e:
            logger.error(f"Circuit management error: {e}")
        finally:
            controller.close()

    def stop_monitoring(self):
        logger.info("Stopping monitoring...")
        self.monitoring_active = False

    def generate_comprehensive_report(self):
        timestamp = datetime.now().isoformat()
        report = {
            'scan_info': {'timestamp': timestamp, 'domain': self.domain, 'onion_address': self.onion_address, 'scan_type': 'comprehensive'},
            'results': self.scan_results,
            'monitoring': {'suspicious_activity': dict(self.suspicious_activity), 'total_incidents': sum(self.suspicious_activity.values())},
            'summary': self._generate_executive_summary()
        }
        report_file = f"{self.output_dir}/comprehensive_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Comprehensive report saved: {report_file}")
        return report

    def _generate_executive_summary(self):
        summary = {'risk_level': 'LOW', 'critical_issues': [], 'recommendations': [], 'total_vulnerabilities': 0}
        # Risk assessment based on scan results
        if 'ports' in self.scan_results:
            ports_data = self.scan_results.get('ports', {})
            open_ports = ports_data.get('nmap_standard', {}).get('ports', [])
            if len(open_ports) > 20:
                summary['risk_level'] = 'HIGH'
                summary['critical_issues'].append(f"High number of open ports ({len(open_ports)})")
        if 'vulnerabilities' in self.scan_results:
            vuln_data = self.scan_results.get('vulnerabilities', {})
            nuclei_findings = vuln_data.get('nuclei', {}).get('summary', {}).get('total_findings', 0)
            if nuclei_findings > 0:
                summary['total_vulnerabilities'] += nuclei_findings
                summary['risk_level'] = 'MEDIUM'
                if nuclei_findings > 5:
                    summary['risk_level'] = 'CRITICAL'
                    summary['critical_issues'].append(f"Critical vulnerabilities found by Nuclei ({nuclei_findings})")
            nikto_vulns = self.scan_results.get('web', {}).get('nikto', {}).get('vulnerabilities', [])
            if len(nikto_vulns) > 10:
                summary['risk_level'] = 'HIGH'
                summary['critical_issues'].append(f"Numerous issues found by Nikto ({len(nikto_vulns)})")

        total_incidents = sum(self.suspicious_activity.values())
        if total_incidents > 20:
            summary['risk_level'] = 'HIGH'
            summary['critical_issues'].append(f"High number of suspicious activities detected ({total_incidents})")
        if summary['critical_issues']:
            summary['recommendations'].extend(["Immediate review of critical issues", "Harden firewall rules", "Activate continuous monitoring", "Ensure regular security updates"])
        return summary

def load_config(config_file):
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
    config = {
        "domain": "example.com",
        "onion_address": "",
        "tor_control_port": 9051,
        "tor_socks_port": 9050,
        "wordlist_path": "/usr/share/wordlists/dirb/common.txt",
        "output_dir": "security_reports",
        "alert_threshold": 5,
        "malicious_relays": [],
        "scan_interval": 3600
    }
    with open('poison_ivory_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    print("Default config created: poison_ivory_config.json")
    print("Please edit the configuration file before running the scanner.")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 poison_ivory.py scan <config_file>")
        print("  python3 poison_ivory.py monitor <config_file>")
        print("  python3 poison_ivory.py create-config")
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
    
    monitor = CMSSecurityMonitor(config)
    
    try:
        if command == "scan":
            report = monitor.run_full_security_scan()
            if report:
                print(f"\nScan completed. Report saved to: {monitor.output_dir}")
                summary = report['summary']
                print(f"Risk Level: {summary['risk_level']}")
                print(f"Critical Issues: {len(summary['critical_issues'])}")
                print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        elif command == "monitor":
            monitor.start_continuous_monitoring()
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
        monitor.stop_monitoring()
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()

