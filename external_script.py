# These are an  example of basic functions you can implement. 


#!/usr/bin/env python3
import subprocess
import requests
import sys
import json
import time
from datetime import datetime
import socket
import ssl
import concurrent.futures
import logging

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityScanner:
    def __init__(self, domain, output_file=None):
        self.domain = domain
        self.output_file = output_file
        self.results = {}
        self.start_time = datetime.now()
        
    def run_command(self, cmd, timeout=300):
        """Führt Kommando aus mit Timeout und Fehlerbehandlung"""
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

    def check_domain_reachable(self):
        """Prüft ob Domain erreichbar ist"""
        logger.info(f"[*] Checking if {self.domain} is reachable...")
        try:
            socket.gethostbyname(self.domain)
            response = requests.get(f"http://{self.domain}", timeout=10)
            self.results['reachable'] = True
            return True
        except Exception as e:
            logger.error(f"Domain nicht erreichbar: {e}")
            self.results['reachable'] = False
            return False

    def check_open_ports(self):
        """Nmap Port-Scan"""
        logger.info("[*] Checking open ports with Nmap...")
        cmd = ["nmap", "-sS", "-T4", "-p-", "--top-ports=1000", self.domain]
        result = self.run_command(cmd)
        
        if result['success']:
            self.results['nmap'] = {
                'raw_output': result['stdout'],
                'open_ports': self._parse_nmap_ports(result['stdout'])
            }
            logger.info(f"Nmap scan completed")
        else:
            logger.error(f"Nmap failed: {result.get('error', 'Unknown error')}")
            self.results['nmap'] = {'error': result.get('error')}

    def _parse_nmap_ports(self, output):
        """Extrahiert offene Ports aus Nmap Output"""
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 2:
                    ports.append(parts[0])
        return ports

    def check_web_server(self):
        """Nikto Web-Server Scan"""
        logger.info("[*] Scanning web server with Nikto...")
        cmd = ["nikto", "-h", f"http://{self.domain}", "-Format", "txt"]
        result = self.run_command(cmd, timeout=600)
        
        if result['success']:
            self.results['nikto'] = {
                'raw_output': result['stdout'],
                'vulnerabilities': self._parse_nikto_vulns(result['stdout'])
            }
            logger.info("Nikto scan completed")
        else:
            logger.error(f"Nikto failed: {result.get('error', 'Unknown error')}")
            self.results['nikto'] = {'error': result.get('error')}

    def _parse_nikto_vulns(self, output):
        """Extrahiert Vulnerabilities aus Nikto Output"""
        vulns = []
        for line in output.split('\n'):
            if '+ ' in line and ('OSVDB' in line or 'CVE' in line):
                vulns.append(line.strip())
        return vulns

    def check_ssl(self):
        """SSL/TLS Konfiguration prüfen"""
        logger.info("[*] Checking SSL configuration...")
        
        # SSLScan
        cmd = ["sslscan", "--no-colour", self.domain]
        result = self.run_command(cmd)
        
        ssl_info = {}
        if result['success']:
            ssl_info['sslscan'] = result['stdout']
            ssl_info['weak_ciphers'] = self._parse_ssl_weaknesses(result['stdout'])
        else:
            ssl_info['sslscan_error'] = result.get('error')
        
        # Testssl.sh falls verfügbar
        cmd = ["testssl.sh", "--jsonfile-pretty", "/tmp/testssl.json", self.domain]
        result = self.run_command(cmd, timeout=600)
        
        if result['success']:
            ssl_info['testssl'] = "Check /tmp/testssl.json for detailed results"
        
        self.results['ssl'] = ssl_info

    def _parse_ssl_weaknesses(self, output):
        """Extrahiert SSL Schwachstellen"""
        weaknesses = []
        weak_indicators = ['SSLv2', 'SSLv3', 'RC4', 'DES', 'MD5', 'NULL']
        
        for line in output.split('\n'):
            for indicator in weak_indicators:
                if indicator in line and 'Accepted' in line:
                    weaknesses.append(line.strip())
        return weaknesses

    def check_dns_security(self):
        """DNS Security Tests"""
        logger.info("[*] Checking DNS security...")
        
        dns_results = {}
        
        # DNSRecon
        cmd = ["dnsrecon", "-d", self.domain, "-t", "std"]
        result = self.run_command(cmd)
        if result['success']:
            dns_results['dnsrecon'] = result['stdout']
        
        # Dig für wichtige Records
        for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
            cmd = ["dig", self.domain, record_type]
            result = self.run_command(cmd)
            if result['success']:
                dns_results[f'dig_{record_type}'] = result['stdout']
        
        self.results['dns'] = dns_results

    def check_vulnerabilities(self):
        """Vulnerability Assessment"""
        logger.info("[*] Checking vulnerabilities...")
        
        vuln_results = {}
        
        # Nuclei falls verfügbar
        cmd = ["nuclei", "-u", f"http://{self.domain}", "-o", "/tmp/nuclei_results.txt"]
        result = self.run_command(cmd, timeout=900)
        if result['success']:
            vuln_results['nuclei'] = "Check /tmp/nuclei_results.txt for results"
        
        # WhatWeb für Fingerprinting
        cmd = ["whatweb", self.domain]
        result = self.run_command(cmd)
        if result['success']:
            vuln_results['whatweb'] = result['stdout']
        
        self.results['vulnerabilities'] = vuln_results

    def generate_report(self):
        """Generiert Abschlussbericht"""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        report = {
            'scan_info': {
                'domain': self.domain,
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': str(duration),
                'scanner_version': '1.0'
            },
            'results': self.results,
            'summary': self._generate_summary()
        }
        
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {self.output_file}")
        
        return report

    def _generate_summary(self):
        """Generiert Zusammenfassung der Ergebnisse"""
        summary = {
            'total_issues': 0,
            'critical_issues': [],
            'recommendations': []
        }
        
        # Analyse der Ergebnisse
        if 'nmap' in self.results and 'open_ports' in self.results['nmap']:
            open_ports = len(self.results['nmap']['open_ports'])
            summary['open_ports_count'] = open_ports
            if open_ports > 10:
                summary['critical_issues'].append("Viele offene Ports gefunden")
        
        if 'ssl' in self.results and 'weak_ciphers' in self.results['ssl']:
            weak_ciphers = len(self.results['ssl']['weak_ciphers'])
            if weak_ciphers > 0:
                summary['critical_issues'].append(f"{weak_ciphers} schwache SSL-Cipher gefunden")
        
        if 'nikto' in self.results and 'vulnerabilities' in self.results['nikto']:
            vulns = len(self.results['nikto']['vulnerabilities'])
            if vulns > 0:
                summary['critical_issues'].append(f"{vulns} Web-Vulnerabilities gefunden")
        
        summary['total_issues'] = len(summary['critical_issues'])
        
        # Empfehlungen
        if summary['total_issues'] > 0:
            summary['recommendations'].extend([
                "Detaillierte Analyse der gefundenen Probleme",
                "Regelmäßige Security-Updates",
                "Firewall-Konfiguration überprüfen",
                "SSL/TLS-Konfiguration härten"
            ])
        
        return summary

    def run_all_checks(self):
        """Führt alle Sicherheitschecks aus"""
        logger.info(f"Starting security scan for {self.domain}")
        
        if not self.check_domain_reachable():
            logger.error("Domain nicht erreichbar. Scan abgebrochen.")
            return self.generate_report()
        
        # Parallel ausführbare Checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(self.check_open_ports): 'nmap',
                executor.submit(self.check_web_server): 'nikto',
                executor.submit(self.check_ssl): 'ssl',
                executor.submit(self.check_dns_security): 'dns'
            }
            
            for future in concurrent.futures.as_completed(futures):
                check_name = futures[future]
                try:
                    future.result()
                    logger.info(f"{check_name} check completed")
                except Exception as e:
                    logger.error(f"{check_name} check failed: {e}")
        
        # Vulnerability check separat (kann lange dauern)
        self.check_vulnerabilities()
        
        return self.generate_report()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 server_security_check.py <domain> [output_file]")
        print("Example: python3 server_security_check.py example.com scan_results.json")
        sys.exit(1)
    
    domain = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else f"{domain}_security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    scanner = SecurityScanner(domain, output_file)
    report = scanner.run_all_checks()
    
    # Kurze Zusammenfassung ausgeben
    summary = report['summary']
    print(f"\n{'='*50}")
    print(f"SECURITY SCAN SUMMARY FOR {domain}")
    print(f"{'='*50}")
    print(f"Total Issues Found: {summary['total_issues']}")
    
    if summary['critical_issues']:
        print("\nCritical Issues:")
        for issue in summary['critical_issues']:
            print(f"  - {issue}")
    
    if summary['recommendations']:
        print("\nRecommendations:")
        for rec in summary['recommendations']:
            print(f"  - {rec}")
    
    print(f"\nDetailed report saved to: {output_file}")

if __name__ == "__main__":
    main()
