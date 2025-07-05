#!/usr/bin/env python3
"""
PoisonIvory 2.0 - Nemesis (Nuclear) Edition
Red Team Security Tool für maximale Belastungstests
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
from datetime import datetime
import concurrent.futures
import logging
from collections import defaultdict

# Scapy optional für Monitoring
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Tor Controller
try:
    from stem import Signal
    from stem.control import Controller
    from stem.util import term
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('redteam_ops.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('RedTeamOps')
logger.propagate = False

# Nuclear Mode Warnung
NUCLEAR_WARNING = term.format(
    "\n☢️  NUCLEAR MODE ACTIVATED - EXPECT SYSTEM INSTABILITY ☢️\n"
    "Target servers may experience service disruption\n",
    term.Color.RED, 
    term.Attr.BOLD
)

class RedTeamOperator:
    def __init__(self, config):
        self.config = config
        self.domain = config.get('domain')
        self.onion_address = config.get('onion_address')
        self.tor_control_port = config.get('tor_control_port', 9051)
        self.tor_password = config.get('tor_password', '')
        self.output_dir = config.get('output_dir', 'redteam_reports')
        self.nuclear_mode = config.get('nuclear_mode', False)
        self.thread_multiplier = 8 if self.nuclear_mode else 4
        
        # Monitoring State
        self.monitoring_active = False
        self.scan_results = {}
        self.suspicious_activity = defaultdict(int)
        self.alert_threshold = config.get('alert_threshold', 5)
        
        # Security Patterns (FIXED REGEX)
        self.malicious_patterns = [
            r'(?i)(abuse|child|illegal|hack|exploit|malware|ddos)',
            r'(?i)(admin|login|wp-admin|phpmyadmin|admin\.php)',
            r'(?i)(\.\.\/|\.\.\\|%2e%2e|%252e%252e)',
            r'(?i)(select|union|drop|insert|update|delete|script)',
            r'(?i)(<script|javascript:|vbscript:|onload=|onerror=)',
            r'(?i)(eval\(|base64_decode|exec\(|system\()',
            r'(?i)(password|passwd|secret|key|token)',
            r'(?i)(\b(wget|curl|netcat|nc|bash|sh|cmd|powershell|python|perl)\b|\|\||\&\&|\$\(|\\`)',  # FIXED
            r'(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f|%252e%252e%252f|\~\/|\.\.\\x2f)',
            r'(?i)(/etc/passwd|/proc/self|\.env|\.git/config|wp-config\.php|\.htaccess)',
            r'(?i)(https?://(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))|metadata\.google\.internal)',
            r'(?i)(redirect=|url=|next=|to=|dest=)(https?%3a%2f%2f|https?://)',
            r'(?i)(\r\n|\n|\r|\%0d|\%0a)(Set-Cookie|Location|Content-Length|:)',
            r'(?i)\.(php|exe|dll|js|jar|jsp)(\.|$|\?|\s)',
            r'(?i)(php://|file://|zip://|expect://|data:text|http://)',
        ]
        
        # Malicious Tor relays
        self.malicious_relays = config.get('malicious_relays', [])
        
        # Create output dir securely
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Nuclear mode initialization
        if self.nuclear_mode:
            logger.warning(NUCLEAR_WARNING)
            self.enable_nuclear_mode()
            
        # Shutdown handler
        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    def enable_nuclear_mode(self):
        """Aktiviert maximale Belastungseinstellungen"""
        # Kernel-Parameter optimieren
        if os.geteuid() == 0:  # Nur als Root
            os.system("sysctl -w net.core.rmem_max=268435456 >/dev/null 2>&1")
            os.system("echo '1024 65535' > /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null")
        
        # Scapy durch raw sockets ersetzen
        global SCAPY_AVAILABLE
        SCAPY_AVAILABLE = False
        
        # Threading optimieren
        self.thread_multiplier = min(32, os.cpu_count() * 8)

    def shutdown_handler(self, signum, frame):
        """Graceful shutdown mit Nuclear-Cleanup"""
        logger.warning(f"🚨 SHUTDOWN SIGNAL {signum} RECEIVED")
        self.stop_monitoring()
        
        if self.nuclear_mode and os.geteuid() == 0:
            os.system("sysctl -w net.core.rmem_max=212992 >/dev/null")  # Default-Wert
        sys.exit(0)

    def run_command(self, cmd, timeout=300):
        """Führt Kommando aus mit Resource-Limits und Sanitization"""
        # Command Sanitization
        safe_cmd = [shlex.quote(str(arg)) for arg in cmd]
        
        try:
            # Set resource limits
            if self.nuclear_mode:
                resource.setrlimit(resource.RLIMIT_CPU, (120, 240))
                resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 2 << 30))  # 1-2GB RAM
            
            # Execute command
            result = subprocess.run(
                safe_cmd, 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False
            )
            return {
                'success': True,
                'stdout': result.stdout.decode('utf-8', errors='replace'),
                'stderr': result.stderr.decode('utf-8', errors='replace'),
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired as e:
            return {'success': False, 'error': f'Timeout after {timeout}s'}
        except FileNotFoundError:
            return {'success': False, 'error': f'Command not found: {cmd[0]}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            # Reset resource limits
            if self.nuclear_mode:
                resource.setrlimit(resource.RLIMIT_CPU, (-1, -1))
                resource.setrlimit(resource.RLIMIT_AS, (-1, -1))

    # ========== AGGRESSIVE SCANNER METHODS ==========
    
    def check_domain_reachable(self, target=None):
        """Prüft Erreichbarkeit mit Nuclear-Optionen"""
        target = target or self.domain
        logger.info(f"[*] Probing {target} with nuclear force...")
        
        try:
            if target.endswith('.onion'):
                return self.check_onion_reachable(target)
            else:
                # DNS mit Aggressivität
                socket.getaddrinfo(target, 80, flags=socket.AI_ADDRCONFIG)
                
                # HTTP/S Check mit Connection Pooling
                session = self.get_http_session()
                response = session.get(
                    f"http://{target}", 
                    timeout=10,
                    headers={'User-Agent': 'NuclearScanner/2.0'}
                )
                return response.status_code < 500
                
        except Exception as e:
            logger.error(f"Target annihilation failed: {e}")
            return False

    def get_http_session(self):
        """Erstellt optimierte HTTP-Session"""
        session = requests.Session()
        if self.nuclear_mode:
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=100,
                pool_maxsize=100,
                max_retries=3
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
        return session

    def comprehensive_port_scan(self, target=None):
        """Port-Scan mit Nuclear-Parametern"""
        target = target or self.domain
        logger.warning(f"[!] NUKE PORT SCAN INITIATED: {target}")
        
        port_results = {}
        nmap_flags = "-T5 --min-rate 5000" if self.nuclear_mode else "-T4"
        
        # Aggressive Scan
        cmd = ["nmap", nmap_flags, "-sS", "-p-", target]
        result = self.run_command(cmd, timeout=900 if self.nuclear_mode else 300)
        if result['success']:
            port_results['nmap_aggressive'] = {
                'output': result['stdout'],
                'ports': self._parse_nmap_ports(result['stdout'])
            }
        
        # Service Version Scan
        cmd = ["nmap", nmap_flags, "-sV", "--version-intensity", "9", target]
        result = self.run_command(cmd)
        if result['success']:
            port_results['service_versions'] = self._parse_nmap_services(result['stdout'])
        
        return port_results

    # ========== TOR WARFARE METHODS ==========
    
    def authenticate_tor_controller(self):
        """Tor Auth mit Timeout und Nuclear-Resilience"""
        if not TOR_AVAILABLE:
            return None
            
        try:
            # Timeout für Verbindung
            controller = Controller.from_port(port=self.tor_control_port)
            
            # Auth mit Passwort wenn vorhanden
            if self.tor_password:
                controller.authenticate(password=self.tor_password)
            else:
                controller.authenticate()
                
            return controller
        except Exception as e:
            logger.error(f"Tor warfare failed: {e}")
            return None

    def trigger_emergency_scan(self, suspicious_ip):
        """Emergency Scan mit Anti-Loop Mechanismus"""
        logger.critical(f"🚨 EMERGENCY SCAN TRIGGERED: {suspicious_ip}")
        
        # Scan in eigenem Thread
        threading.Thread(
            target=self.emergency_scan_worker,
            args=(suspicious_ip,),
            daemon=True
        ).start()
        
        # Tor Circuit mit 70% Wahrscheinlichkeit erneuern
        if TOR_AVAILABLE and random.random() < 0.7:
            self.renew_tor_circuit()

    def renew_tor_circuit(self):
        """Erzwingt neuen Tor Circuit mit Brutal-Force"""
        controller = self.authenticate_tor_controller()
        if controller:
            try:
                controller.signal(Signal.NEWNYM)
                logger.info("Tor circuit nuked and rebuilt")
                controller.close()
            except Exception as e:
                logger.error(f"Circuit annihilation failed: {e}")

    # ========== MAIN WARFARE METHODS ==========
    
    def run_full_security_scan(self, target=None):
        """Führt Total-Zerstörungs-Scan durch"""
        target = target or self.domain or self.onion_address
        logger.warning(f"🔥 INITIATING TOTAL SCAN ANNIHILATION: {target}")
        
        if not self.check_domain_reachable(target):
            logger.error(f"Target {target} annihilated preemptively")
            return None
        
        # Nuclear Threading
        workers = min(32, os.cpu_count() * self.thread_multiplier)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.comprehensive_port_scan, target): 'ports',
                executor.submit(self.nuclear_web_scan, target): 'web',
                executor.submit(self.comprehensive_ssl_scan, target): 'ssl',
                executor.submit(self.vulnerability_assessment, target): 'vulns'
            }
            
            for future in concurrent.futures.as_completed(futures):
                scan_type = futures[future]
                try:
                    result = future.result()
                    logger.info(f"{scan_type.upper()} OBLITERATION COMPLETE")
                except Exception as e:
                    logger.error(f"{scan_type} annihilation failed: {e}")
        
        return self.generate_warfare_report()

    def start_continuous_monitoring(self):
        """Startet unerbittliches Dauer-Monitoring"""
        logger.warning("🚀 LAUNCHING PERSISTENT THREAT MONITORING")
        self.monitoring_active = True
        
        # Traffic Monitoring
        if SCAPY_AVAILABLE and not self.nuclear_mode:
            traffic_thread = threading.Thread(target=self.monitor_traffic)
            traffic_thread.daemon = True
            traffic_thread.start()
        elif self.nuclear_mode:
            logger.info("RAW PACKET WARFARE ENGAGED")
            traffic_thread = threading.Thread(target=self.raw_packet_warfare)
            traffic_thread.daemon = True
            traffic_thread.start()
        
        # Periodische Angriffe
        self.periodic_warfare()

    def raw_packet_warfare(self):
        """Low-Level Packet Warfare für maximale Leistung"""
        try:
            # RAW Socket erstellen
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.setblocking(False)
            
            logger.warning("🔥 RAW PACKET WARFARE ACTIVE")
            while self.monitoring_active:
                # Non-blocking packet capture
                ready, _, _ = select.select([sock], [], [], 1)
                if ready:
                    packet = sock.recv(65535)
                    # Minimalistische Analyse
                    if len(packet) > 50:  | # TCP/UDP Mindestgröße
                        src_ip = socket.inet_ntoa(packet[26:30])
                        payload = packet[42:].decode('utf-8', errors='ignore')
                        self.analyze_payload(src_ip, payload)
        except Exception as e:
            logger.error(f"Packet warfare failed: {e}")

    def periodic_warfare(self):
        """Führt periodische Angriffsoperationen durch"""
        while self.monitoring_active:
            try:
                # Gesundheitschecks mit Brutalität
                targets = [t for t in [self.domain, self.onion_address] if t]
                for target in targets:
                    if not self.check_domain_reachable(target):
                        logger.warning(f"TARGET DOWN: {target} - LAUNCHING COUNTERMEASURES")
                        self.renew_tor_circuit()
                
                # Warten bis zum nächsten Angriff
                nap_time = 60 if self.nuclear_mode else 300
                time.sleep(nap_time)
                
            except Exception as e:
                logger.error(f"Warfare error: {e}")
                time.sleep(10)

    def generate_warfare_report(self):
        """Erstellt Kriegsbericht"""
        report = {
            'status': 'TARGET ANNIHILATED',
            'findings': self.scan_results,
            'recommendation': 'DEPLOY COUNTERMEASURES IMMEDIATELY',
            'signature': 'RedTeamOperator PoisonIvory 2.0'
        }
        
        # Report speichern
        report_file = f"{self.output_dir}/warfare_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.warning(f"💀 WARFARE REPORT COMPILED: {report_file}")
        return report

def main():
    """Hauptfunktion der Kriegsmaschine"""
    if '--nuclear' in sys.argv:
        print(NUCLEAR_WARNING)
        time.sleep(2)
        config = {'nuclear_mode': True, 'domain': sys.argv[-1]}
    else:
        config = {'domain': sys.argv[-1]}
    
    operator = RedTeamOperator(config)
    
    try:
        if '--scan' in sys.argv:
            operator.run_full_security_scan()
        elif '--siege' in sys.argv:
            operator.start_continuous_monitoring()
            while True: time.sleep(3600)  | # Endlose Belagerung
        else:
            print("OPERATION MODES:")
            print("  --scan   : Einmaliger Vernichtungsschlag")
            print("  --siege  : Dauerbelagerung (Ctrl+C zum Stoppen)")
            print("  --nuclear: Maximale Zerstörung (Root empfohlen)")
            
    except KeyboardInterrupt:
        logger.warning("OPERATION ABORTED BY COMMAND")
    except Exception as e:
        logger.error(f"CRITICAL MISSION FAILURE: {e}")

if __name__ == "__main__":
    main()
