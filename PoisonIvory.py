#!/usr/bin/env python3
"""
PoisonIvory 1.2 - Nemesis (Nuclear) Edition
Red Team Security Tool mit professioneller Konfigurationsverwaltung
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
import select
import struct
from datetime import datetime
import concurrent.futures
import logging
from collections import defaultdict

# Scapy optional für erweitertes Monitoring
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Tor Controller
try:
    from stem import Signal
    from stem.control import Controller
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

class ConfigManager:
    """Lädt und verwaltet Konfigurationen aus JSON-Dateien"""
    
    DEFAULT_CONFIG = {
        "domain": "",
        "onion_address": "",
        "tor_control_port": 9051,
        "tor_password": "",
        "output_dir": "redteam_reports",
        "alert_threshold": 5,
        "malicious_relays": [],
        "malicious_patterns": [
            r'(?i)(abuse|child|illegal|hack|exploit|malware|ddos)',
            r'(?i)(admin|login|wp-admin|phpmyadmin|admin\.php)',
            r'(?i)(\.\.\/|\.\.\\|%2e%2e|%252e%252e)',
            r'(?i)(select|union|drop|insert|update|delete|script)',
            r'(?i)(<script|javascript:|vbscript:|onload=|onerror=)',
            r'(?i)(eval\(|base64_decode|exec\(|system\()',
            r'(?i)(password|passwd|secret|key|token)',
            r'(?i)(\b(wget|curl|netcat|nc|bash|sh|cmd|powershell|python|perl)\b|\|\||\&\&|\$\(|\\`)',
            r'(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f|%252e%252e%252f|\~\/|\.\.\\x2f)',
            r'(?i)(/etc/passwd|/proc/self|\.env|\.git/config|wp-config\.php|\.htaccess)',
            r'(?i)(https?://(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))|metadata\.google\.internal)',
            r'(?i)(redirect=|url=|next=|to=|dest=)(https?%3a%2f%2f|https?://)',
            r'(?i)(\r\n|\n|\r|\%0d|\%0a)(Set-Cookie|Location|Content-Length|:)',
            r'(?i)\.(php|exe|dll|js|jar|jsp)(\.|$|\?|\s)',
            r'(?i)(php://|file://|zip://|expect://|data:text|http://)',
        ],
        "scan_tools": {
            "nmap": "/usr/bin/nmap",
            "nikto": "/usr/bin/nikto",
            "sslscan": "/usr/bin/sslscan"
        },
        "monitoring_interval": 300,
        "emergency_scan_threshold": 5
    }
    
    @staticmethod
    def load_config(config_path):
        """Lädt Konfiguration aus JSON-Datei mit Fallback auf Defaults"""
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
            
            # Merge mit Default-Konfiguration
            config = ConfigManager.DEFAULT_CONFIG.copy()
            config.update(user_config)
            return config
            
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            raise

class RedTeamOperator:
    def __init__(self, config):
        self.config = config
        self.domain = config.get('domain')
        self.onion_address = config.get('onion_address')
        self.tor_control_port = config.get('tor_control_port')
        self.tor_password = config.get('tor_password')
        self.output_dir = config.get('output_dir')
        self.nuclear_mode = config.get('nuclear_mode', False)
        self.thread_multiplier = 8 if self.nuclear_mode else 4
        self.monitoring_interval = config.get('monitoring_interval', 300)
        
        # Monitoring State
        self.monitoring_active = False
        self.scan_results = {}
        self.suspicious_activity = defaultdict(int)
        self.alert_threshold = config.get('alert_threshold', 5)
        self.lock = threading.Lock()
        
        # Security Patterns
        self.malicious_patterns = config.get('malicious_patterns', [])
        
        # Malicious Tor relays
        self.malicious_relays = config.get('malicious_relays', [])
        
        # Tool Paths
        self.tool_paths = config.get('scan_tools', {})
        
        # Create output dir securely
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Nuclear mode initialization
        if self.nuclear_mode:
            logger.warning("NUCLEAR MODE ACTIVATED")
            self.enable_nuclear_mode()
            
        # Shutdown handler
        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    def enable_nuclear_mode(self):
        """Aktiviert maximale Belastungseinstellungen"""
        if os.geteuid() == 0:
            try:
                subprocess.run(['sysctl', '-w', 'net.core.rmem_max=268435456'], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with open('/proc/sys/net/ipv4/ip_local_port_range', 'w') as f:
                    f.write("1024 65535")
            except Exception:
                logger.warning("Nuclear: Kernel tuning failed (run as root for full effect)")
        
        self.thread_multiplier = min(32, (os.cpu_count() or 1) * 8)
        self.monitoring_interval = 60  # Kürzeres Intervall im Nuclear Mode

    def shutdown_handler(self, signum, frame):
        """Graceful shutdown mit Cleanup"""
        logger.warning(f"SHUTDOWN SIGNAL {signum} RECEIVED")
        self.stop_monitoring()
        
        if self.nuclear_mode and os.geteuid() == 0:
            try:
                subprocess.run(['sysctl', '-w', 'net.core.rmem_max=212992'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        sys.exit(0)

    def run_command(self, cmd, timeout=300):
        """Führt Kommando aus mit Resource-Limits"""
        try:
            if self.nuclear_mode:
                resource.setrlimit(resource.RLIMIT_CPU, (120, 240))
                resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 2 << 30))
            
            result = subprocess.run(
                cmd, 
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
            if self.nuclear_mode:
                resource.setrlimit(resource.RLIMIT_CPU, (-1, -1))
                resource.setrlimit(resource.RLIMIT_AS, (-1, -1))

    # ========== SCANNER METHODEN ==========
    
    def comprehensive_port_scan(self, target=None):
        """Führt Port-Scan mit konfigurierten Tools durch"""
        target = target or self.domain
        if not target:
            logger.error("No target specified for port scan")
            return {}
            
        logger.info(f"Starting port scan: {target}")
        
        port_results = {}
        nmap_flags = "-T5 --min-rate 5000" if self.nuclear_mode else "-T4"
        nmap_path = self.tool_paths.get('nmap', 'nmap')
        
        # Nmap-Scan
        cmd = [nmap_path] + nmap_flags.split() + ["-sS", "-p-", target]
        result = self.run_command(cmd, timeout=900 if self.nuclear_mode else 300)
        if result['success']:
            port_results['nmap'] = {
                'output': result['stdout'],
                'ports': self._parse_nmap_ports(result['stdout'])
            }
        
        return port_results

    def _parse_nmap_ports(self, output):
        """Parst Nmap-Ausgabe nach offenen Ports"""
        ports = []
        port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+open\s+')
        
        for line in output.split('\n'):
            match = port_pattern.search(line)
            if match:
                ports.append(f"{match.group(1)}/{match.group(2)}")
                
        return ports

    # ========== KONFIGURATIONSBASIERTES MONITORING ==========
    
    def start_continuous_monitoring(self):
        """Startet kontinuierliches Monitoring basierend auf Konfiguration"""
        if not self.domain and not self.onion_address:
            logger.error("No monitoring targets configured")
            return
            
        logger.info("Starting security monitoring")
        self.monitoring_active = True
        
        # Netzwerk-Monitoring starten
        if self.config.get('enable_traffic_monitoring', True):
            monitor_thread = threading.Thread(target=self.network_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
        
        # Periodische Scans
        self.periodic_monitoring()

    def network_monitor(self):
        """Startet geeigneten Netzwerk-Monitor"""
        try:
            if self.nuclear_mode and os.geteuid() == 0:
                logger.info("Using raw socket monitoring")
                self.raw_packet_sniffer()
            elif SCAPY_AVAILABLE:
                logger.info("Using Scapy for packet monitoring")
                self.scapy_packet_sniffer()
            else:
                logger.warning("Packet monitoring disabled")
        except Exception as e:
            logger.error(f"Monitoring failed: {e}")

    def raw_packet_sniffer(self):
        """Low-Level Packet Sniffer"""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.setblocking(False)
            
            while self.monitoring_active:
                ready, _, _ = select.select([sock], [], [], 1)
                if ready:
                    packet = sock.recv(65535)
                    self.process_raw_packet(packet)
        except PermissionError:
            logger.error("Raw sockets require root privileges")
        except Exception as e:
            logger.error(f"Raw packet sniffer error: {e}")

    def process_raw_packet(self, packet):
        """Verarbeitet Rohpakete auf Sicherheitsbedrohungen"""
        if len(packet) < 14:
            return
            
        eth_header = packet[:14]
        eth_type = eth_header[12:14]
        
        # IPv4-Pakete
        if eth_type == b'\x08\x00' and len(packet) >= 34:
            ip_header = packet[14:34]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            protocol = ip_header[9]
            
            # TCP-Pakete
            if protocol == 6 and len(packet) >= 54:
                tcp_header = packet[34:54]
                data_offset = (tcp_header[12] >> 4) * 4
                payload_start = 14 + 20 + data_offset
                if len(packet) > payload_start:
                    self.analyze_payload(src_ip, packet[payload_start:])
            
            # UDP-Pakete
            elif protocol == 17 and len(packet) >= 42:
                self.analyze_payload(src_ip, packet[14+20:])

    def analyze_payload(self, src_ip, payload):
        """Analysiert Payload auf bösartige Muster"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            for pattern in self.malicious_patterns:
                if re.search(pattern, payload_str):
                    with self.lock:
                        self.handle_suspicious_activity(src_ip, pattern)
                    break
        except Exception as e:
            logger.debug(f"Payload analysis error: {e}")

    def handle_suspicious_activity(self, src_ip, pattern):
        """Verarbeitet verdächtige Aktivitäten"""
        self.suspicious_activity[src_ip] += 1
        logger.warning(f"Suspicious activity from {src_ip}: {pattern}")
        
        # Log-Eintrag erstellen
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': src_ip,
            'pattern': pattern,
            'count': self.suspicious_activity[src_ip]
        }
        
        log_path = os.path.join(self.output_dir, 'suspicious_activity.jsonl')
        with open(log_path, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        # Emergency-Scan bei Überschreitung des Schwellwerts
        if self.suspicious_activity[src_ip] >= self.alert_threshold:
            self.trigger_emergency_scan(src_ip)

    def trigger_emergency_scan(self, src_ip):
        """Startet Notfall-Scan für verdächtige IP"""
        logger.critical(f"EMERGENCY SCAN TRIGGERED: {src_ip}")
        threading.Thread(
            target=self.run_emergency_scan,
            args=(src_ip,),
            daemon=True
        ).start()

    def run_emergency_scan(self, target_ip):
        """Führt Notfall-Scan durch"""
        try:
            logger.info(f"Emergency scan started for {target_ip}")
            
            # Schneller Port-Scan
            scan_results = self.comprehensive_port_scan(target_ip)
            
            # Ergebnisse speichern
            report = {
                'timestamp': datetime.now().isoformat(),
                'target_ip': target_ip,
                'results': scan_results
            }
            
            report_path = os.path.join(
                self.output_dir, 
                f"emergency_scan_{target_ip}_{int(time.time())}.json"
            )
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
                
            logger.info(f"Emergency scan saved: {report_path}")
            
        except Exception as e:
            logger.error(f"Emergency scan failed: {e}")

    # ========== KERNOPERATIONEN ==========
    
    def run_full_audit(self):
        """Führt vollständiges Security-Audit durch"""
        targets = self.get_audit_targets()
        if not targets:
            logger.error("No audit targets configured")
            return
            
        logger.info(f"Starting security audit for {len(targets)} targets")
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(targets))  # Max 8 parallele Scans
        ) as executor:
            futures = {executor.submit(self.audit_target, target): target for target in targets}
            
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                    logger.info(f"Audit completed for {target}")
                except Exception as e:
                    logger.error(f"Audit failed for {target}: {e}")
        
        logger.info("Security audit completed")

    def get_audit_targets(self):
        """Gibt Liste der zu auditierenden Ziele zurück"""
        targets = []
        if self.domain:
            targets.append(self.domain)
        if self.onion_address:
            targets.append(self.onion_address)
        return targets

    def audit_target(self, target):
        """Führt vollständiges Audit für ein Ziel durch"""
        logger.info(f"Starting audit: {target}")
        
        # 1. Port-Scan
        port_scan = self.comprehensive_port_scan(target)
        
        # 2. Web-Scan
        web_scan = self.comprehensive_web_scan(target)
        
        # 3. SSL-Scan
        ssl_scan = self.comprehensive_ssl_scan(target)
        
        # Report generieren
        report = {
            'target': target,
            'port_scan': port_scan,
            'web_scan': web_scan,
            'ssl_scan': ssl_scan,
            'timestamp': datetime.now().isoformat()
        }
        
        report_path = os.path.join(
            self.output_dir, 
            f"audit_report_{target}_{int(time.time())}.json"
        )
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Audit report saved: {report_path}")

    def periodic_monitoring(self):
        """Führt periodische Überprüfungen durch"""
        while self.monitoring_active:
            try:
                # Zielverfügbarkeit prüfen
                for target in self.get_audit_targets():
                    if not self.check_target_availability(target):
                        logger.warning(f"Target unavailable: {target}")
                
                # Verarbeitete Aktivitäten protokollieren
                if self.suspicious_activity:
                    logger.info(f"Suspicious activity counts: {dict(self.suspicious_activity)}")
                
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(10)

    def stop_monitoring(self):
        """Stoppt alle Überwachungsaktivitäten"""
        logger.info("Stopping monitoring")
        self.monitoring_active = False

def main():
    """Hauptfunktion mit erweiterter Konfigurationsverwaltung"""
    if len(sys.argv) < 2:
        print("Enterprise Security Auditor")
        print("Usage:")
        print("  ./PoisonIvory.py --config <config.json> [--audit|--monitor] [--nuclear]")
        print("\nExample config:")
        print(json.dumps(ConfigManager.DEFAULT_CONFIG, indent=2))
        sys.exit(1)
    
    # Argumente parsen
    config_path = None
    command = None
    nuclear_mode = False
    
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--config" and i+1 < len(sys.argv):
            config_path = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == "--audit":
            command = "audit"
            i += 1
        elif sys.argv[i] == "--monitor":
            command = "monitor"
            i += 1
        elif sys.argv[i] == "--nuclear":
            nuclear_mode = True
            i += 1
        else:
            print(f"Unknown argument: {sys.argv[i]}")
            sys.exit(1)
    
    if not config_path:
        print("Config file required (--config)")
        sys.exit(1)
    
    try:
        # Konfiguration laden
        config = ConfigManager.load_config(config_path)
        config['nuclear_mode'] = nuclear_mode
        
        # Operator initialisieren
        operator = RedTeamOperator(config)
        
        # Kommando ausführen
        if command == "audit":
            operator.run_full_audit()
        elif command == "monitor":
            operator.start_continuous_monitoring()
            while operator.monitoring_active:
                time.sleep(1)
        else:
            print("No command specified (use --audit or --monitor)")
            sys.exit(1)
            
    except KeyboardInterrupt:
        if 'operator' in locals():
            operator.stop_monitoring()
        logger.warning("Operation cancelled")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Sichere Dateiberechtigungen
    os.umask(0o077)
    main()
