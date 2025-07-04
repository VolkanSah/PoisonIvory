#  #############  .__  ##################  .__  ########################   #
#   ______   ____ |__| __________   ____   |__| __  _____________ ___.__.  #
#   \____ \ /  _ \|  |/  ___/  _ \ /    \  |  \  \/ /  _ \_  __ <   |  |   #
#   |  |_> >  <_> )  |\___ (  <_> )   |  \ |  |\   (  <_> )  | \/\___  |   #
#   |   __/ \____/|__/____  >____/|___|  / |__| \_/ \____/|__|   / ____|   #
#   |__|  lite v.30.5.23 \/           \/   © 2008-2023 Volkan Sah   \/     # 
#   https://github.com/VolkanSah/PoisonIvory-lite/
#!/usr/bin/env python3
"""
Tor Security Monitor für MiniGreX CMS
Überwacht Tor-Traffic und triggert Security-Scans bei verdächtigen Aktivitäten
"""

from scapy.all import *
from stem import Signal
from stem.control import Controller
import requests
import re
import json
import threading
import time
import logging
import subprocess
import os
from datetime import datetime
from collections import defaultdict

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tor_security_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TorSecurityMonitor:
    def __init__(self, onion_address, tor_control_port=9051):
        self.onion_address = onion_address
        self.tor_control_port = tor_control_port
        self.suspicious_activity = defaultdict(int)
        self.monitoring_active = False
        self.external_scanner_path = "server_security_check.py"
        self.alert_threshold = 5  # Anzahl verdächtiger Requests vor Alarm
        
        # Malicious patterns erweitert
        self.malicious_patterns = [
            r'(?i)(abuse|child|illegal|hack|exploit|malware|ddos)',
            r'(?i)(admin|login|wp-admin|phpmyadmin|admin\.php)',
            r'(?i)(\.\.\/|\.\.\\|%2e%2e|%252e%252e)',  # Directory traversal
            r'(?i)(select|union|drop|insert|update|delete|script)',  # SQL injection
            r'(?i)(<script|javascript:|vbscript:|onload=|onerror=)'  # XSS
        ]
        
        # Tor exit nodes blacklist
        self.malicious_relays = [
            # Hier würdest du bekannte schlechte Exit-Nodes eintragen
            "FINGERPRINT1", "FINGERPRINT2"
        ]
        
    def authenticate_tor_controller(self):
        """Authentifiziert sich mit Tor Controller"""
        try:
            controller = Controller.from_port(port=self.tor_control_port)
            controller.authenticate()
            return controller
        except Exception as e:
            logger.error(f"Tor Controller authentication failed: {e}")
            return None

    def check_malicious_traffic(self, request_data):
        """Überprüft Request auf malicious patterns"""
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
            'request_data': str(request_data)[:500],  # Begrenzt auf 500 Zeichen
            'onion_address': self.onion_address
        }
        
        # In File loggen
        with open('suspicious_activity.json', 'a') as f:
            f.write(json.dumps(activity_log) + '\n')
        
        # Counter erhöhen
        self.suspicious_activity[source_ip] += 1
        
        logger.warning(f"Suspicious activity from {source_ip}: {pattern}")
        
        # Security scan triggern wenn Threshold erreicht
        if self.suspicious_activity[source_ip] >= self.alert_threshold:
            self.trigger_security_scan(source_ip)

    def trigger_security_scan(self, target_ip):
        """Triggert externen Security-Scanner"""
        logger.info(f"Triggering security scan for {target_ip}")
        
        try:
            # Externen Scanner aufrufen
            cmd = [
                'python3', 
                self.external_scanner_path, 
                target_ip,
                f"emergency_scan_{target_ip}_{int(time.time())}.json"
            ]
            
            # Asynchron ausführen
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            logger.info(f"Security scan started for {target_ip} (PID: {process.pid})")
            
            # Optional: Tor-Circuit erneuern
            self.renew_tor_circuit()
            
        except Exception as e:
            logger.error(f"Failed to trigger security scan: {e}")

    def renew_tor_circuit(self):
        """Erneuert Tor-Circuit"""
        controller = self.authenticate_tor_controller()
        if controller:
            try:
                controller.signal(Signal.NEWNYM)
                logger.info("Tor circuit renewed")
                controller.close()
            except Exception as e:
                logger.error(f"Failed to renew Tor circuit: {e}")

    def exclude_malicious_relays(self):
        """Blacklistet bekannte schlechte Exit-Nodes"""
        controller = self.authenticate_tor_controller()
        if not controller:
            return
        
        try:
            # Aktuelle Circuit-Info holen
            circuits = controller.get_circuits()
            
            for circuit in circuits:
                if circuit.status == 'BUILT':
                    for hop in circuit.path:
                        if hop[0] in self.malicious_relays:
                            logger.warning(f"Malicious relay detected: {hop[0]}")
                            
                            # Relay zur Blacklist hinzufügen
                            controller.set_conf(f"ExcludeExitNodes {hop[0]}")
                            
                            # Circuit schließen
                            controller.close_circuit(circuit.id)
                            
            controller.close()
            
        except Exception as e:
            logger.error(f"Failed to exclude malicious relays: {e}")

    def packet_handler(self, packet):
        """Handler für abgefangene Pakete"""
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                
                # Auf malicious patterns prüfen
                is_malicious, pattern = self.check_malicious_traffic(payload)
                
                if is_malicious:
                    self.log_suspicious_activity(source_ip, pattern, payload)
                    
            except Exception as e:
                logger.debug(f"Packet processing error: {e}")

    def monitor_tor_traffic(self):
        """Überwacht Tor-Traffic"""
        logger.info("Starting Tor traffic monitoring...")
        self.monitoring_active = True
        
        try:
            # Sniff auf Tor-Ports
            sniff(
                filter="tcp and (port 9050 or port 9051 or port 80 or port 443)",
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda p: not self.monitoring_active
            )
        except Exception as e:
            logger.error(f"Traffic monitoring error: {e}")

    def check_onion_health(self):
        """Prüft Health der Onion-Adresse"""
        try:
            # Tor Session für Request
            session = requests.Session()
            session.proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
            
            response = session.get(f"http://{self.onion_address}", timeout=30)
            
            if response.status_code == 200:
                logger.info(f"Onion service {self.onion_address} is healthy")
                return True
            else:
                logger.warning(f"Onion service responded with status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Onion health check failed: {e}")
            return False

    def periodic_security_checks(self):
        """Führt periodische Security-Checks aus"""
        while self.monitoring_active:
            try:
                # Onion Health Check
                if not self.check_onion_health():
                    logger.warning("Onion service health check failed")
                    self.trigger_security_scan(self.onion_address)
                
                # Malicious relays ausschließen
                self.exclude_malicious_relays()
                
                # Statistiken loggen
                if self.suspicious_activity:
                    logger.info(f"Suspicious activity summary: {dict(self.suspicious_activity)}")
                
                time.sleep(300)  # 5 Minuten warten
                
            except Exception as e:
                logger.error(f"Periodic check error: {e}")
                time.sleep(60)

    def start_monitoring(self):
        """Startet das Monitoring"""
        logger.info(f"Starting Tor security monitor for {self.onion_address}")
        
        # Periodic checks in separatem Thread
        periodic_thread = threading.Thread(target=self.periodic_security_checks)
        periodic_thread.daemon = True
        periodic_thread.start()
        
        # Traffic monitoring im main thread
        self.monitor_tor_traffic()

    def stop_monitoring(self):
        """Stoppt das Monitoring"""
        logger.info("Stopping Tor security monitor")
        self.monitoring_active = False

    def get_activity_report(self):
        """Generiert Activity Report"""
        report = {
            'onion_address': self.onion_address,
            'monitoring_started': datetime.now().isoformat(),
            'suspicious_activity_count': sum(self.suspicious_activity.values()),
            'unique_suspicious_ips': len(self.suspicious_activity),
            'top_suspicious_ips': dict(sorted(
                self.suspicious_activity.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }
        return report

def main():
    """Hauptfunktion"""
    # Konfiguration
    onion_address = "INSERT .ONION ADDRESS HERE"  # Deine .onion Adresse
    
    if onion_address == "INSERT .ONION ADDRESS HERE":
        print("Bitte .onion Adresse in der Konfiguration setzen!")
        return
    
    # Monitor initialisieren
    monitor = TorSecurityMonitor(onion_address)
    
    try:
        # Monitoring starten
        monitor.start_monitoring()
        
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
        monitor.stop_monitoring()
        
        # Abschlussbericht
        report = monitor.get_activity_report()
        print("\n" + "="*50)
        print("MONITORING SUMMARY")
        print("="*50)
        print(f"Onion Address: {report['onion_address']}")
        print(f"Suspicious Activities: {report['suspicious_activity_count']}")
        print(f"Unique Suspicious IPs: {report['unique_suspicious_ips']}")
        
        if report['top_suspicious_ips']:
            print("\nTop Suspicious IPs:")
            for ip, count in report['top_suspicious_ips'].items():
                print(f"  {ip}: {count} incidents")

if __name__ == "__main__":
    main()
