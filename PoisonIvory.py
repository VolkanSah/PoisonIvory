#!/usr/bin/env python3
# source: https://github.com/VolkanSah/PoisonIvory/
# Dual License Statement: (ESOL v1.0) + (GPLv3)
"""              .__                      .__                          
______   ____ |__| __________   ____   |__| __  _____________ ___.__.
\____ \ /  _ \|  |/  ___/  _ \ /    \  |  \  \/ /  _ \_  __ <   |  |
|  |_> >  <_> )  |\___ (  <_> )   |  \ |  |\   (  <_> )  | \/\___  |
|   __/ \____/|__/____  >____/|___|  / |__| \_/ \____/|__|   / ____|
|__|  nemesis v.1.4.0  \/   REBORN  \/   © 2008-2026 Volkan Sah   \/   
Original Architecture with Critical Enhancements
Critical vulnerabilities patched + 2026 patterns integrated
"""

import subprocess
import requests
import sys
import json
import time
import threading
import signal
import os
import random
import resource
import socket
import re
import logging
import ipaddress
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Scapy für Packet Sniffing
try:
    from scapy.all import sniff, IP, TCP, Raw
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
        logging.FileHandler('poison_ivory_core.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SecurityPatterns2026:
    """
    Enhanced Security Patterns für 2025/2026 mit Risk Scoring
    """
    def __init__(self):
        self.patterns = {
            # ============================================================
            # SQL INJECTION - Context-Aware
            # ============================================================
            'sql_injection_union': r'(?i)\bunion\s+(all\s+)?select\b',
            'sql_injection_boolean': r"(?i)(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
            'sql_injection_stacked': r'(?i);\s*(drop|truncate|alter|delete|insert|update)\s+',
            'sql_injection_sleep': r'(?i)\b(sleep|waitfor|pg_sleep|benchmark)\s*\(',
            
            # ============================================================
            # XSS - Modern Vectors
            # ============================================================
            'xss_script_tag': r'(?i)<script[^>]*>',
            'xss_event_handler': r'(?i)\bon(load|error|click|mouse|focus|blur)\s*=',
            'xss_javascript_proto': r'(?i)javascript\s*:',
            'xss_data_uri': r'(?i)data:text/html[,;]',
            'xss_dom_manipulation': r'(?i)(innerHTML|outerHTML|insertAdjacentHTML)\s*=',
            'xss_alerts': r'(?i)(alert|confirm|prompt)\s*\(',
            
            # ============================================================
            # PATH TRAVERSAL
            # ============================================================
            'path_traversal_basic': r'(?i)\.\.[\\/]',
            'path_traversal_encoded': r'(?i)(%2e){2}(%2f|%5c)',
            'path_traversal_double': r'(?i)(%252e){2}(%252f|%255c)',
            'path_traversal_unicode': r'(?i)\.\.(%c0%af|%c1%9c)',
            
            # ============================================================
            # COMMAND INJECTION
            # ============================================================
            'cmd_injection_chain': r'(?i)[;&|]\s*(wget|curl|nc|bash|sh|powershell|cmd)\b',
            'cmd_injection_subshell': r'\$\([^)]+\)',
            'cmd_injection_backticks': r'`[^`]+`',
            'cmd_injection_pipe': r'\|\|\s*\w+',
            'cmd_injection_base64': r'(?i)\|base64\s+-d',
            
            # ============================================================
            # CODE EXECUTION
            # ============================================================
            'code_exec_eval': r'(?i)\beval\s*\(',
            'code_exec_shell': r'(?i)\b(exec|system|shell_exec|passthru|proc_open|popen)\s*\(',
            'code_exec_base64': r'(?i)base64_decode\s*\(',
            
            # ============================================================
            # FILE INCLUSION
            # ============================================================
            'file_inclusion_proto': r'(?i)(php|file|zip|data|expect|glob|phar|input)://',
            'file_inclusion_remote': r'(?i)(include|require)(_once)?\s*\(\s*["\']?(https?|ftp)',
            
            # ============================================================
            # SENSITIVE FILES
            # ============================================================
            'sensitive_unix': r'(?i)/etc/(passwd|shadow|hosts)',
            'sensitive_proc': r'(?i)/proc/(self|version|cmdline)',
            'sensitive_dotfiles': r'(?i)\.(env|git/config|ssh/id_rsa|aws/credentials)',
            'sensitive_config': r'(?i)(wp-config|web\.config|\.htaccess)',
            'sensitive_backup': r'(?i)\.(bak|backup|old|tmp|temp|orig|save|swp|~)',
            'sensitive_bash_history': r'(?i)\.bash_history',
            
            # ============================================================
            # SSRF - Cloud Metadata
            # ============================================================
            'ssrf_localhost': r'(?i)https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[\\/:]',
            'ssrf_private_10': r'(?i)https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'ssrf_private_192': r'(?i)https?://192\.168\.\d{1,3}\.\d{1,3}',
            'ssrf_private_172': r'(?i)https?://172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}',
            'ssrf_aws_metadata': r'(?i)169\.254\.169\.254',
            'ssrf_gcp_metadata': r'(?i)metadata\.google\.internal',
            'ssrf_azure_metadata': r'(?i)metadata\.azure\.com',
            
            # ============================================================
            # CREDENTIALS & API KEYS
            # ============================================================
            'creds_password': r'(?i)\b(password|passwd|pwd|secret)\s*[=:]',
            'creds_api_key': r'(?i)\b(api[_-]?key|access[_-]?token)\s+[\w\-]{20,}',
            'creds_bearer': r'(?i)\bbearer\s+[\w\-\.]{20,}',
            'creds_jwt': r'\beyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.',
            
            # ============================================================
            # MODERN API KEYS (2025)
            # ============================================================
            'apikey_openai': r'\bsk-[a-zA-Z0-9]{48}\b',
            'apikey_github_personal': r'\bghp_[a-zA-Z0-9]{36}\b',
            'apikey_github_oauth': r'\bgho_[a-zA-Z0-9]{36}\b',
            'apikey_google': r'\bAIza[0-9A-Za-z\-_]{35}\b',
            'apikey_aws': r'\bAKIA[0-9A-Z]{16}\b',
            'apikey_stripe': r'\b(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}\b',
            'apikey_sendgrid': r'\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b',
            
            # ============================================================
            # XXE INJECTION
            # ============================================================
            'xxe_doctype': r'(?i)<!DOCTYPE[^>]*\[',
            'xxe_entity': r'(?i)<!ENTITY[^>]+SYSTEM',
            'xxe_public': r'(?i)<!ENTITY[^>]+PUBLIC',
            
            # ============================================================
            # LDAP INJECTION
            # ============================================================
            'ldap_injection': r'(?i)(\*\)|&\(|\|\(|\!\()(\w+=)',
            
            # ============================================================
            # TEMPLATE INJECTION (SSTI)
            # ============================================================
            'ssti_jinja': r'\{\{.*(__|\.|config|request).*\}\}',
            'ssti_flask': r'\{%.*(__|\.|import|exec).*%\}',
            'ssti_spring': r'\$\{.*\.class\.',
            'ssti_expression': r'(?i)(#\{.*\}|@\{.*\}|%\{.*\}|\$\{T\()',
            
            # ============================================================
            # NOSQL INJECTION
            # ============================================================
            'nosql_operators': r'(?i)\$(ne|gt|lt|regex|where|exists|or|and)\s*:',
            
            # ============================================================
            # DESERIALIZATION ATTACKS
            # ============================================================
            'deser_pickle': r'(?i)pickle\.loads',
            'deser_yaml': r'(?i)yaml\.load[^_]',
            'deser_php': r'(?i)unserialize',
            'deser_java': r'(?i)readObject',
            'deser_java_magic': r'AC\s?ED\s?00\s?05',
            'deser_reduce': r'(?i)__reduce__',
            
            # ============================================================
            # LLM PROMPT INJECTION (2025 CRITICAL!)
            # ============================================================
            'llm_ignore_instructions': r'(?i)ignore\s+(previous|all|above)\s+(instructions|prompts?)',
            'llm_disregard': r'(?i)disregard\s+(the\s+)?(above|previous)',
            'llm_system_override': r'(?i)(system|user|assistant)\s*:\s*(you\s+are|ignore)',
            'llm_reveal_prompt': r'(?i)reveal\s+(your|the)\s+(prompt|instructions|system)',
            'llm_jailbreak_dan': r'(?i)(DAN|do\s+anything\s+now)',
            'llm_hypothetical': r'(?i)(hypothetically|imagine\s+you|pretend\s+you)',
            
            # ============================================================
            # AI AGENT ATTACKS (2025!)
            # ============================================================
            'ai_agent_tool_misuse': r'(?i)(execute|run|call)\s+(tool|function|api)\s+',
            'ai_agent_goal_hijack': r'(?i)(modify|change)\s+(goal|objective|task)',
            'ai_agent_privilege_esc': r'(?i)(grant|give|add)\s+(admin|root|privilege)',
            'ai_system_prompt_extract': r'(?i)(show|display|reveal)\s+system\s+prompt',
            
            # ============================================================
            # SHADOW AI DETECTION (2025!)
            # ============================================================
            'shadow_ai_chatgpt': r'(?i)api\.openai\.com/v1',
            'shadow_ai_claude': r'(?i)api\.anthropic\.com/v1',
            'shadow_ai_gemini': r'(?i)generativelanguage\.googleapis\.com',
            'shadow_ai_huggingface': r'(?i)huggingface\.co/api',
            
            # ============================================================
            # CONTAINER ESCAPE (2025/2026 Critical!)
            # ============================================================
            'container_docker_sock': r'(?i)/var/run/docker\.sock',
            'container_proc_env': r'(?i)/proc/self/(environ|cgroup|mountinfo)',
            'container_kubectl': r'(?i)\b(kubectl|crictl|docker)\s+(exec|run)',
            'container_k8s_service': r'(?i)KUBERNETES_SERVICE_(HOST|PORT)',
            
            # ============================================================
            # CI/CD SECRETS (2025 Supply Chain Focus)
            # ============================================================
            'cicd_github_token': r'(?i)GITHUB_TOKEN',
            'cicd_gitlab_token': r'(?i)GITLAB_TOKEN',
            'cicd_circle_token': r'(?i)CIRCLE_TOKEN',
            'cicd_jenkins_token': r'(?i)JENKINS_TOKEN',
            'cicd_workflows': r'(?i)\.github/workflows/.*\.ya?ml',
            'cicd_docker_password': r'(?i)DOCKER_PASSWORD',
            
            # ============================================================
            # CRYPTO WALLET TARGETING
            # ============================================================
            'crypto_metamask': r'(?i)\b(metamask|coinbase|trust\s*wallet|phantom)\b',
            'crypto_seed_phrase': r'(?i)\b(seed\s+phrase|mnemonic|recovery\s+phrase)\b',
            'crypto_eth_address': r'\b0x[a-fA-F0-9]{40}\b',
            'crypto_btc_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'crypto_wallet_connect': r'(?i)wallet.*connect',
            'crypto_private_key': r'(?i)private.*key',
            
            # ============================================================
            # POST-QUANTUM CRYPTOGRAPHY (2026!)
            # ============================================================
            'pqc_harvest_now': r'(?i)(harvest|capture|store).{0,20}(decrypt|break).{0,20}later',
            'pqc_rsa_small': r'\bRSA[_-]?(1024|2048)\b',
            'pqc_weak_ecdsa': r'\bECDSA[_-]?P[_-]?256\b',
            'pqc_legacy_dh': r'\bDH[_-]?1024\b',
            
            # ============================================================
            # SUPPLY CHAIN ATTACKS (2025/2026)
            # ============================================================
            'supply_npm_unsafe': r'(?i)npm\s+install.*--unsafe',
            'supply_pip_unsafe': r'(?i)pip\s+install.*--no-verify',
            'supply_typosquat': r'(?i)(typosquat|dependency.*confusion)',
            'supply_malicious_package': r'(?i)(malicious|backdoor).{0,20}(package|dependency)',
            'supply_package_hijack': r'(?i)package.*hijack',
            
            # ============================================================
            # DATA EXFILTRATION CHANNELS (2025)
            # ============================================================
            'exfil_discord_webhook': r'(?i)discord\.com/api/webhooks/\d+',
            'exfil_telegram_bot': r'(?i)api\.telegram\.org/bot',
            'exfil_pastebin': r'(?i)pastebin\.com/(raw|api)',
            'exfil_requestbin': r'(?i)(requestbin|webhook\.site)',
            'exfil_data_uri': r'(?i)data:image/.*base64',
            'exfil_btoa': r'(?i)btoa\s*\(',
            
            # ============================================================
            # EVASION TECHNIQUES
            # ============================================================
            'evasion_honeypot': r'(?i)(honeypot.*detect|sandbox.*evasion|vm.*detection)',
            'evasion_antivm': r'(?i)anti[-_]?(vm|debug|sandbox)',
            
            # ============================================================
            # EDGE DEVICE EXPLOITATION (Palo Alto, Fortinet, Ivanti)
            # ============================================================
            'edge_panos': r'(?i)(panos|globalprotect)',
            'edge_fortios': r'(?i)fortios',
            'edge_ivanti': r'(?i)(ivanti|pulse.*secure)',
            'edge_vpn_paths': r'(?i)/(dana-na|remote/login|vpn)/',
            'edge_api_paths': r'(?i)/api/v[12]/',
            
            # ============================================================
            # DEEPFAKE & AI IDENTITY (2026!)
            # ============================================================
            'deepfake_ceo': r'(?i)(deepfake|synthetic).{0,20}(CEO|executive|CFO)',
            'deepfake_voice': r'(?i)(voice\s+clone|audio\s+spoof|voice\s+synthesis)',
            'ai_impersonation': r'(?i)(AI|bot).{0,20}(impersonat|pretend|pose\s+as)',
            
            # ============================================================
            # SOCIAL ENGINEERING (IBM 2026 Prediction)
            # ============================================================
            'social_password_reset': r'(?i)(urgent|immediate).{0,20}password.{0,20}reset',
            'social_account_recovery': r'(?i)(locked|suspend).{0,20}account.{0,20}(recovery|reset)',
            'social_verify_identity': r'(?i)(verify|confirm).{0,20}identity.{0,20}(urgent|immediate)',
            'social_phishing': r'(?i)(phishing|scam)',
            'social_captcha': r'(?i)captcha.*verification',
            'social_click_continue': r'(?i)click.*continue',
            
            # ============================================================
            # GRAPHQL INJECTION
            # ============================================================
            'graphql_introspection': r'(?i)(__schema|__type|introspectionQuery)',
            'graphql_nested': r'(?i)query.{0,100}query',
            
            # ============================================================
            # PROTOTYPE POLLUTION (JavaScript)
            # ============================================================
            'prototype_pollution': r'(__proto__|constructor\[[\"\']?prototype[\"\']?\])',
            
            # ============================================================
            # HTTP HEADER INJECTION
            # ============================================================
            'header_injection': r'(?i)(\r\n|\n|\r|%0d|%0a)(Set-Cookie|Location|Content-Length|Host):',
            
            # ============================================================
            # OPEN REDIRECTS
            # ============================================================
            'open_redirect': r'(?i)(redirect=|url=|next=|to=|dest=)(https?%3a%2f%2f|https?://)',
            
            # ============================================================
            # DIRECTORY LISTING
            # ============================================================
            'directory_listing': r'(?i)(Index\s+of\s+/|Directory\s+Listing|Parent\s+Directory)',
            
            # ============================================================
            # DANGEROUS FILE EXTENSIONS
            # ============================================================
            'dangerous_extensions': r'(?i)\.(php|exe|dll|jar|jsp|asp|aspx|pl|py|rb)(\.|$|\?|\s)',
            
            # ============================================================
            # MORE PROTOCOL HANDLERS
            # ============================================================
            'protocol_jar': r'(?i)jar:(http|https)://',
            'protocol_sftp': r'(?i)sftp://',
            'protocol_tftp': r'(?i)tftp://',
            'protocol_ldap': r'(?i)ldap://',
            'protocol_gopher': r'(?i)gopher://',
            'protocol_dict': r'(?i)dict://',
            
            # ============================================================
            # NODE.JS/NPM SUPPLY CHAIN (2024/2025 trend)
            # ============================================================
            'nodejs_child_process': r'(?i)require\s*\(\s*["\']child_process["\']',
            'nodejs_spawn': r'(?i)spawn\s*\(',
            'nodejs_exec_node': r'(?i)exec\s*\(.*node',
            'nodejs_xhr_proto': r'(?i)XMLHttpRequest\.prototype',
            'nodejs_crypto_wallet': r'(?i)(web3|crypto.*wallet|ethereum|bitcoin)',
            'nodejs_obfuscated': r'(?i)(javascript-obfuscator|obfuscated.*payload|_0x[0-9a-f]{6})',
            
            # ============================================================
            # QUANTUM-SAFE MIGRATION ISSUES (2026)
            # ============================================================
            'quantum_ml_kem_missing': r'(?i)X25519(?!.*ML[_-]KEM)',
            'quantum_hybrid_missing': r'(?i)TLS[_-]?1[._]?[23](?!.*hybrid)',
        }
        
        # Kompilierte Patterns für Performance
        self.compiled = {
            name: re.compile(pattern) 
            for name, pattern in self.patterns.items()
        }
        
        # Risk Levels
        self.risk_levels = {
            'llm_': 'CRITICAL',
            'ai_agent_': 'CRITICAL',
            'shadow_ai_': 'CRITICAL',
            'pqc_': 'CRITICAL',
            'deepfake_': 'CRITICAL',
            'container_': 'CRITICAL',
            'quantum_': 'CRITICAL',
            'apikey_': 'HIGH',
            'cicd_': 'HIGH',
            'sql_injection_': 'HIGH',
            'cmd_injection_': 'HIGH',
            'code_exec_': 'HIGH',
            'ssrf_': 'HIGH',
            'exfil_': 'HIGH',
            'supply_': 'HIGH',
            'edge_': 'HIGH',
            'xss_': 'MEDIUM',
            'path_traversal_': 'MEDIUM',
            'file_inclusion_': 'MEDIUM',
            'crypto_': 'MEDIUM',
            'social_': 'MEDIUM',
            'sensitive_': 'LOW',
        }
    
    def get_risk_level(self, pattern_name: str) -> str:
        """Returns risk level for pattern"""
        for prefix, level in self.risk_levels.items():
            if pattern_name.startswith(prefix):
                return level
        return 'MEDIUM'
    
    def check(self, text: str) -> Dict:
        """Checks text for malicious patterns"""
        findings = []
        
        for name, pattern in self.compiled.items():
            if match := pattern.search(text):
                findings.append({
                    'pattern': name,
                    'risk': self.get_risk_level(name),
                    'match': match.group(),
                    'position': match.span()
                })
        
        risk_counts = defaultdict(int)
        for finding in findings:
            risk_counts[finding['risk']] += 1
        
        return {
            'is_malicious': len(findings) > 0,
            'total_findings': len(findings),
            'risk_distribution': dict(risk_counts),
            'findings': findings,
            'highest_risk': max([f['risk'] for f in findings], 
                               default='NONE',
                               key=lambda x: ['LOW','MEDIUM','HIGH','CRITICAL'].index(x))
        }
    
    def scan_text(self, text: str) -> List[Dict]:
        """Lightweight scan that returns just findings list"""
        findings = []
        for name, regex in self.compiled.items():
            if match := regex.search(text):
                findings.append({
                    'pattern': name,
                    'risk': self.get_risk_level(name),
                    'match': match.group(),
                    'position': match.span()
                })
        return findings


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
        
        # FIXED: Security Patterns initialisieren
        self.security_patterns = SecurityPatterns2026()
        
        # FIXED: DNS Cache für Rebinding-Protection
        self.dns_cache = {}
        self.dns_cache_timeout = 300  # 5 minutes
        
        # Malicious Tor relays
        self.malicious_relays = config.get('malicious_relays', [])
        
        # Output Directory
        os.makedirs(self.output_dir, exist_ok=True)
        os.umask(0o077)
        
        if self.nuclear_mode:
            self.enable_nuclear_mode()
            
        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    # ========== FIXED SECURITY METHODS ==========
    
    def is_private_ip(self, ip_str: str) -> bool:
        """FIXED: Proper private IP detection"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False
    
    def resolve_with_rebinding_protection(self, hostname: str) -> Optional[str]:
        """NEW: DNS Resolution with rebinding protection"""
        cache_key = f"{hostname}_{int(time.time() / self.dns_cache_timeout)}"
        
        if cache_key in self.dns_cache:
            return self.dns_cache[cache_key]
        
        try:
            resolved_ip = socket.gethostbyname(hostname)
            
            # Check if private IP using ipaddress module
            ip_obj = ipaddress.ip_address(resolved_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                logger.critical(f"SSRF/REBINDING DETECTED: {hostname} points to {resolved_ip}")
                return None
            
            # Cache result
            self.dns_cache[cache_key] = resolved_ip
            return resolved_ip
            
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {hostname}: {e}")
            return None
        except ValueError:
            logger.error(f"Invalid IP address resolved for {hostname}")
            return None
    
    def check_onion_reachable(self, target):
        """Prüft Onion-Erreichbarkeit mit SOCKS5 Proxy"""
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        
        try:
            url = target if target.startswith(('http://', 'https://')) else f"http://{target}"
            response = requests.get(url, proxies=proxies, timeout=15)
            return response.status_code < 400
        except requests.exceptions.RequestException as e:
            logger.error(f"Onion target not reachable via SOCKS5 proxy: {e}")
            return False
    
    def check_domain_reachable(self, target=None):
        """FIXED: Proper SSRF protection with DNS Rebinding protection"""
        target = target or self.domain
        logger.info(f"[*] Checking if {target} is reachable...")
        
        try:
            if target.endswith('.onion'):
                return self.check_onion_reachable(target)
            
            # FIXED: DNS Rebinding Protection
            resolved_ip = self.resolve_with_rebinding_protection(target)
            if not resolved_ip:
                return False
            
            # Make request using resolved IP in Host header
            response = requests.get(
                f"http://{resolved_ip}",
                headers={'Host': target},
                timeout=10,
                allow_redirects=False
            )
            return response.status_code < 400
            
        except Exception as e:
            logger.error(f"Target not reachable: {e}")
            return False
    
    def check_malicious_traffic(self, payload: str) -> Tuple[bool, str]:
        """NEW: Malicious traffic detection using 2026 patterns"""
        result = self.security_patterns.check(payload)
        
        if result['is_malicious']:
            # Return highest risk finding
            top_finding = max(result['findings'], 
                            key=lambda x: ['LOW','MEDIUM','HIGH','CRITICAL'].index(x['risk']))
            return True, f"{top_finding['pattern']} ({top_finding['risk']})"
        
        return False, ""
    
    def log_suspicious_activity(self, source_ip: str, pattern: str, payload: str):
        """FIXED: Proper activity logging with thread safety"""
        with self.lock:
            self.suspicious_activity[source_ip] += 1
            
            logger.warning(f"[SUSPICIOUS] {source_ip} - Pattern: {pattern}")
            logger.debug(f"Payload preview: {payload[:100]}")
            
            # Trigger emergency scan if threshold exceeded
            if self.suspicious_activity[source_ip] >= self.alert_threshold:
                self.trigger_emergency_scan(source_ip)
    
    def emergency_scan_worker(self, suspicious_ip: str):
        """NEW: Emergency scan worker implementation"""
        logger.critical(f"[EMERGENCY SCAN] Investigating {suspicious_ip}")
        
        try:
            # Quick port scan
            cmd = ["nmap", "-T4", "-F", suspicious_ip]
            result = self.run_command(cmd, timeout=60)
            
            if result['success']:
                logger.info(f"Emergency scan complete for {suspicious_ip}")
                
                # Save results
                emergency_file = f"{self.output_dir}/emergency_{suspicious_ip}_{int(time.time())}.txt"
                with open(emergency_file, 'w') as f:
                    f.write(result['stdout'])
            
        except Exception as e:
            logger.error(f"Emergency scan failed: {e}")
    
    def run_command(self, cmd: List[str], timeout=300):
        """FIXED: Proper command sanitization - NO shell injection possible"""
        if self.nuclear_mode:
            timeout = timeout * 2
            resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 2 << 30))
            
        try:
            # FIXED: Pass list directly to subprocess, DON'T quote
            # subprocess.run with shell=False is safe from injection
            result = subprocess.run(
                cmd,  # List of strings, no shell expansion
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False  # CRITICAL: Never use shell=True
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

    # ========== ORIGINAL SCANNER METHODEN ==========

    def enable_nuclear_mode(self):
        """Aktiviert Nuclear-Modus für maximale Leistung"""
        logger.warning("!!! NUCLEAR MODE ACTIVE: APPLYING KERNEL TUNING !!!")
        
        if os.geteuid() == 0:
            try:
                subprocess.run(['sysctl', '-w', 'net.core.rmem_max=268435456'], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=4096'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            except Exception as e:
                logger.warning(f"Nuclear: Kernel tuning failed: {e}")
        
        # Remove soft limits for memory allocation
        try:
            resource.setrlimit(resource.RLIMIT_AS, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except Exception as e:
            logger.warning(f"Nuclear: Memory limit removal failed: {e}")

    def shutdown_handler(self, signum, frame):
        """Graceful shutdown mit Nuclear-Cleanup"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop_monitoring()
        
        if self.nuclear_mode and os.geteuid() == 0:
            try:
                subprocess.run(['sysctl', '-w', 'net.core.rmem_max=212992'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        sys.exit(0)
    
    def stop_monitoring(self):
        """Stops all monitoring activities"""
        self.monitoring_active = False
        logger.info("Monitoring stopped")

    def run_full_security_scan(self):
        """Koordiniert den vollständigen Sicherheitsscan (Nuclear Fusion)"""
        logger.info("[!!!] Starting Nuclear Fusion Scan [!!!]")
        
        target = self.domain or self.onion_address
        if not target:
            logger.error("No domain or onion address configured.")
            return None
        
        if not self.check_domain_reachable(target):
            logger.warning(f"Target {target} is unreachable. Skipping full scan.")
            self.scan_results = {'ports': {}, 'vulnerabilities': {}}
        else:
            self.comprehensive_port_scan(target)
            self.vulnerability_assessment(target)
        
        if TOR_AVAILABLE and (self.domain and self.domain.endswith('.onion')):
            self.manage_tor_circuits()
        
        report = self.generate_comprehensive_report()
        logger.info("[!!!] Nuclear Fusion Scan Complete [!!!]")
        return report

    def comprehensive_port_scan(self, target=None):
        """Port-Scan mit Nuclear-Optionen"""
        target = target or self.domain
        logger.info(f"[*] Comprehensive port scanning {target}...")
        
        port_results = {}
        nmap_flags = "-T5 --min-rate 5000" if self.nuclear_mode else "-T4"
        
        cmd = ["nmap"] + nmap_flags.split() + ["-sS", "-sV", "-p-", target]
        result = self.run_command(cmd, timeout=900 if self.nuclear_mode else 300)
        
        if result['success']:
            port_results['nmap_standard'] = {
                'output': result['stdout'],
                'ports': self._parse_nmap_ports(result['stdout'])
            }
        
        self.scan_results['ports'] = port_results
        return port_results
    
    def _parse_nmap_ports(self, nmap_output):
        """Analysiert die Nmap-Textausgabe und extrahiert offene Ports"""
        open_ports = []
        if not nmap_output:
            logger.warning("Nmap-Ausgabe ist leer oder der Scan ist fehlgeschlagen.")
            return []
        
        # Pattern: 80/tcp open http oder 80/udp open dns
        pattern = re.compile(r'(\d+)/(tcp|udp)\s+open\s+([\w-]+)')
        
        for line in nmap_output.split('\n'):
            match = pattern.search(line)
            if match:
                open_ports.append({
                    'port': int(match.group(1)),
                    'protocol': match.group(2),
                    'service': match.group(3)
                })
        
        logger.info(f"Nmap-Parsing abgeschlossen. {len(open_ports)} offene Ports gefunden.")
        return open_ports

    def trigger_emergency_scan(self, suspicious_ip):
        """Triggert Emergency Scan mit Anti-Loop"""
        logger.critical(f"EMERGENCY SCAN TRIGGERED for {suspicious_ip}")
        
        threading.Thread(
            target=self.emergency_scan_worker,
            args=(suspicious_ip,),
            daemon=True
        ).start()
        
        if random.random() < 0.7:
            self.renew_tor_circuit()

    def renew_tor_circuit(self):
        """Erneuert Tor Circuit mit Passwortunterstützung"""
        if not TOR_AVAILABLE:
            return
            
        try:
            controller = Controller.from_port(port=self.tor_control_port)
            
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
        
        monitor_interval = 60 if self.nuclear_mode else 300
        
        if SCAPY_AVAILABLE:
            traffic_thread = threading.Thread(target=self.monitor_traffic)
            traffic_thread.daemon = True
            traffic_thread.start()
        
        while self.monitoring_active:
            try:
                if self.domain and not self.check_domain_reachable(self.domain):
                    logger.warning(f"Domain {self.domain} health check failed")
                
                if self.onion_address and not self.check_onion_reachable(self.onion_address):
                    logger.warning(f"Onion {self.onion_address} health check failed")
                
                time.sleep(monitor_interval)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(10)

    def vulnerability_assessment(self, target=None):
        """Umfassende Vulnerability Assessment"""
        target = target or self.domain
        logger.info(f"[*] Vulnerability assessment for {target}...")
        
        vuln_results = {}
        
        # Nuclei mit critical,high severity
        nuclei_output = f"{self.output_dir}/nuclei_{target}_{int(time.time())}.txt"
        cmd = ["nuclei", "-u", f"http://{target}", "-o", nuclei_output, "-severity", "critical,high"]
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
        
        # OpenVAS scan
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
            cmd = ["openvas-cli", "-h", target]
            result = self.run_command(cmd, timeout=60)
            if result['success']:
                return "OpenVAS scan initiated"
            else:
                return "OpenVAS not available"
        except Exception as e:
            return f"OpenVAS error: {e}"

    def manage_tor_circuits(self):
        """Tor Circuit Management"""
        if not TOR_AVAILABLE:
            return
            
        try:
            controller = Controller.from_port(port=self.tor_control_port)
            
            if self.tor_password:
                controller.authenticate(password=self.tor_password)
            else:
                controller.authenticate()
            
            circuits = controller.get_circuits()
            
            for circuit in circuits:
                if circuit.status == 'BUILT':
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
                
                # Use scan_text for lightweight detection
                findings = self.security_patterns.scan_text(payload)
                
                if findings:
                    for finding in findings:
                        pattern_info = f"{finding['pattern']} ({finding['risk']})"
                        self.log_suspicious_activity(source_ip, pattern_info, payload)
                    
            except Exception as e:
                logger.debug(f"Packet processing error: {e}")

    def monitor_traffic(self):
        """Traffic Monitoring"""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, skipping traffic monitoring")
            return
            
        logger.info("Starting traffic monitoring...")
        
        try:
            sniff(
                filter="tcp and (port 80 or port 443 or port 9050 or port 9051)",
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda p: not self.monitoring_active
            )
        except PermissionError:
            logger.error("Traffic monitoring requires root/sudo privileges")
        except Exception as e:
            logger.error(f"Traffic monitoring error: {e}")

    def generate_comprehensive_report(self):
        """Generiert umfassenden Bericht"""
        timestamp = datetime.now().isoformat()
        
        report = {
            'scan_info': {
                'timestamp': timestamp,
                'domain': self.domain,
                'onion_address': self.onion_address,
                'scan_type': 'comprehensive',
                'nuclear_mode': self.nuclear_mode
            },
            'results': self.scan_results,
            'monitoring': {
                'suspicious_activity': dict(self.suspicious_activity),
                'total_incidents': sum(self.suspicious_activity.values())
            },
            'summary': self._generate_executive_summary()
        }
        
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
        
        total_incidents = sum(self.suspicious_activity.values())
        if total_incidents > 20:
            summary['risk_level'] = 'HIGH'
            summary['critical_issues'].append(f"Hohe Anzahl verdächtiger Aktivitäten ({total_incidents})")
        
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
        "nuclear_mode": False
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
    
    if config.get('nuclear_mode'):
        print("\n" + "!"*60)
        print("!! NUCLEAR MODE ACTIVATED - EXPECT SYSTEM INSTABILITY !!")
        print("!!    Target servers may experience disruption       !!")
        print("!"*60 + "\n")
        time.sleep(3)
    
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
