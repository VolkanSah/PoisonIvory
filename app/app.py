# This is the orchestration layer (CLI entry point) of PoisonIvory 2.0.
# It uses services injected by the PyFundaments main.py.

import asyncio
import logging
import sys
from typing import Dict, Any, Optional

logger = get_logger('Application') # Nutzung des kürzeren Loggernamens 'Application'

# Dummy imports for conceptual clarity. In a real PyFundaments structure, 
# these core components would likely be injected as services if they are complex.
# For simplicity, we assume they are either injected or handled by the Core service.

async def _handle_scan_command(fundaments: Dict[str, Any], core_service: Any):
    """Handles the main 'scan' command, including ethical verification and AI augmentation."""
    
    config = fundaments["config"]
    domain = config.get("TARGET_DOMAIN") # Annahme: Domain wird über Config/CLI übergeben
    
    # === 1. ETHICAL GATE CHECK (Mandatory for 'scan') ===
    ethical_gates = fundaments.get("ethical_gates")
    if not ethical_gates:
        logger.critical("Ethical Gates service not loaded. Cannot run aggressive 'scan' command.")
        return

    logger.info(f"[*] Starting mandatory ownership verification for {domain}...")
    
    if not await ethical_gates.verify_ownership(domain):
        logger.critical("SCAN ABORTED. Server ownership verification failed. Check documentation.")
        sys.exit(1)

    logger.info("[*] Ownership successfully verified. Proceeding with scan.")
    
    # === 2. TOOL MANAGER CHECK (Mandatory for 'scan') ===
    tool_manager = fundaments.get("tool_manager")
    if not tool_manager:
        logger.critical("Tool Manager service is mandatory for scanning but is not loaded. Exiting.")
        sys.exit(1)
    
    # === 3. AI AUGMENTATION INJECTION (Optional) ===
    ki_connector = fundaments.get("ki_connector")
    
    if ki_connector:
        logger.info("[*] AI Augmentation active (Research, Workflow Analysis).")
        # Inject both KI Connector and Tool Manager into the Core function
        report = await core_service.run_full_security_scan(
            domain=domain, 
            ki_connector=ki_connector,
            tool_manager=tool_manager
        )
    else:
        logger.warning("[!] AI Connector not loaded (Missing API key). Running standard scan.")
        report = await core_service.run_full_security_scan(
            domain=domain,
            tool_manager=tool_manager
        )

    # 4. Report-Ausgabe (Delegiert an Core, z.B. JSON/Markdown Export)
    if report:
        logger.info("Scan and analysis complete.")
        # Beispiel für einen weiteren Fundament-Dienst, der den Report speichert
        io_handler = fundaments.get("io_handler")
        if io_handler:
            # Annahme: Der Report-Speicherort ist in der Konfiguration definiert
            report_path = config.get("REPORT_OUTPUT_PATH", "./reports") 
            io_handler.save_report(report, path=report_path)
            logger.info(f"Report saved to {report_path}")
        else:
            print("\n--- Final Report (IO Handler not loaded) ---\n")
            # Zeigt den KI-Summary oder den gesamten Report
            print(report.get("ai_summary", report))


async def start_application(fundaments: Dict[str, Any]):
    """
    The main entry point for the PoisonIvory application logic.
    It orchestrates the execution flow based on the command and available fundaments.
    """
    
    # === 1. CORE SERVICE AND METADATA EXTRACTION ===
    config_service = fundaments["config"]
    core_service = fundaments.get("poisonivory_core") # Die Hauptlogik-Klasse
    
    APP_NAME = config_service.get("APP_NAME", "PoisonIvory")
    APP_VERSION = config_service.get("APP_VERSION", "2.0.0-dev")
    
    logger.info(f"{APP_NAME} v{APP_VERSION} Application starting...") # Dynamische Ausgabe
    
    if not core_service:
        logger.critical("PoisonIvory Core Service is missing or failed to initialize. Exiting.")
        sys.exit(1)

    # Annahme: Der Hauptbefehl (z.B. 'scan', 'monitor', 'help') wird über die Konfiguration oder CLI geparst.
    command = config_service.get("CLI_COMMAND", "help").lower()
    
    # --- 2. COMMAND DISPATCH ---
    
    if command == "scan":
        # Prüfung auf benötigten Services (Ethical Gates & Tool Manager)
        if not fundaments.get("ethical_gates"):
            logger.critical("Cannot run 'scan' command: 'ethical_gates' fundament service is not available.")
            return
        if not fundaments.get("tool_manager"): # NEUE PRÜFUNG HIER
            logger.critical("Cannot run 'scan' command: 'tool_manager' fundament service is not available.")
            return

        await _handle_scan_command(fundaments, core_service)
        
    elif command == "monitor":
        # Monitoring erfordert typischerweise eine Datenbank oder einen Event-Handler
        db_service = fundaments.get("db")
        if db_service:
            logger.info("Starting passive monitoring mode with DB persistence...")
            # await core_service.run_monitor_mode(db_service)
        else:
            logger.warning("DB Service not available. Monitoring will be non-persistent.")
            # await core_service.run_monitor_mode()
        
    elif command == "report":
        # Report-Generation ohne aktiven Scan.
        logger.info("Generating reports from previous logs/DB entries...")
        
    elif command == "help":
        print(f"\n{APP_NAME} v{APP_VERSION} - Available commands: scan, monitor, report.")
        
    else:
        logger.error(f"Unknown command: {command}")
    
    logger.info("Application tasks finished successfully.")


# ----------------------------------------------------------------------
# Standard PyFundaments/Sentinel Block - DO NOT MODIFY
# (Sichert die Testbarkeit des Moduls)
if __name__ == '__main__':
    # HACK: Define simple get_logger function for standalone testing
    def get_logger(name):
        _logger = logging.getLogger(name)
        _logger.setLevel(logging.DEBUG)
        if not _logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s: %(message)s'))
            _logger.addHandler(handler)
        return _logger
    
    logger = get_logger('Application')
    
    print("WARNING: Running app.py directly. Fundament modules might not be correctly initialized.")
    print("Please run 'python main.py' instead for proper initialization.")
    
    # For testing purposes, create a minimal dummy fundaments dict
    class DummyConfig:
        def get(self, key, default=None):
            if key == "TARGET_DOMAIN": return "test.domain.com"
            if key == "CLI_COMMAND": return "scan"
            if key == "APP_NAME": return "TestIvory"
            if key == "APP_VERSION": return "0.9.9-test"
            return default

    class DummyCore:
        # NEU: Signature angepasst, um tool_manager zu akzeptieren
        async def run_full_security_scan(self, domain, ki_connector=None, tool_manager=None): 
            logger.info(f"[DummyCore] Simulating scan on {domain}. KI active: {bool(ki_connector)}, Tools active: {bool(tool_manager)}")
            return {"status": "ok", "summary": "Simulated scan complete."}
    
    class DummyGates:
        async def verify_ownership(self, domain):
            logger.info(f"[DummyGates] Simulating ownership verification for {domain} (Success).")
            return True
            
    class DummyIO:
        def save_report(self, report, path):
            logger.info(f"[DummyIO] Report saved to simulated path {path}.")

    class DummyToolManager: # NEU: Dummy Tool Manager für Tests
        async def execute_tool(self, tool_name: str, target: str, args: Optional[list] = None) -> Dict[str, Any]:
            logger.info(f"[DummyTools] Simulating tool execution: {tool_name} on {target}.")
            return {"output": "Simulated scan result.", "error": "", "return_code": 0}

    test_fundaments = {
        "config": DummyConfig(),
        "poisonivory_core": DummyCore(),
        "ethical_gates": DummyGates(), # Obligatorischer Dienst
        "tool_manager": DummyToolManager(), # Obligatorischer Dienst
        "ki_connector": "DummyKI",    # Optionaler Dienst, der geladen ist
        "io_handler": DummyIO()       # Optionaler Dienst, der geladen ist
    }
    
    # Testfall 1: Voll funktionsfähig
    asyncio.run(start_application(test_fundaments))
    
    # Testfall 2: KI und IO fehlen (simuliert fehlende API-Keys)
    logger.info("\n--- Running Test Case 2 (Missing KI/IO) ---")
    test_fundaments_minimal = test_fundaments.copy()
    test_fundaments_minimal.pop("ki_connector")
    test_fundaments_minimal.pop("io_handler")
    asyncio.run(start_application(test_fundaments_minimal))
