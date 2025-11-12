# app/core.py
# Die eigentliche Kernlogik (Scan-Engine) von PoisonIvory 2.0.
# Orchestriert externe Tools, KI-Services und sammelt die Ergebnisse.

import logging
import asyncio
from typing import Dict, Any, Optional

logger = logging.getLogger('CoreService')

class PoisonIvoryCore:
    """
    Die Hauptklasse der Scan-Engine.
    Sie akzeptiert alle notwendigen Fundament-Services (Konfiguration, Tools, etc.) 
    während der Initialisierung durch main.py.
    """
    
    def __init__(self, config: Any, io_handler: Any):
        """
        Initialisiert den Core Service. Nur die permanent benötigten Fundamente 
        (Config, I/O) werden hier benötigt. Optionale Dienste (KI, Tools) 
        werden erst zur Laufzeit in run_full_security_scan injiziert.
        
        Args:
            config: Der injizierte Konfigurationsdienst.
            io_handler: Der injizierte I/O-Handler (zum Laden von Vorlagen, etc.).
        """
        self.config = config
        self.io_handler = io_handler
        self.scan_config = self.config.get("SCAN_SETTINGS", {})
        logger.info("PoisonIvory Core initialized. Ready to accept scan commands.")


    async def _run_basic_scan(self, domain: str, tool_manager: Any) -> Dict[str, Any]:
        """
        Führt den eigentlichen, tool-basierten Sicherheitsscan durch.
        Nutzt den injizierten ToolManager für alle externen Aufrufe.
        """
        logger.info(f"Starting basic tool-based scan on {domain}...")
        results = {"technologies": [], "vulnerabilities": [], "summary": "Basic scan complete."}

        # --- 1. Nmap Scan (Port- und Service-Erkennung) ---
        nmap_args = self.scan_config.get("NMAP_ARGS", ["-sS", "-sV", "-p21,22,80,443,8080"])
        nmap_result = await tool_manager.execute_tool("nmap", domain, nmap_args)
        
        if nmap_result["return_code"] == 0:
            logger.info("Nmap scan successful. Analyzing output...")
            # Real-world: Hier würde die Nmap-Ausgabe geparst werden
            results["technologies"].append({"tool": "Nmap", "output": nmap_result["output"][:100] + "..."})
        else:
            logger.error(f"Nmap failed: {nmap_result['error']}")
            
        # --- 2. Nuclei Scan (Template-basierte Schwachstellenprüfung) ---
        # Nuclei wird oft als obligatorisch betrachtet
        nuclei_args = self.scan_config.get("NUCLEI_ARGS", ["-passive", "-t", "default-templates"])
        nuclei_result = await tool_manager.execute_tool("nuclei", domain, nuclei_args)
        
        if nuclei_result["output"]:
            logger.warning("Nuclei found potential issues. Passing to KI for analysis.")
            results["vulnerabilities"].append({"tool": "Nuclei", "raw_findings": nuclei_result["output"]})
        else:
            logger.info("Nuclei completed with no immediate findings.")
            
        return results


    async def run_full_security_scan(
        self, 
        domain: str, 
        tool_manager: Any,
        ki_connector: Optional[Any] = None 
    ) -> Dict[str, Any]:
        """
        Der Haupt-Scan-Workflow, der von app.py aufgerufen wird.
        
        Args:
            domain: Das Ziel.
            tool_manager: Der injizierte Tool Manager (obligatorisch).
            ki_connector: Der injizierte KI Connector (optional).
            
        Returns:
            Der fertige Scan-Report.
        """
        final_report = {"target": domain, "timestamp": self.io_handler.get_timestamp()}
        
        try:
            # === 1. BASIS-SCAN (Immer obligatorisch) ===
            scan_results = await self._run_basic_scan(domain, tool_manager)
            final_report.update(scan_results)

            # === 2. KI-AUGMENTIERUNG (Optional) ===
            if ki_connector:
                logger.info("[+] Starting AI augmentation phase.")
                
                # A. KI-gestützte Bug-Recherche
                tech_list = ", ".join([t.get('name', 'unknown') for t in scan_results['technologies']])
                bug_query = f"Latest vulnerabilities for {tech_list}."
                
                new_bugs = await ki_connector.research_bugs(bug_query)
                final_report["ki_research_bugs"] = new_bugs
                logger.info(f"KI found {len(new_bugs.get('vulnerabilities', []))} new potential issues.")
                
                # B. KI-gestützte Ergebnis-Analyse
                workflow_data = {
                    "basic_scan_results": scan_results,
                    "ki_research_bugs": new_bugs,
                }
                ai_summary = await ki_connector.run_workflow("reporting_workflow", workflow_data)
                final_report["ai_summary"] = ai_summary
                
            else:
                final_report["ai_summary"] = "AI analysis was disabled."
                
            logger.info("Full security scan and analysis complete.")
            return final_report
            
        except Exception as e:
            logger.critical(f"A critical error occurred during the scan: {e}")
            final_report["error"] = f"Critical Scan Failure: {str(e)}"
            return final_report

```eof

---

### Was diese Architektur so robust macht:

1.  **Explizite Übergabe (Injection):**
    * Die `PoisonIvoryCore` wird in `main.py` mit **Basisdiensten** (`config`, `io_handler`) initialisiert.
    * Die kritischen, **dynamischen Dienste** (`tool_manager`, `ki_connector`) werden erst zur Laufzeit in `run_full_security_scan` injiziert. Das zwingt die `app.py` (Orchestrierung) dazu, sicherzustellen, dass sie da sind, wenn sie gebraucht werden.
2.  **Klarer Workflow:** Der Scan ist in logische, sequenzielle Schritte unterteilt (`_run_basic_scan`, `KI-Bug-Recherche`, `KI-Analyse`).
3.  **Abstraktion:** Die Core-Logik weiß nicht, **wie** der `ToolManager` Nmap aufruft oder **wie** der `KIConnector` mit Google spricht. Sie weiß nur, **was** sie von ihnen verlangen kann (`execute_tool`, `research_bugs`).
4.  **Asynchrone Ausführung:** Durch die Nutzung von `await` für alle I/O-Operationen (externe Tools, KI-APIs) bleibt die Anwendung reaktionsschnell und kann mehrere Aufgaben gleichzeitig ausführen (wenn Sie dies später implementieren möchten).
5.  **Optionale Features:** Der KI-Augmentierungs-Teil ist in einem klaren `if ki_connector:` Block gekapselt, was die **Graceful Degradation** garantiert, falls der API-Schlüssel fehlt.

```
