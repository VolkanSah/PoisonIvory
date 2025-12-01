# app/tool_manager.py
# Kapselt die Ausführung aller externen Security-Binaries (Nmap, Nuclei, SSLScan).
# Stellt eine sichere und asynchrone Schnittstelle für Subprozess-Aufrufe bereit.

import logging
import asyncio
import os
from typing import Dict, Any, Optional

logger = logging.getLogger('ToolManager')

class ToolManager:
    """
    Verwaltet und führt externe Sicherheitstools als asynchrone Subprozesse aus.
    Stellt sicher, dass die Tools korrekt konfiguriert und erreichbar sind.
    """
    
    def __init__(self, config: Any):
        """
        Initialisiert den Dienst und lädt die Pfade zu den Tools.
        
        Args:
            config: Der injizierte Konfigurationsdienst (Fundament).
        """
        self.config = config
        # Pfade aus der Konfiguration laden. Fallbacks sind wichtig.!!!
        self.tool_paths = {
            # Red
            "nmap": config.get("TOOL_NMAP_PATH", "/usr/bin/nmap"),
            "nuclei": config.get("TOOL_NUCLEI_PATH", "/usr/bin/nuclei"),
            "sslscan": config.get("TOOL_SSLSCAN_PATH", "/usr/bin/sslscan"),
            # Blue
            "suricata": config.get("TOOL_SURICATA_PATH", "/usr/bin/suricata"),
            "tcpdump": config.get("TOOL_TCPDUMP_PATH", "/usr/sbin/tcpdump"),
            "yara": config.get("TOOL_YARA_PATH", "/usr/bin/yara"),
            # Your needs below
            # ->
        }
        
        self._validate_tools()

    def _validate_tools(self):
        """Prüft, ob die konfigurierten Tools im Dateisystem existieren."""
        for name, path in self.tool_paths.items():
            if not os.path.exists(path):
                logger.error(f"Tool '{name}' not found at configured path: {path}. Tool will be unavailable.")
                self.tool_paths[name] = None # Deaktiviere das Tool

    
    async def execute_tool(self, tool_name: str, target: str, args: Optional[list] = None) -> Dict[str, Any]:
        """
        Führt ein externes Tool asynchron als Subprozess aus.
        
        Args:
            tool_name: Der Name des Tools (z.B. 'nmap', 'nuclei').
            target: Das Ziel (Domain oder IP).
            args: Optionale Argumente als Liste (z.B. ['-sV', '-p-']).
            
        Returns:
            Ein Dictionary mit 'output', 'error' und 'return_code'.
        """
        tool_path = self.tool_paths.get(tool_name)
        if not tool_path:
            return {"error": f"Tool '{tool_name}' is not configured or available."}
        
        command_args = [target]
        if args:
            command_args.extend(args)
            
        full_command = [tool_path] + command_args
        logger.info(f"Executing command: {' '.join(full_command)}")
        
        try:
            # Erstellt und führt den Subprozess asynchron aus
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wartet auf die Beendigung des Prozesses und liest stdout/stderr
            stdout, stderr = await process.communicate()
            return_code = process.returncode

            # Dekodiert die Ausgabe und den Fehler
            output = stdout.decode().strip()
            error = stderr.decode().strip()

            if return_code != 0 and error:
                logger.warning(f"Tool '{tool_name}' failed with code {return_code}. Error: {error}")
            
            return {
                "output": output,
                "error": error,
                "return_code": return_code,
            }

        except FileNotFoundError:
            logger.error(f"Subprocess failed: Tool '{tool_name}' not found at {tool_path}")
            return {"error": f"Tool '{tool_name}' binary not found.", "return_code": 127}
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            return {"error": f"Execution exception: {e}", "return_code": -1}
