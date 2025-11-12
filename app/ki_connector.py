# app/ki_connector.py
# Modul zur Kapselung und Orchestrierung aller LLM-Interaktionen.
# Implementiert Provider-Routing und Retry-Logik (Exponential Backoff).

import logging
import asyncio
import json
import time
from typing import Dict, Any, Optional
import requests
from requests.exceptions import RequestException

logger = logging.getLogger('KIConnector')

# --- KONFIGURATION UND KONSTANTEN ---
# Diese sollten idealerweise über den Fundaments Config Service geladen werden.
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
OPENROUTER_API_URL = "https://api.openrouter.ai/api/v1/chat/completions"
MAX_RETRIES = 3
INITIAL_DELAY = 1.0  # Sekunden

class AIConnector:
    """
    Stellt eine Provider-agnostische Schnittstelle für KI-Funktionen bereit.
    Übernimmt die Zuständigkeit für API-Schlüssel, Routing, und Fehlermanagement.
    """
    
    def __init__(self, config: Any):
        """
        Initialisiert den Connector und lädt die API-Schlüssel.
        
        Args:
            config: Der injizierte Konfigurationsdienst (Fundament).
        """
        self.config = config
        self.gemini_key = config.get("GEMINI_API_KEY")
        self.openrouter_key = config.get("OPENROUTER_API_KEY")
        
        # Bestimmt das Standardmodell für die Bug-Recherche (z.B. gemini-2.5-pro)
        self.bug_research_model = config.get("BUG_RESEARCH_MODEL", "gemini-2.5-flash")
        
        # Stellt sicher, dass mindestens ein Provider konfiguriert ist, wenn der Connector geladen wird
        if not self.gemini_key and not self.openrouter_key:
            logger.error("No API keys found for Gemini or OpenRouter. KI operations will fail.")


    def _determine_provider(self, model_name: str) -> str:
        """Bestimmt, welcher API-Provider für das gegebene Modell zuständig ist."""
        if "gemini" in model_name.lower():
            return "gemini"
        if any(p in model_name.lower() for p in ["mistral", "llama", "gemma"]):
            return "openrouter" # OpenRouter hostet viele gängige Modelle
        
        # Fallback auf den Standard-KI-Provider aus der Konfiguration
        default_provider = self.config.get("DEFAULT_AI_PROVIDER", "gemini")
        return default_provider.lower()


    async def _call_api(self, model_name: str, prompt: str, is_json: bool = False) -> str:
        """
        Zentrale Funktion für alle LLM-API-Aufrufe mit Exponential Backoff.
        
        Args:
            model_name: Der Name des zu verwendenden LLM.
            prompt: Der Text-Prompt.
            is_json: Ob eine strukturierte JSON-Antwort erwartet wird.
            
        Returns:
            Die rohe Text- oder JSON-Antwort der API.
        """
        
        provider = self._determine_provider(model_name)
        
        # Wählt die Implementierung
        if provider == "gemini":
            caller_func = self._call_gemini_api
            api_key = self.gemini_key
        elif provider == "openrouter":
            caller_func = self._call_openrouter_api
            api_key = self.openrouter_key
        else:
            raise ValueError(f"Unknown or unsupported KI provider: {provider}")

        # Prüft auf fehlenden Schlüssel VOR dem Retry-Zyklus
        if not api_key:
            logger.error(f"API key is missing for provider {provider}.")
            return json.dumps({"error": f"API Key missing for {provider}"})
            
        delay = INITIAL_DELAY
        for attempt in range(MAX_RETRIES):
            try:
                # Führt den spezifischen API-Aufruf aus (Delegation)
                response_text = await caller_func(
                    model_name=model_name, 
                    prompt=prompt, 
                    api_key=api_key, 
                    is_json=is_json
                )
                return response_text # Erfolg
                
            except RequestException as e:
                logger.warning(f"API Call failed (Attempt {attempt + 1}/{MAX_RETRIES}) with error: {e}")
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"All {MAX_RETRIES} attempts failed for model {model_name}.")
                    raise
                
                logger.info(f"Retrying in {delay:.2f} seconds...")
                await asyncio.sleep(delay)
                delay *= 2.0 # Exponential Backoff
                
            except Exception as e:
                # Für andere Fehler (z.B. Parsing-Fehler)
                logger.error(f"Unrecoverable error during API call: {e}")
                raise


    async def _call_gemini_api(self, model_name: str, prompt: str, api_key: str, is_json: bool) -> str:
        """Interne Methode zur Interaktion mit der Google Gemini API."""
        
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": api_key
        }
        
        # Konfiguriert das JSON-Schema, wenn eine strukturierte Antwort gewünscht ist
        response_config = {}
        if is_json:
            response_config = {
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "OBJECT",
                    "properties": {
                        "vulnerability_id": {"type": "STRING"},
                        "cms_version_affected": {"type": "STRING"},
                        "summary": {"type": "STRING"}
                    }
                }
            }
            
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "tools": [{"google_search": {}}], # Aktiviert Google Search Grounding
            "config": response_config
        }
        
        url = GEMINI_API_URL.format(model=model_name)
        
        # Führt den synchronen HTTP-Call in einem Thread aus (da Python's 'requests' nicht asyncio-nativ ist)
        response = await asyncio.to_thread(
            requests.post, 
            url, 
            headers=headers, 
            json=payload, 
            timeout=30
        )
        response.raise_for_status() # Löst RequestException für 4xx/5xx aus

        result = response.json()
        
        # Extrahiert den Text aus der Gemini-Struktur
        try:
            return result["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            logger.error(f"Failed to parse Gemini response structure: {result}")
            raise ValueError("Invalid response structure from Gemini API.")


    async def _call_openrouter_api(self, model_name: str, prompt: str, api_key: str, is_json: bool) -> str:
        """Interne Methode zur Interaktion mit der OpenRouter API."""
        
        # OpenRouter erfordert ein leicht abweichendes Format
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "https://poisonivory-scanner.com" # Wichtig für OpenRouter
        }
        
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"} if is_json else None, # JSON-Format-Anforderung
            "stream": False
        }

        # Führt den synchronen HTTP-Call in einem Thread aus
        response = await asyncio.to_thread(
            requests.post, 
            OPENROUTER_API_URL, 
            headers=headers, 
            json=payload, 
            timeout=30
        )
        response.raise_for_status()

        result = response.json()
        
        # Extrahiert den Text aus der OpenRouter/OpenAI-ähnlichen Struktur
        try:
            return result["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            logger.error(f"Failed to parse OpenRouter response structure: {result}")
            raise ValueError("Invalid response structure from OpenRouter API.")


    # --- PUBLIC POISONIVORY INTERFACE ---

    async def research_bugs(self, query: str) -> Dict[str, Any]:
        """
        Führt eine strukturierte, web-gestützte Recherche nach neuen Schwachstellen durch.
        Erwartet immer eine JSON-Antwort.
        """
        model_to_use = self.bug_research_model
        
        system_prompt = (
            "You are a specialized security analyst (PoisonIvory) focusing on CMS vulnerabilities. "
            "Your task is to search the web for the latest, unpatched vulnerabilities (CVE, Zero-Days) "
            f"for technologies related to the query: '{query}'. "
            "Respond ONLY with a valid JSON array of findings. Do not add any conversational text."
        )
        
        prompt = f"{system_prompt} Search Query: {query}"
        
        logger.info(f"Starting bug research using model: {model_to_use} (JSON output expected).")
        
        try:
            # API Call erwartet eine strukturierte (JSON) Antwort
            raw_json_response = await self._call_api(model_to_use, prompt, is_json=True)
            return json.loads(raw_json_response)
        except Exception as e:
            logger.error(f"KI Bug Research failed: {e}")
            return {"error": "KI Research failed", "details": str(e)}


    async def run_workflow(self, workflow_name: str, context_data: Dict[str, Any]) -> str:
        """
        Führt einen allgemeinen KI-Workflow aus (z.B. Zusammenfassung, Maßnahmenkatalog).
        Erwartet eine Freitext-Antwort.
        """
        model_to_use = self.config.get("REPORT_ANALYSIS_MODEL", "gemini-2.5-flash")

        if workflow_name == "reporting_workflow":
            prompt = (
                "You are generating a final security report summary for the PoisonIvory scanner. "
                "Analyze the following scan results and bug findings. Provide a concise, professional "
                "summary of the 3 most critical issues and the top 3 actionable recommendations."
                f"\n\nContext Data:\n{json.dumps(context_data, indent=2)}"
            )
        else:
            raise ValueError(f"Unknown KI workflow: {workflow_name}")

        logger.info(f"Starting workflow '{workflow_name}' using model: {model_to_use}.")
        
        try:
            # API Call erwartet eine Freitext-Antwort
            return await self._call_api(model_to_use, prompt, is_json=False)
        except Exception as e:
            logger.error(f"KI Workflow '{workflow_name}' failed: {e}")
            return f"Error: Failed to execute AI analysis workflow ({e})."
