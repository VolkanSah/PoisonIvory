import hashlib, uuid, google.generativeai as genai

class CMSSecurityMonitor:
    def __init__(self, config):
        self.config = config
        self.domain = config.get('domain')
        self.google_api_key = config.get('google_api_key')
        self.scan_results = {}
        # ... restliche Initialisierung wie bisher ...
        
    # === Gemini / Google AI ===
    def call_gemini_api(self, prompt_text, model_name="gemini-1.5-pro-latest", temperature=0.7, max_tokens=4096):
        try:
            genai.configure(api_key=self.google_api_key)
            model = genai.GenerativeModel(model_name=model_name)
            response = model.generate_content(
                prompt_text,
                generation_config=genai.types.GenerationConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens
                )
            )
            if response.candidates and response.candidates[0].content:
                return response.text
            else:
                return "Keine gültige Antwort von Gemini erhalten"
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return None

    # === Bug Research ===
    def research_new_bugs(self, query):
        prompt = f"Suche nach den neuesten Schwachstellen zu: {query} und gib Name, CVE, Beschreibung."
        return self.call_gemini_api(prompt)  # optional JSON parsing nach Bedarf

    # === AI Workflow ===
    def run_ai_workflow(self, workflow_file, data):
        try:
            with open(workflow_file, 'r') as f:
                workflow = json.load(f)
            prompt = workflow['prompt_template'].format(**data)
            return self.call_gemini_api(prompt, model_name=workflow.get('model', 'gemini-1.5-pro-latest'))
        except Exception as e:
            logger.error(f"Workflow error: {e}")
            return None

    # === Server-Verifizierung ===
    def generate_verification_token(self):
        return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()

    def verify_server_ownership(self, target_domain):
        token = self.generate_verification_token()
        verification_url = f"http://{target_domain}/poisonivory_verification.txt"
        print(f"\n[!] VERIFIZIERUNG ERFORDERLICH [!]")
        print(f"Bitte erstelle 'poisonivory_verification.txt' mit Token:\n{token}\n")
        input("ENTER zum Starten der Verifizierung...")
        try:
            response = requests.get(verification_url, timeout=10)
            if response.status_code == 200 and response.text.strip() == token:
                logger.info(f"Server {target_domain} verifiziert")
                return True
            else:
                logger.error("Verifizierung fehlgeschlagen")
                return False
        except Exception as e:
            logger.error(f"Verbindung fehlgeschlagen: {e}")
            return False

    # === Full Scan Upgrade ===
    def run_full_security_scan(self):
        if not self.verify_server_ownership(self.domain):
            logger.critical("Scan abgebrochen: Server nicht verifiziert")
            return None

        # hier kommt dein vorhandener Scan-Code
        self.scan_results['vulnerabilities'] = self.vulnerability_assessment()

        # Neue Bugs & AI Workflow
        new_bugs = self.research_new_bugs("CMS Schwachstellen der letzten 7 Tage")
        workflow_data = {'scan_results': self.scan_results, 'new_bugs': new_bugs}
        ai_summary = self.run_ai_workflow('reporting_workflow.json', workflow_data)
        self.scan_results['ai_summary'] = ai_summary
        return self.scan_results
