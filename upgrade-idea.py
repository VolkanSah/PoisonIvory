# sorry soon! so it will be more secure, cause 
# Research new Bugs
def research_new_bugs(self, query):
        """
        Recherchiert neue Sicherheitslücken im Internet mit der Gemini API.
        """
        logger.info(f"[*] Starting AI research for new bugs with query: '{query}'...")
        try:
            model = genai.GenerativeModel('gemini-1.5-pro-latest')
            prompt = f"""
            Suche nach den neuesten und kritischsten Sicherheitslücken und Exploits für CMS-Systeme und Server-Software, die in den letzten 7 Tagen gemeldet wurden. Gib die Ergebnisse in einer strukturierten Liste zurück, die den Namen der Schwachstelle, die CVE-Nummer (falls vorhanden) und eine kurze Beschreibung enthält.

            Suchbegriffe: {query}
            
            Format:
            [
              {{
                "name": "Schwachstellen-Name",
                "cve": "CVE-JAHR-NUMMER",
                "description": "Kurze Beschreibung der Schwachstelle."
              }}
            ]
            """
            response = model.generate_content(prompt)
            new_vulnerabilities = json.loads(response.text)
            
            logger.info(f"AI research completed. Found {len(new_vulnerabilities)} new vulnerabilities.")
            return new_vulnerabilities
        except Exception as e:
            logger.error(f"AI research failed: {e}")
            return []



