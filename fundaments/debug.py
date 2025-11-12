import os
import sys
import importlib.util
import datetime
import logging
from logging.handlers import RotatingFileHandler

class PyFundamentsDebug:
    """
    Debug-Klasse für PyFundaments.
    Liest ENV-Variablen und konfiguriert Logging.
    Gibt Startup-Infos aus, wenn PYFUNDAMENTS_DEBUG=true.
    """

    def __init__(self):
        # Debug aktivieren mit ENV VAR (default: False)
        self.enabled = os.getenv("PYFUNDAMENTS_DEBUG", "false").lower() == "true"

        # Log-Level aus ENV lesen, default INFO
        log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
        self.log_level = getattr(logging, log_level_str, logging.INFO)

        # Logs in /tmp oder stdout? (default False)
        self.log_to_tmp = os.getenv("LOG_TO_TMP", "false").lower() == "true"

        # Öffentliches Logging an/aus (default True)
        self.enable_public_logs = os.getenv("ENABLE_PUBLIC_LOGS", "true").lower() == "true"

        # Logger Setup
        self.logger = logging.getLogger('pyfundaments_debug')
        self._setup_logger()

    def _setup_logger(self):
        if not self.enable_public_logs:
            # Nur kritische Fehler im Log, wenn deaktiviert
            logging.basicConfig(level=logging.CRITICAL)
            return

        handlers = []
        if self.log_to_tmp:
            log_file = '/tmp/pyfundaments_debug.log'
            file_handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=3)
            handlers.append(file_handler)
        handlers.append(logging.StreamHandler(sys.stdout))

        logging.basicConfig(
            level=self.log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers
        )

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"==== PYFUNDAMENTS DEBUG STARTUP ({datetime.datetime.now()}) ====")
        self.logger.info(f"Python version: {sys.version}")
        self.logger.info(f"CWD: {os.getcwd()}")
        self.logger.info(f"sys.path: {sys.path}")

        fund_dir = "fundaments"
        self.logger.info(f"fundaments exists: {os.path.isdir(fund_dir)}")

        required_files = [
            "__init__.py",
            "access_control.py",
            "postgresql.py",
            "config_handler.py",
            "security.py",
            "user_handler.py",
            "encryption.py"
        ]

        for file in required_files:
            path = os.path.join(fund_dir, file)
            exists = os.path.isfile(path)
            readable = os.access(path, os.R_OK)
            self.logger.info(f"{file} exists: {exists} | readable: {readable}")

        if os.path.isdir(fund_dir):
            self.logger.info(f"Listing fundaments contents: {os.listdir(fund_dir)}")
        else:
            self.logger.warning("fundaments folder not found.")

        spec = importlib.util.find_spec("fundaments")
        self.logger.info(f"fundaments importable: {spec is not None}")

        conflicts = [mod for mod in sys.modules if mod == "fundaments"]
        self.logger.info(f"Name conflict in sys.modules: {conflicts}")

        self.logger.info("==== PYFUNDAMENTS DEBUG END ====")
