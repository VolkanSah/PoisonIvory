# PyFundaments: A Secure Python Architecture
# Copyright 2008-2025 - Volkan Kücükbudak
# Apache License V. 2
# Repo: https://github.com/VolkanSah/PyFundaments
# fundaments/security.py
# A central security manager that orchestrates core security functions.
# This class acts as a single, trusted interface for the application to
# interact with all underlying security fundamentals.

import logging
from typing import Dict, Any, Optional

# VORHER: Diese direkten Imports sind überflüssig,
# da die Instanzen der Klassen über den 'services'-Dictionary
# im __init__-Konstruktor übergeben werden.
# Sie sind auch nicht für die Typisierung notwendig,
# da wir 'Optional[ClassName]' verwenden, was ausreicht.
# from fundaments.encryption import Encryption
# from fundaments.access_control import AccessControl
# from fundaments.postgresql import execute_secured_query
# from fundaments.user_handler import UserHandler

logger = logging.getLogger('security')

class Security:
    def __init__(self, services: Dict[str, Any]):
        # VORHER: Hier werden die Instanzen aus dem übergebenen Dictionary entnommen.
        self.user_handler: Optional[UserHandler] = services.get("user_handler")
        self.access_control: Optional[AccessControl] = services.get("access_control")
        self.encryption: Optional[Encryption] = services.get("encryption")

        # VORHER: Bei fehlenden kritischen Diensten wird die Anwendung sofort gestoppt.
        # Dies ist eine strikte, aber unflexible Regel.
        if not self.user_handler:
            logger.critical("Security manager init failed: UserHandler service missing.")
            raise RuntimeError("UserHandler service missing")

        if not self.access_control:
            logger.critical("Security manager init failed: AccessControl service missing.")
            raise RuntimeError("AccessControl service missing")

        # VORHER: Bei einem nicht-kritischen Dienst wird nur eine Warnung ausgegeben.
        # Die Anwendung läuft weiter.
        if not self.encryption:
            logger.warning("Encryption service not available. Encryption/decryption features will be disabled.")

        logger.info("Security manager initialized and ready.")

    # VORHER: Hier fehlt die Überprüfung, ob 'self.user_handler' None ist.
    # Wenn der Dienst nicht initialisiert wurde (wie oben), würde dies einen AttributeError auslösen.
    async def user_login(self, username: str, password: str, request_data: dict) -> bool:
        logger.info(f"Attempting login for user: {username}")
        if await self.user_handler.login(username, password, request_data):
            return await self.user_handler.validate_session(request_data)
        return False

    # VORHER: Hier fehlt die Überprüfung, ob 'self.access_control' None ist.
    async def check_permission(self, user_id: int, permission_name: str) -> bool:
        logger.debug(f"Checking permission '{permission_name}' for user ID {user_id}")
        return await self.access_control.has_permission(user_id, permission_name)

    # VORHER: Hier wird geprüft, ob 'self.encryption' None ist, was korrekt ist.
    def encrypt_data(self, data: str) -> Dict[str, str]:
        if not self.encryption:
            raise RuntimeError("Encryption service not initialized.")
        logger.debug("Encrypting data.")
        return self.encryption.encrypt(data)

    # VORHER: Hier wird geprüft, ob 'self.encryption' None ist, was korrekt ist.
    def decrypt_data(self, encrypted_data: str, nonce: str, tag: str) -> Optional[str]:
        if not self.encryption:
            logger.error("Encryption service not initialized. Cannot decrypt data.")
            return None
        logger.debug("Decrypting data.")
        try:
            return self.encryption.decrypt(encrypted_data, nonce, tag)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
