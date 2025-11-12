# PyFundaments: A Secure Python Architecture
# Copyright 2008-2025 - Volkan Kücükbudak
# Apache License V. 2
# Repo: https://github.com/VolkanSah/PyFundaments
# user_handler.py
# A Python module for handling user authentication and session management.

import sqlite3
import uuid
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
import os

class Database:
    """
    A simple placeholder class to simulate a database connection.
    In a real application, you would use a proper ORM like SQLAlchemy
    or a specific database driver.
    """
    def __init__(self, db_name="cms_database.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()

    def execute(self, query, params=None):
        if params is None:
            params = []
        self.cursor.execute(query, params)
        self.conn.commit()

    def fetchone(self, query, params=None):
        if params is None:
            params = []
        self.cursor.execute(query, params)
        return self.cursor.fetchone()

    def fetchall(self, query, params=None):
        if params is None:
            params = []
        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def close(self):
        self.conn.close()

    def setup_tables(self):
        """
        Creates the necessary tables for users and sessions.
        """
        self.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                account_locked INTEGER NOT NULL DEFAULT 0,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

class Security:
    """
    Handles secure password hashing and session regeneration.
    Using passlib for robust and secure password management.
    """
    @staticmethod
    def hash_password(password: str) -> str:
        """Hashes a password using PBKDF2 with SHA256."""
        return pbkdf2_sha256.hash(password)

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verifies a password against a stored hash."""
        return pbkdf2_sha256.verify(password, hashed_password)

    @staticmethod
    def regenerate_session(session_id: str):
        """
        Simulates regenerating a session ID to prevent session fixation.
        In a real web framework, this would be a framework-specific function.
        """
        print(f"Session regenerated. Old ID: {session_id}")
        new_session_id = str(uuid.uuid4())
        print(f"New ID: {new_session_id}")
        return new_session_id

class UserHandler:
    """
    Handles user login, logout, and session validation.
    This class mirrors the logic from the user's PHP User class.
    """
    def __init__(self, db: Database):
        self.db = db
        # A simple in-memory session store for this example
        self._session = {}

    def login(self, username: str, password: str, request_data: dict) -> bool:
        """
        Logs in the user by verifying credentials and storing a new session.
        :param username: The user's username.
        :param password: The user's plain-text password.
        :param request_data: A dictionary containing 'ip_address' and 'user_agent'.
        :return: True if login is successful, False otherwise.
        """
        try:
            # Step 1: Find the user in the database
            user_data = self.db.fetchone("SELECT id, username, password, is_admin, account_locked, failed_login_attempts FROM users WHERE username = ?", (username,))
            if user_data is None:
                print(f"Login failed: Username '{username}' not found.")
                return False

            user = {
                'id': user_data[0],
                'username': user_data[1],
                'password': user_data[2],
                'is_admin': user_data[3],
                'account_locked': user_data[4],
                'failed_login_attempts': user_data[5]
            }

            # Check if account is locked
            if user['account_locked'] == 1:
                print(f"Login failed: Account for '{username}' is locked.")
                return False

            # Step 2: Verify the password
            if Security.verify_password(password, user['password']):
                print(f"Login successful for user: '{username}'")
                
                # Reset failed login attempts on success
                self.reset_failed_attempts(username)

                # Step 3: Create a new session record in the database
                session_id = str(uuid.uuid4())
                ip_address = request_data.get('ip_address', 'unknown')
                user_agent = request_data.get('user_agent', 'unknown')

                self.db.execute(
                    "INSERT INTO sessions (id, user_id, ip_address, user_agent) VALUES (?, ?, ?, ?)",
                    (session_id, user['id'], ip_address, user_agent)
                )

                # Step 4: Store session data in the in-memory session (or a session store)
                self._session = {
                    'session_id': session_id,
                    'user_id': user['id'],
                    'username': user['username'],
                    'is_admin': user['is_admin']
                }

                # Security: Regenerate session ID
                self._session['session_id'] = Security.regenerate_session(session_id)
                return True
            else:
                print(f"Login failed: Incorrect password for user '{username}'.")
                # Increment failed login attempts
                self.increment_failed_attempts(username)
                return False

        except sqlite3.Error as e:
            print(f"Database error during login: {e}")
            return False

    def logout(self) -> bool:
        """
        Logs out the current user by deleting the session from the database.
        :return: True if logout is successful, False otherwise.
        """
        if 'user_id' not in self._session:
            print("No active session to log out.")
            return False

        try:
            # Step 1: Delete the session from the database
            self.db.execute("DELETE FROM sessions WHERE user_id = ?", (self._session['user_id'],))
            
            # Step 2: Clear the in-memory session data
            self._session.clear()
            print("User logged out successfully.")
            return True
        except sqlite3.Error as e:
            print(f"Database error during logout: {e}")
            return False

    def is_logged_in(self) -> bool:
        """
        Checks if the current user is logged in.
        :return: True if a valid session exists, False otherwise.
        """
        if 'user_id' not in self._session:
            return False

        try:
            # Check for the session in the database
            session_data = self.db.fetchone(
                "SELECT * FROM sessions WHERE id = ? AND user_id = ?",
                (self._session['session_id'], self._session['user_id'])
            )
            return session_data is not None
        except sqlite3.Error as e:
            print(f"Database error during is_logged_in check: {e}")
            return False

    def is_admin(self) -> bool:
        """
        Checks if the logged-in user is an admin.
        :return: True if the user is an admin, False otherwise.
        """
        return self._session.get('is_admin', 0) == 1

    def validate_session(self, request_data: dict) -> bool:
        """
        Validates the current session against IP address and user agent.
        :param request_data: A dictionary containing 'ip_address' and 'user_agent'.
        :return: True if the session is valid, False otherwise.
        """
        if not self.is_logged_in():
            return False

        try:
            ip_address = request_data.get('ip_address', 'unknown')
            user_agent = request_data.get('user_agent', 'unknown')

            session_data = self.db.fetchone(
                "SELECT * FROM sessions WHERE id = ? AND user_id = ? AND ip_address = ? AND user_agent = ?",
                (self._session['session_id'], self._session['user_id'], ip_address, user_agent)
            )
            return session_data is not None
        except sqlite3.Error as e:
            print(f"Database error during session validation: {e}")
            return False

    def lock_account(self, username: str):
        """
        Locks a user account.
        :param username: The username of the account to lock.
        """
        try:
            self.db.execute("UPDATE users SET account_locked = 1 WHERE username = ?", (username,))
            print(f"Account for '{username}' has been locked.")
        except sqlite3.Error as e:
            print(f"Database error while locking account: {e}")

    def reset_failed_attempts(self, username: str):
        """
        Resets failed login attempts for a user.
        :param username: The username of the account.
        """
        try:
            self.db.execute("UPDATE users SET failed_login_attempts = 0 WHERE username = ?", (username,))
        except sqlite3.Error as e:
            print(f"Database error while resetting failed attempts: {e}")

    def increment_failed_attempts(self, username: str):
        """
        Increments failed login attempts and locks the account if a threshold is met.
        :param username: The username of the account.
        """
        try:
            # Get the current failed attempts
            user_data = self.db.fetchone("SELECT failed_login_attempts FROM users WHERE username = ?", (username,))
            if user_data:
                attempts = user_data[0] + 1
                self.db.execute(
                    "UPDATE users SET failed_login_attempts = ? WHERE username = ?",
                    (attempts, username)
                )
                print(f"Failed login attempts for '{username}': {attempts}")
                
                # Check for threshold (e.g., 5 attempts)
                if attempts >= 5:
                    self.lock_account(username)

        except sqlite3.Error as e:
            print(f"Database error while incrementing failed attempts: {e}")

# --- Example Usage ---
if __name__ == "__main__":
    db = Database()
    db.setup_tables()
    user_handler = UserHandler(db)

    # Clean up old test data if it exists
    db.execute("DELETE FROM users WHERE username IN (?, ?)", ("testuser", "adminuser"))
    db.execute("DELETE FROM sessions")

    # 1. Register a new user and an admin user
    hashed_password = Security.hash_password("secure_password_123")
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("testuser", hashed_password))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", ("adminuser", hashed_password))

    print("--- Test 1: Successful Login ---")
    # Simulate a web request
    request_data = {
        'ip_address': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    login_success = user_handler.login("testuser", "secure_password_123", request_data)
    print(f"Login attempt status: {login_success}")
    print(f"Is user logged in? {user_handler.is_logged_in()}")
    print(f"Is user an admin? {user_handler.is_admin()}")
    print(f"Is session valid? {user_handler.validate_session(request_data)}")
    print("-" * 20)
    
    # 2. Simulate a logout
    print("--- Test 2: Logout ---")
    user_handler.logout()
    print(f"Is user logged in after logout? {user_handler.is_logged_in()}")
    print("-" * 20)

    # 3. Simulate a failed login and account lock
    print("--- Test 3: Failed Login and Account Lock ---")
    # Log in with the wrong password multiple times
    for i in range(6):
        user_handler.login("testuser", "wrong_password", request_data)
    
    # Now, try to log in with the correct password. It should fail because the account is locked.
    print("\nAttempting to log in with correct password after lock:")
    login_attempt_after_lock = user_handler.login("testuser", "secure_password_123", request_data)
    print(f"Login attempt status: {login_attempt_after_lock}")
    print("-" * 20)
    
    # 4. Reset failed attempts for a new login
    print("--- Test 4: Resetting failed attempts ---")
    user_handler.reset_failed_attempts("testuser")
    login_attempt_after_reset = user_handler.login("testuser", "secure_password_123", request_data)
    print(f"Login attempt status after reset: {login_attempt_after_reset}")
    
    db.close()
    
    # Optional: Clean up the database file after the run
    # os.remove("cms_database.db")
