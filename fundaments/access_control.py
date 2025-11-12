# PyFundaments: A Secure Python Architecture
# Copyright 2008-2025 - Volkan Kücükbudak
# Apache License V. 2
# Repo: https://github.com/VolkanSah/PyFundaments
# access_control.py
# This is the standalone module for access control.
# It is intended to be imported by main.py or app.py.

import sys
from typing import Optional, List, Dict, Any

# Your foundational PostgreSQL module is imported here.
# IMPORTANT: Ensure 'postgresql.py' is in the same directory or accessible
# via the Python path.
from fundaments import postgresql as db
# local db use: db.execute_secured_query(), db.init_db_pool(), etc. but this fundaments are optimized for clouds


# If asyncpg is not installed, exit the script gracefully.
try:
    import asyncpg
except ImportError:
    print("Error: The 'asyncpg' library is required. Please install it with 'pip install asyncpg'.")
    sys.exit(1)


class AccessControl:
    """
    Asynchronous class for managing access control.
    It builds directly on the functions of your secure database module.
    This is the layer that uses the foundation without modifying it.

    How to extend this class:
    To add new functionality, simply create a new asynchronous method
    within this class. This method can call the `db.execute_secured_query`
    function to interact with the database. For example:

    async def get_user_last_login(self):
        sql = "SELECT last_login FROM users WHERE id = $1"
        result = await db.execute_secured_query(sql, self.user_id, fetch_method='fetchrow')
        return result['last_login'] if result else None
    """
    def __init__(self, user_id: Optional[int] = None):
        self.user_id = user_id

    async def has_permission(self, permission_name: str) -> bool:
        """
        Checks if the user has a specific permission.
        Uses the secure execute_secured_query function from the foundation.
        """
        if self.user_id is None:
            return False

        # SQL Query Explanation:
        # This query counts the number of rows where the user (user_id)
        # has a role (user_role_assignments) that is linked to a permission
        # (role_permissions) which has the specified name (user_permissions.name).
        # If the count is > 0, the user has the permission.
        sql = """
            SELECT COUNT(*) AS count
            FROM user_role_assignments ura
            JOIN role_permissions rp ON ura.role_id = rp.role_id
            JOIN user_permissions up ON rp.permission_id = up.id
            WHERE ura.user_id = $1 AND up.name = $2
        """
        try:
            result = await db.execute_secured_query(
                sql,
                self.user_id,
                permission_name,
                fetch_method='fetchrow'
            )
            return result['count'] > 0
        except Exception as e:
            # Error handling is managed by your postgresql module.
            # We just re-raise the exception here to propagate it.
            raise Exception(f'Failed to check permission: {e}')

    async def get_user_permissions(self) -> List[Dict[str, Any]]:
        """Returns all permissions for a user."""
        if self.user_id is None:
            return []

        # SQL Query Explanation:
        # This query retrieves all distinct permission names and descriptions
        # associated with the user's roles. `DISTINCT` ensures each permission
        # is listed only once.
        sql = """
            SELECT DISTINCT up.name, up.description
            FROM user_role_assignments ura
            JOIN role_permissions rp ON ura.role_id = rp.role_id
            JOIN user_permissions up ON rp.permission_id = up.id
            WHERE ura.user_id = $1
            ORDER BY up.name
        """
        try:
            return await db.execute_secured_query(sql, self.user_id)
        except Exception as e:
            raise Exception(f'Failed to get user permissions: {e}')

    async def get_user_roles(self) -> List[Dict[str, Any]]:
        """Returns all roles for a user."""
        if self.user_id is None:
            return []

        # SQL Query Explanation:
        # This query selects the details (id, name, description) of the roles
        # that are assigned to the specified user (user_id) in the
        # `user_role_assignments` table.
        sql = """
            SELECT r.id, r.name, r.description
            FROM user_role_assignments ura
            JOIN user_roles r ON ura.role_id = r.id
            WHERE ura.user_id = $1
            ORDER BY r.name
        """
        try:
            return await db.execute_secured_query(sql, self.user_id)
        except Exception as e:
            raise Exception(f'Failed to get user roles: {e}')

    async def assign_role(self, role_id: int) -> None:
        """Assigns a role to a user."""
        if self.user_id is None:
            raise Exception('No user specified')

        # SQL Query Explanation:
        # Inserts a new row into the `user_role_assignments` table to create
        # the relationship between a user and a role.
        sql = "INSERT INTO user_role_assignments (user_id, role_id) VALUES ($1, $2)"
        try:
            await db.execute_secured_query(
                sql,
                self.user_id,
                role_id,
                fetch_method='execute'
            )
        except Exception as e:
            raise Exception(f'Failed to assign role: {e}')

    async def remove_role(self, role_id: int) -> None:
        """Removes a role from a user."""
        if self.user_id is None:
            raise Exception('No user specified')

        # SQL Query Explanation:
        # Deletes the row from the `user_role_assignments` table that matches
        # the specified user ($1) and role ($2).
        sql = "DELETE FROM user_role_assignments WHERE user_id = $1 AND role_id = $2"
        try:
            await db.execute_secured_query(
                sql,
                self.user_id,
                role_id,
                fetch_method='execute'
            )
        except Exception as e:
            raise Exception(f'Failed to remove role: {e}')

    async def get_all_roles(self) -> List[Dict[str, Any]]:
        """Returns all available roles."""
        # SQL Query Explanation:
        # Selects all roles from the `user_roles` table.
        sql = "SELECT id, name, description FROM user_roles ORDER BY name"
        try:
            return await db.execute_secured_query(sql)
        except Exception as e:
            raise Exception(f'Failed to get roles: {e}')

    async def get_all_permissions(self) -> List[Dict[str, Any]]:
        """Returns all available permissions."""
        # SQL Query Explanation:
        # Selects all permissions from the `user_permissions` table.
        sql = "SELECT id, name, description FROM user_permissions ORDER BY name"
        try:
            return await db.execute_secured_query(sql)
        except Exception as e:
            raise Exception(f'Failed to get permissions: {e}')

    async def create_role(self, name: str, description: str) -> int:
        """Creates a new role."""
        # SQL Query Explanation:
        # Inserts a new role into the `user_roles` table and returns the
        # automatically generated ID of the new role (`RETURNING id`).
        sql = "INSERT INTO user_roles (name, description) VALUES ($1, $2) RETURNING id"
        try:
            result = await db.execute_secured_query(
                sql,
                name,
                description,
                fetch_method='fetchrow'
            )
            return result['id']
        except Exception as e:
            raise Exception(f'Failed to create role: {e}')

    async def update_role_permissions(self, role_id: int, permission_ids: List[int]) -> None:
        """Updates the permissions for a role."""
        # IMPORTANT: Since your module does not handle transactions across multiple
        # queries, we perform these actions sequentially. Query-level security
        # is guaranteed by your module.
        try:
            # SQL Query Explanation:
            # Deletes all existing permissions for the given role.
            sql_delete = "DELETE FROM role_permissions WHERE role_id = $1"
            await db.execute_secured_query(sql_delete, role_id, fetch_method='execute')

            # SQL Query Explanation:
            # Inserts a new row for each permission_id passed into the
            # `role_permissions` table.
            if permission_ids:
                sql_insert = "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)"
                for permission_id in permission_ids:
                    await db.execute_secured_query(
                        sql_insert,
                        role_id,
                        permission_id,
                        fetch_method='execute'
                    )
        except Exception as e:
            # If an error occurs, the underlying foundation will log the issue.
            # We re-raise the error here.
            raise Exception(f'Failed to update role permissions: {e}')

    async def get_role_permissions(self, role_id: int) -> List[Dict[str, Any]]:
        """Returns all permissions for a role."""
        # SQL Query Explanation:
        # Selects the details (id, name, description) of all permissions
        # linked to the specified role.
        sql = """
            SELECT p.id, p.name, p.description
            FROM role_permissions rp
            JOIN user_permissions p ON rp.permission_id = p.id
            WHERE rp.role_id = $1
            ORDER BY p.name
        """
        try:
            return await db.execute_secured_query(sql, role_id)
        except Exception as e:
            raise Exception(f'Failed to get role permissions: {e}')
