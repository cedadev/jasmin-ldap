"""
This module defines the entity manager.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

from .exceptions import SchemaNotFoundError
from .schema import Schema
from .query import Query


class EntityManager:
    """
    An entity manager is responsible for managing the marshalling of objects to
    and from LDAP. This is achieved by associating schemas with object types, and
    issuing LDAP commands appropriately.

    :param pool: The :py:class:`jasmin_ldap.core.ConnectionPool` to use
    """
    def __init__(self, pool):
        self._pool = pool
        self._registry = {}

    def register(self, obj_type, schema):
        """
        Manually associates an object type with a schema instance or schema class.

        :param obj_type: The object type
        :param schema: The schema instance
        """
        self._registry[obj_type] = schema

    def find_schema(self, obj):
        """
        Tries to find and return a schema for the given object.

        If the object is a class, there must be a schema registered for the class.
        If the object is an instance, it's class is used.

        If no schema has been registered, an error is raised.
        """
        if not isinstance(obj, type):
            return self.find_schema(type(obj))
        try:
            return self._registry[obj]
        except KeyError:
            raise SchemaNotFoundError(
                "No schema defined for '{}'".format(obj.__name__)
            )

    def query(self, obj_type):
        """
        Creates a query for the given object type.
        """
        return Query.create(self._pool, obj_type, self.find_schema(obj_type))

    def create(self, obj):
        """
        Creates an object in LDAP.

        :param obj: The object to create
        :returns: ``True`` on success (should raise on failure)
        """
        schema = self.find_schema(obj)
        dn, attrs = schema.to_ldap(obj)
        with self._pool.connection() as conn:
            return conn.create_entry(dn, attrs)

    def update(self, obj):
        """
        Updates an object in LDAP.

        :param obj: The object to udpate
        :returns: ``True`` on success (should raise on failure)
        """
        schema = self.find_schema(obj)
        dn, attrs = schema.to_ldap(obj)
        with self._pool.connection() as conn:
            return conn.update_entry(dn, attrs)

    def delete(self, obj):
        """
        Deletes an object in LDAP.

        :param obj: The object to delete
        :returns: ``True`` on success (should raise on failure)
        """
        schema = self.find_schema(obj)
        dn = schema.build_dn(obj)
        with self._pool.connection() as conn:
            return conn.delete_entry(dn)
