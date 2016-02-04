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
        :param schema: The schema instance or schema class
        """
        # Create an instance if we have a class
        if isinstance(schema, type) and issubclass(schema, Schema):
            schema = schema()
        self._registry[obj_type] = schema

    def find_schema(self, obj_type):
        """
        Tries to find a schema for ``obj_type``.

        If a schema for the type has been manually registered (using ``register``)
        or previously been discovered and cached, that schema will be returned.

        If no schema is found via that route, the method will look for a subclass of
        :py:class:`.schema.Schema` as a nested class of ``obj_type`` and use that
        as the schema class. The result will be cached for future use.

        If a schema is not found by either of those methods, an error will be raised.
        """
        # If we already have a schema, use that
        if obj_type in self._registry:
            return self._registry[obj_type]
        # Otherwise, try and find a nested schema class
        for value in obj_type.__dict__.values():
            if isinstance(value, type) and issubclass(value, Schema):
                # Cache it for the future
                schema = value()
                self._registry[obj_type] = schema
                return schema
        raise SchemaNotFoundError(
            "No schema defined for '{}'".format(obj_type.__name__)
        )

    def create_query(self, obj_type):
        """
        Creates a query for the given object type.
        """
        return Query.create(self._pool, obj_type, self.find_schema(obj_type))
