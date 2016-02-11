"""
This module provides a query interface for objects managed by the data-mapper.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

from functools import reduce
from operator import and_

from ..filters import F, Expression, AndNode, OrNode, NotNode
from ..query import Query as LDAPQuery


class Query:
    """
    A lazily evaluated, filter-able, object-mapped query.

    The query is not executed at all until the results are requested, and results
    are fetched in batches as the query is iterated over.

    Results are **not** cached, so results may change between iterations. To
    retrieve all the results as a list for caching, just use ``list(query)``.

    :param query: The underlying :py:class:`jasmin_ldap.query.Query`
    :param obj_type: The type of objects that the query will return
                     This is also used as an object factory
    :param schema: A :py:class:`.schema.Schema` instance to use to map LDAP records
                   to object properties
    """
    def __init__(self, query, obj_type, schema):
        self._query = query
        self._obj_type = obj_type
        self._schema = schema

    ############################################################################
    ## Methods that fetch data
    ############################################################################

    def __iter__(self):
        """
        Returns an iterator of the results from this query.
        """
        for dn, attrs in self._query:
            yield self._obj_type(**self._schema.to_python(dn, attrs))

    def one(self):
        """
        Returns a single result from the query, or ``None`` if there is no such
        object.
        """
        return next(iter(self), None)

    ############################################################################
    ## Methods that return a new query instance
    ############################################################################

    def _compile(self, node):
        """
        Recursively cross-compiles a filters.Node using object properties to one
        that uses LDAP attributes.
        """
        if isinstance(node, Expression):
            # All we want to do is map field names to LDAP attribute names
            field, lookup, value = node.field, node.lookup_type, node.value
            try:
                return Expression(
                    self._schema.field_for_name(field).attribute, lookup, value
                )
            except KeyError:
                # Convert the key error into a more informative message
                raise KeyError("Field '{}' is not in schema for '{}'".format(
                    field, self._obj_type.__name__
                ))
        elif isinstance(node, AndNode):
            return AndNode(*[self._compile(c) for c in node.children])
        elif isinstance(node, OrNode):
            return OrNode(*[self._compile(c) for c in node.children])
        elif isinstance(node, NotNode):
            return NotNode(self._compile(node.child))
        else:
            raise ValueError("Unknown node type '{}'".format(type(node).__name__))

    def filter(self, *args, **kwargs):
        """
        Returns a new query with args combined with this query using AND.

        Positional arguments should be :py:class:`.filters.Node`\ s.

        Keyword arguments should be of the form ``field__lookuptype = value``,
        similar to the Django ORM.
        """
        return type(self)(
            # Create a filter from the args, cross-compile it and filter the
            # current query using it
            self._query.filter(self._compile(F(*args, **kwargs))),
            self._obj_type,
            self._schema
        )

    def exclude(self, *args, **kwargs):
        """
        Returns a new query with NOT(args) combined with this query using AND.

        Positional arguments should be :py:class:`.filters.Node`\ s.

        Keyword arguments should be of the form ``field__lookuptype = <value>``,
        similar to the Django ORM.
        """
        return self.filter(~F(*args, **kwargs))

    ############################################################################
    ## Python magic methods
    ############################################################################

    def __len__(self):
        """
        Returns the number of items in the query.
        """
        # To do this, we have to force all the results to be fetched
        return len(list(iter(self)))

    ############################################################################
    ## Alternative constructor
    ############################################################################

    @classmethod
    def create(cls, pool, obj_type, schema):
        """
        Creates a new object-mapped query using the given LDAP connection pool
        that maps LDAP results to the given ``obj_type`` using the given schema.

        :param pool: The :py:class:`jasmin_ldap.core.ConnectionPool` to use
        :param obj_type: The object type to map to
        :param schema: The schema to use
        :returns: A :py:class:`Query` for the object type
        """
        # Create the underlying LDAP query
        q = LDAPQuery(
            pool,
            schema.base_dn,
            # The default filter is the object classes from the schema
            reduce(and_, (F(objectClass = o) for o in schema.object_classes)),
            scope = LDAPQuery.SCOPE_SINGLE_LEVEL
        )
        # Create the object-mapped query
        return cls(q, obj_type, schema)
