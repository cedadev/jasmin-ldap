"""
This module provides facilities for making LDAP queries.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

from functools import reduce
from operator import or_

import ldap3.utils.conv

from .core import Connection
from .filters import F, Expression, AndNode, OrNode, NotNode


class Query:
    """
    A lazily evaluated, filter-able LDAP search query.

    The query is not executed at all until the results are requested, and results
    are fetched from LDAP in batches as the query is iterated over.

    Results are **not** cached, so results may change between iterations. To
    retrieve all the results as a list for caching, just use ``list(query)``.

    :param pool: The :py:class:`.core.ConnectionPool` to use
    :param base_dn: The base DN for the search
    :param filter: A :py:class:`.filters.Node` for the filter to apply (optional)
    :param scope: The scope of the search (optional, one of ``SCOPE_SUBTREE`` or
                  ``SCOPE_SINGLE_LEVEL``)
    """
    #: Scope to search entire subtree
    SCOPE_SUBTREE      = Connection.SEARCH_SCOPE_SUBTREE
    #: Scope to search just a single level
    SCOPE_SINGLE_LEVEL = Connection.SEARCH_SCOPE_SINGLE_LEVEL

    def __init__(self, pool, base_dn, filter = None, scope = SCOPE_SINGLE_LEVEL):
        self._pool = pool
        self._base_dn = base_dn
        # If no filter was given, use a catch-all filter
        self._filter = filter or F(objectClass__present = True)
        self._scope = scope

    ############################################################################
    ## Methods that fetch data
    ############################################################################

    # Maps the supported lookup types to an LDAP search filter template
    # NOTE: 'in' is also supported, but is handled in _compile, since it needs
    #       special treatment
    _LOOKUP_TYPES = {
        'exact'       : '({field}={value})',
        'iexact'      : '({field}={value})',
        'contains'    : '({field}=*{value}*)',
        'icontains'   : '({field}=*{value}*)',
        'startswith'  : '({field}={value}*)',
        'istartswith' : '({field}={value}*)',
        'endswith'    : '({field}=*{value})',
        'iendswith'   : '({field}=*{value})',
        'present'     : '({field}=*)',
        'search'      : '({field}=*{value}*)',
    }
    # Characters that need escaping in values for filter expressions
    _ESCAPE_CHARS = {
        '*': '\\2A', '(': '\\28', ')': '\\29', '\\': '\\5C', '\0': '\\00'
    }

    def _compile(self, node):
        """
        Recursively compiles a :py:class:`.filters.Node` into an LDAP query string.
        """
        if isinstance(node, Expression):
            # Use 'exact' as the default lookup type
            field, lookup, value = node.field, node.lookup_type or 'exact', node.value
            # We support 'in' as a lookup type, but only by mapping it to an OR
            if lookup == 'in':
                # If no values were given, raise an error
                if not value:
                    raise ValueError("At least one value required for 'in' lookup")
                # Convert the values to a list of exact match expressions
                expressions = [Expression(field, 'exact', v) for v in value]
                # Combine the expressions using OR and compile the result
                return self._compile(reduce(or_, expressions))
            # Present with a false-y value is not present
            elif lookup == 'present' and not value:
                return self._compile(NotNode(Expression(field, 'present', True)))
            # isnull is the opposite of present
            elif lookup == 'isnull':
                return self._compile(NotNode(Expression(field, 'present', value)))
            # Escape any dodgy characters in the value
            if isinstance(value, bytes):
                value = ldap3.utils.conv.escape_bytes(value)
            else:
                value = ''.join(self._ESCAPE_CHARS.get(c, c) for c in str(value))
            # Insert values into the filter template for the lookup type
            try:
                return self._LOOKUP_TYPES[lookup].format(field = field, value = value)
            except KeyError:
                raise ValueError("Unsupported lookup type - {}".format(lookup))
        elif isinstance(node, AndNode):
            return '(&{})'.format(''.join(self._compile(c) for c in node.children))
        elif isinstance(node, OrNode):
            return '(|{})'.format(''.join(self._compile(c) for c in node.children))
        elif isinstance(node, NotNode):
            return '(!{})'.format(self._compile(node.child))
        else:
            raise ValueError("Unknown node type '{}'".format(type(node).__name__))

    def __iter__(self):
        """
        Returns an iterator of the results from this query.
        """
        # We need to make sure we hold on to the connection until we have finished
        # iterating
        # To ensure that the connection gets released when a partial iteration is
        # finished with, we must turn GeneratorExit into StopIteration
        with self._pool.connection() as conn:
            try:
                yield from conn.search(self._base_dn,
                                       self._compile(self._filter), self._scope)
            except GeneratorExit:
                raise StopIteration

    def one(self):
        """
        Returns a single result from the query, or ``None`` if there is no such
        object.
        """
        return next(iter(self), None)

    ############################################################################
    ## Methods that return a new query instance
    ############################################################################

    def filter(self, *args, **kwargs):
        """
        Returns a new query with args combined with this query using AND.

        Positional arguments should be :py:class:`.filters.Node`\ s.

        Keyword arguments should be of the form ``field__lookuptype = value``,
        similar to the Django ORM. If no lookup type is given, exact is used.

        ::

            from jasmin_ldap.filters import F

            q = Query(...).filter(mail__exact = 'jbloggs@example.com')
            q = Query(...).filter(F(mail = 'jbloggs@example.com') | F(uid = 'jbloggs'))
        """
        return type(self)(
            self._pool,
            self._base_dn,
            # Combine our filter and a filter built from the args
            self._filter & F(*args, **kwargs),
            self._scope
        )

    def exclude(self, *args, **kwargs):
        """
        Returns a new query with NOT(args) combined with this query using AND.

        Positional arguments should be :py:class:`.filters.Node` objects.

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
