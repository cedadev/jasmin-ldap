"""
This module provides facilities for making LDAP queries.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

import abc, re
from functools import reduce, cmp_to_key
from operator import or_
from collections import Iterable

import ldap3.utils.conv

from .core import Connection
from .filters import F, Expression, AndNode, OrNode, NotNode
from .aggregations import Count


class QueryBase(metaclass = abc.ABCMeta):
    """
    Base class containing functionality common to all query types.
    """
    @abc.abstractmethod
    def _run_query(self):
        """
        Returns an iterator of the results of the query.
        """

    @property
    def _cached(self):
        if not hasattr(self, '_cache'):
            self._cache = list(self._run_query())
        return self._cache

    def __iter__(self):
        """
        Caches query results on first iteration and returns cache.
        """
        return iter(self._cached)

    def one(self):
        """
        Returns a single result from the query, or ``None`` if there is no such
        object.
        """
        return next(iter(self), None)

    def select(self, *attributes):
        """
        Returns a new query that selects only the given attributes from each entry.
        """
        return SelectQuery(self, attributes)

    def distinct(self):
        """
        Returns a new query that yields only the distinct attribute dictionaries.
        """
        return DistinctQuery(self)

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
        return FilteredQuery(self, F(*args, **kwargs))

    def exclude(self, *args, **kwargs):
        """
        Returns a new query with NOT(args) combined with this query using AND.

        Positional arguments should be :py:class:`.filters.Node` objects.

        Keyword arguments should be of the form ``field__lookuptype = <value>``,
        similar to the Django ORM.
        """
        return self.filter(~F(*args, **kwargs))

    def annotate(self, **annotations):
        """
        Returns a new query consisting of this query with extra calculated
        attributes (annotations).

        Each annotation is just a name => callable mapping, where the callable recieves
        the attribute dictionary as its only argument.

        Some commonly used annotations are provided in the :py:mod:`~.annotations`
        module.

        For example, to annotate a query with a field containing the number of mail
        entries:

        ::

            from jasmin_ldap.annotations import Count
            query = query.annotate(num_mails = Count('mail'))

        After doing this, each attribute dictionary will have an additional ``num_mails``
        element.
        """
        return AnnotatedQuery(self, annotations)

    def order_by(self, *orderings):
        """
        Returns a new query with the given orderings imposed.

        Each ordering is an attribute name. Prefixing the attribute name with ``-``
        indicates that the ordering should be descending. The orderings are applied
        in the order they are given, i.e. entries are ordered as follows:

          1. Entries are ordered by the first ordering
          2. Where the first ordering considers entries equal, they are ordered
             by the second ordering
          3. And so on...
        """
        return OrderedQuery(self, orderings)

    def __getitem__(self, key):
        if isinstance(key, tuple):
            raise TypeError('Multi-dimensional indexing of queries is not supported')
        # If the key is a single integer, just return the item
        if isinstance(key, int):
            return self[key:key + 1].one()
        # Otherwise, the key is a slice
        low, high, step = key.start or 0, key.stop, key.step or 1
        return SlicedQuery(self, low, high, step)

    def aggregate(self, **aggregations):
        """
        Applies the given aggregations to the query as a whole, and returns a
        dictionary mapping aggregation name => value.

        Each aggregation is an object with three methods/properties:

          1. An ``accumulate`` method. The ``accumulate`` method is called once
             for each entry in the query, and recieves the attribute dictionary
             as its only argument.
          2. A ``result`` property. The ``result`` property is interrogated once
             iteration is complete.
          3. A ``reset`` method that clears any existing result.

        This structure allows multiple aggregations to be calculated in one 'sweep'
        of the query.

        Some common aggregations are provided in the :py:mod:`~.aggregations` module.
        For example, to count the number of elements and the maximum and mimimum
        uidNumber in one sweep, the following could be used:

        ::

            from jasmin_ldap.aggregations import Count, Max, Min
            query.aggregate(count = Count(),
                            max_uid = Max('uidNumber'),
                            min_uid = Min('uidNumber')))
            # Returns:
            #   {'max_uid': [10], 'count': [15], 'min_uid': [5]}
        """
        # Before we iterate, reset the aggregations
        for _, agg in aggregations.items(): agg.reset()
        # Do the accumulation
        for attrs in self:
            for _, agg in aggregations.items():
                agg.accumulate(attrs)
        # Return the results
        return { name : agg.result for name, agg in aggregations.items() }

    def __len__(self):
        """
        Returns the number of items in the query.
        """
        # To do this, we have to force all the results to be fetched
        return len(self._cached)


class EmptyQuery(QueryBase):
    """
    Special class to represent an empty query
    """
    def _run_query(self):
        yield from ()

    def one(self):
        """
        See :py:meth:`QueryBase.one`
        """
        return None

    def select(self, *attributes):
        """
        See :py:meth:`QueryBase.select`
        """
        return self

    def distinct(self):
        """
        See :py:meth:`QueryBase.distinct`
        """
        return self

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        return self

    def annotate(self, **annotations):
        """
        See :py:meth:`QueryBase.annotate`
        """
        return self

    def order_by(self, *orderings):
        """
        See :py:meth:`QueryBase.order_by`
        """
        return self

    def __getitem__(self, key):
        raise IndexError('Index out of range')

    def __len__(self):
        return 0

    def instance(cls):
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
        return cls._instance


class Query(QueryBase):
    """
    A lazily evaluated, filter-able LDAP search query.

    The query is not executed at all until the results are requested, and results
    are fetched from LDAP in batches as the query is iterated over.

    Results are **not** cached, so results may change between iterations. To
    retrieve all the results as a list for caching, just use ``list(query)``.

    :param conn: The :py:class:`.core.Connection` to use
    :param base_dn: The base DN for the search
    :param filter: A :py:class:`.filters.Node` for the filter to apply (optional)
    :param scope: The scope of the search (optional, one of ``SCOPE_SUBTREE`` or
                  ``SCOPE_SINGLE_LEVEL``)
    """
    #: Scope to search entire subtree
    SCOPE_SUBTREE      = Connection.SEARCH_SCOPE_SUBTREE
    #: Scope to search just a single level
    SCOPE_SINGLE_LEVEL = Connection.SEARCH_SCOPE_SINGLE_LEVEL

    def __init__(self, conn, base_dn, filter = None, scope = SCOPE_SINGLE_LEVEL):
        self._conn = conn
        self._base_dn = base_dn
        # If no filter was given, use a catch-all filter
        self._filter = filter or F(objectClass__present = True)
        self._scope = scope

    # Maps the supported lookup types to an LDAP search filter template
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

    def _compile_filter(self, node):
        """
        Recursively compiles a :py:class:`.filters.Node` into an LDAP query string.
        """
        if isinstance(node, Expression):
            # Use 'exact' as the default lookup type
            field, lookup, value = node.field, node.lookup_type or 'exact', node.value

            # Decide what filter to use based on lookup type
            if lookup == 'in':
                # We support 'in' as a lookup type by mapping it to an OR
                # If no values were given, raise an error
                if not value:
                    raise ValueError("At least one value required for 'in' lookup")
                # Convert the values to a list of exact match expressions
                expressions = [Expression(field, 'exact', v) for v in value]
                # Combine the expressions using OR and compile the result
                return self._compile_filter(reduce(or_, expressions))
            elif lookup == 'present' and not value:
                # Present with a false-y value is not present
                return self._compile_filter(~Expression(field, 'present', True))
            elif lookup == 'isnull':
                # isnull is the opposite of present
                return self._compile_filter(Expression(field, 'present', not value))
            else:
                # All other valid lookup types use patterns from the lookup table
                # Escape any dodgy characters in the value
                if isinstance(value, bytes):
                    value = ldap3.utils.conv.escape_bytes(value)
                else:
                    value = ldap3.utils.conv.escape_filter_chars(str(value))
                # Insert values into the filter template for the lookup type
                try:
                    return self._LOOKUP_TYPES[lookup].format(field = field, value = value)
                except KeyError:
                    raise ValueError("Unsupported lookup type - {}".format(lookup))
        elif isinstance(node, AndNode):
            return '(&{})'.format(''.join(self._compile_filter(c) for c in node.children))
        elif isinstance(node, OrNode):
            return '(|{})'.format(''.join(self._compile_filter(c) for c in node.children))
        elif isinstance(node, NotNode):
            return '(!{})'.format(self._compile_filter(node.child))
        else:
            raise ValueError("Unknown node type '{}'".format(repr(node)))

    def _run_query(self):
        return self._conn.search(self._base_dn,
                                 self._compile_filter(self._filter),
                                 self._scope)

    def _split_node(self, node):
        if isinstance(node, Expression):
            field, lookup = node.field, node.lookup_type or 'exact'
            # Comparison operators are not supported in LDAP, but we support them
            # in Python
            if lookup in ['gt', 'gte', 'lt', 'lte']:
                return None, node, None
            # Any lookups that are not for DN can be done in LDAP
            if field.lower() != 'dn':
                return node, None, None
            # DN lookups have to be exact to be done natively
            # Any other DN lookups are done in Python
            if lookup == 'exact':
                return None, None, node
            else:
                return None, node, None
        elif isinstance(node, AndNode):
            # This takes advantage of the fact that, because we are combining with
            # AND, the ordering doesn't matter
            ldap, python, dn = [], [], []
            for n in node.children:
                _0, _1, _2 = self._split_node(n)
                if _0: ldap.append(_0)
                if _1: python.append(_1)
                if _2: dn.append(_2)
            if len(dn) >= 2:
                # If there is more than one DN filter, add them to the python filter
                python += dn
                dn = None
            else:
                dn = dn[0] if dn else None
            if len(ldap) >= 2:
                ldap = AndNode(*ldap)
            else:
                ldap = ldap[0] if ldap else None
            if len(python) >= 2:
                python = AndNode(*python)
            else:
                python = python[0] if python else None
            return ldap, python, dn
        elif isinstance(node, OrNode):
            # Once ORs are involved, we can't split the filter - either the whole
            # node is applied in LDAP or the whole node is applied in Python
            for n in node.children:
                ldap, python, dn = self._split_node(n)
                if python or dn:
                    return None, node, None
            return node, None, None
        elif isinstance(node, NotNode):
            # We can't split a NOT query either
            ldap, python, dn = self._split_node(node.child)
            if python or dn:
                return None, node, None
            return node, None, None
        else:
            raise ValueError("Unknown node type '{}'".format(repr(node)))

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`

        We want to run as many filters in LDAP as we can.

        However, this becomes more complicated when we want to allow filtering by DN:

          * Any filters not involving DNs can be applied directly to LDAP

          * An exact filter on a single DN, possibly combined with non-DN filters
            **using AND only**, can be done purely in LDAP by using the DN as the
            search base with ENTITY scope

          * Any other filters involving DNs (e.g. an OR of a DN with other filters)
            need to be done in Python (boo)
        """
        ldap, python, dn = self._split_node(F(*args, **kwargs))
        query = self
        # If there is a DN node, we know it will be a single exact match
        if dn:
            if self._scope == Connection.SEARCH_SCOPE_ENTITY:
                # We are already a single DN search - DNs must match
                if dn.value.lower() != self._base_dn.lower():
                    # Filtering on two different DNs combined with AND can never
                    # have any results, regardless of other filters
                    return EmptyQuery.instance
            else:
                # We are not already a single DN search
                # The DN must fall under our existing base DN
                if dn.value.lower().endswith(self._base_dn.lower()):
                    query = Query(query._conn, dn.value,
                                  query._filter, Connection.SEARCH_SCOPE_ENTITY)
                else:
                    # If the DN is not under the base, there will never be any results
                    return EmptyQuery.instance
        # Apply the LDAP filter
        if ldap:
            query = Query(query._conn, query._base_dn,
                          query._filter & ldap, query._scope)
        # Apply the Python filter
        if python:
            query = FilteredQuery(query, python)
        return query


class AnnotatedQuery(QueryBase):
    """
    An LDAP query with additional annotations.

    :param query: The underlying query
    :param \*\*annotations: The annotations to apply
    """
    def __init__(self, query, annotations):
        self._query = query
        self._annotations = dict(annotations)

    def _run_query(self):
        for attrs in self._query:
            for attr, func in self._annotations.items():
                attrs[attr] = func(attrs)
            yield attrs

    def _split_node(self, node):
        """
        Splits the given filter node into two - one that can be applied to the
        underlying query (i.e. doesn't involve the annotations) and one that
        must be applied to the annotations.

        The two returned filters must be combinable using AND to be equivalent to
        the original node.

        If it is not possible or necessary to split the node, one of the nodes
        will be None.
        """
        if isinstance(node, Expression):
            if node.field in self._annotations:
                # If the node is querying an annotation it has to be applied to
                # the annotated query
                return (None, node)
            else:
                # Otherwise, it can be applied to the underlying query
                return (node, None)
        elif isinstance(node, AndNode):
            # This takes advantage of the fact that, because we are combining with
            # AND, the ordering doesn't matter
            left, right = [], []
            for n in node.children:
                _0, _1 = self._split_node(n)
                if _0: left.append(_0)
                if _1: right.append(_1)
            if len(left) >= 2:
                left = AndNode(*left)
            else:
                left = left[0] if left else None
            if len(right) >= 2:
                right = AndNode(*right)
            else:
                right = right[0] if right else None
            return (left, right)
        elif isinstance(node, OrNode):
            # Once ORs are involved, we can't split the query - either the whole
            # node is applied to the underlying query or the whole node is applied
            # to this query directly
            for n in node.children:
                left, right = self._split_node(n)
                if right:
                    return (None, node)
            return (node, None)
        elif isinstance(node, NotNode):
            # We can't split a NOT query either
            left, right = self._split_node(node.child)
            if right:
                return (None, node)
            return (node, None)
        else:
            raise ValueError("Unknown node type '{}'".format(repr(node)))

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Split the node into a part that can be applied to the underlying query
        # and a part that requires the annotations
        # We do this to push as much filtering into LDAP as possible
        left, right = self._split_node(F(*args, **kwargs))
        # Apply the left filter to the underlying query if there is one
        q = AnnotatedQuery(self._query.filter(left), self._annotations) if left else self
        # Apply the right hand filter to the annotated query
        return FilteredQuery(q, right) if right else q


class FilteredQuery(QueryBase):
    """
    A filtered query where all the filters are applied in Python.

    :param query: The underlying query
    :param filter: The filter to apply
    """
    def __init__(self, query, filter):
        self._query = query
        self._filter = filter

    def _compile_filter(self, node):
        """
        Recursively compiles a :py:class:`.filters.Node` into a boolean function
        that operates on an attribute dictionary.
        """
        if isinstance(node, Expression):
            # Use 'exact' as the default lookup type
            field, lookup, value = node.field, node.lookup_type or 'exact', node.value
            # DNs get special treatment - all lookups are case-insensitive
            if field.lower() == 'dn':
                if lookup == 'in':
                    def in_func(attrs):
                        return attrs.get(field, '').lower() in [v.lower() for v in value]
                    return in_func
                elif lookup.endswith('exact'):
                    def exact_func(attrs):
                        return attrs.get(field, '').lower() == value.lower()
                    return exact_func
                elif lookup.endswith('contains') or lookup == 'search':
                    def contains_func(attrs):
                        return value.lower() in attrs.get(field, '').lower()
                    return contains_func
                elif lookup.endswith('startswith'):
                    def starts_func(attrs):
                        return attrs.get(field, '').lower().startswith(value.lower())
                    return starts_func
                elif lookup.endswith('endswith'):
                    def ends_func(attrs):
                        return attrs.get(field, '').lower().endswith(value.lower())
                    return ends_func
                else:
                    raise ValueError("Unsupported lookup type - {}".format(lookup))
            # present is based on the whole attribute
            elif lookup == 'present':
                return lambda attrs: (bool(value) == bool(attrs.get(field, ())))
            # isnull is the inverse of present
            elif lookup == 'isnull':
                return lambda attrs: (bool(value) != bool(attrs.get(field, ())))
            # Everything else is element-wise, i.e. is there an element of the
            # attribute that matches
            else:
                # Try not to use regexes unless we have to
                if lookup == 'in':
                    elem_func = lambda el: el in value
                elif lookup == 'exact':
                    elem_func = lambda el: el == value
                elif lookup == 'iexact':
                    elem_func = lambda el: el.lower() == value.lower()
                elif lookup == 'contains':
                    elem_func = lambda el: value in el
                elif lookup == 'icontains' or lookup == 'search':
                    elem_func = lambda el: value.lower() in el.lower()
                elif lookup == 'startswith':
                    elem_func = lambda el: el.startswith(value)
                elif lookup == 'istartswith' :
                    elem_func = lambda el: el.lower().startswith(value.lower())
                elif lookup == 'endswith':
                    elem_func = lambda el: el.endswith(value)
                elif lookup == 'iendswith' :
                    elem_func = lambda el: el.lower().endswith(value.lower())
                elif lookup == 'gt':
                    elem_func = lambda el: el > value
                elif lookup == 'gte':
                    elem_func = lambda el: el >= value
                elif lookup == 'lt':
                    elem_func = lambda el: el < value
                elif lookup == 'lte':
                    elem_func = lambda el: el <= value
                else:
                    raise ValueError("Unsupported lookup type - {}".format(lookup))
                return lambda attrs: any(elem_func(v) for v in attrs.get(field, ()))
        elif isinstance(node, AndNode):
            child_funcs = [self._compile_filter(c) for c in node.children]
            return lambda attrs: all(f(attrs) for f in child_funcs)
        elif isinstance(node, OrNode):
            child_funcs = [self._compile_filter(c) for c in node.children]
            return lambda attrs: any(f(attrs) for f in child_funcs)
        elif isinstance(node, NotNode):
            child_func = self._compile_filter(node.child)
            return lambda attrs: not child_func(attrs)
        raise ValueError("Unknown node type '{}'".format(repr(node)))

    def _run_query(self):
        filter_func = self._compile_filter(self._filter)
        for attrs in self._query:
            if filter_func(attrs):
                yield attrs

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Apply the filter to the underlying query
        # This risks having nested FilteredQuerys for the advantage of pushing as
        # much filtering into LDAP as possible
        return FilteredQuery(self._query.filter(F(*args, **kwargs)), self._filter)


class OrderedQuery(QueryBase):
    """
    A query with ordering imposed.

    :param query: The underlying query
    :param orderings: The attributes to use for ordering - a ``-`` prefix indicates
                      a descending search
    """
    def __init__(self, query, orderings):
        self._query = query
        self._orderings = orderings

    def _compile_order(self, orderings):
        """
        Compiles the given orderings into a comparison function.
        """
        to_apply = []
        for o in orderings:
            descending = False
            if o.startswith('-'):
                descending = True
                o = o[1:]
            to_apply.append((o, descending))
        def compare(res1, res2):
            # res1 and res2 are attribute dictionaries
            # Apply each comparison in order
            # Note that we consider None to be bigger than anything else (i.e.
            # in an ascending sort, None comes after everything else)
            for attr, descending in to_apply:
                if descending:
                    x, y = res2.get(attr, []), res1.get(attr, [])
                else:
                    x, y = res1.get(attr, []), res2.get(attr, [])
                if x < y:
                    return -1
                elif x > y:
                    return 1
            return 0
        return compare

    def _run_query(self):
        compare_func = self._compile_order(self._orderings)
        yield from sorted(self._query, key = cmp_to_key(compare_func))

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Apply the filter to the underlying query
        return OrderedQuery(self._query.filter(*args, **kwargs), self._orderings)


class SlicedQuery(QueryBase):
    """
    A slice of a query.

    :param query: The underlying query
    :param low: The low index for the slice
    :param high: The high index for the slice
    :param step: The step for the slice
    """
    def __init__(self, query, low, high = None, step = 1):
        if low < 0 or (high is not None and high < 0) or step < 1:
            raise TypeError('Negative indexing of queries is not supported')
        self._query = query
        self._low = low
        self._high = high
        self._step = step

    def _run_query(self):
        pos = -1
        for attrs in self._query:
            pos += 1
            if pos < self._low:
                continue
            if self._high is not None and pos >= self._high:
                break
            if (pos - self._low) % self._step != 0:
                continue
            yield attrs


class SelectQuery(QueryBase):
    """
    A query with the attributes restricted.

    :param query: The underlying query
    :param attributes: The attributes to include in results
    """
    def __init__(self, query, attributes):
        self._query = query
        self._attributes = attributes

    def _run_query(self):
        for attrs in self._query:
            yield { k : v for k, v in attrs.items() if k in self._attributes }

    def select(self, *attributes):
        """
        See :py:meth:`QueryBase.select`
        """
        # There is no point in having directly nested selects
        return SelectQuery(self._query, attributes)

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Apply the filter directly to the underlying query
        return SelectQuery(self._query.filter(F(*args, **kwargs)), self._attributes)


class DistinctQuery(QueryBase):
    """
    A query that yields only distinct elements of the underlying query.

    :param query: The underlying query
    """
    def __init__(self, query):
        self._query = query

    def _run_query(self):
        seen = set()
        for attrs in self._query:
            # To put it in a set, we need to convert the entry to something hashable
            # We don't want to worry about ordering when comparing values, so each
            # value is also converted to a frozenset
            hashable = frozenset((k, frozenset(v)) for k, v in attrs.items())
            if hashable not in seen:
                seen.add(hashable)
                yield attrs

    def distinct(self):
        """
        See :py:meth:`QueryBase.distinct`
        """
        # There is no point in directly nested distinct queries
        return self

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Apply the filter directly to the underlying query
        return DistinctQuery(self._query.filter(F(*args, **kwargs)))
