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


class QueryBase(metaclass = abc.ABCMeta):
    """
    Base class containing functionality common to all query types.
    """
    @abc.abstractmethod
    def __iter__(self):
        """
        Returns an iterator of the results from this query.
        """

    def one(self):
        """
        Returns a single result from the query, or ``None`` if there is no such
        object.
        """
        return next(iter(self), None)

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
        the dn and attribute dictionary as its arguments.

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
             for each entry in the query, and recieves the dn and attribute
             dictionary as arguments.
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
        # Do the accumulation
        for dn, attrs in self:
            for _, agg in aggregations.items():
                agg.accumulate(dn, attrs)
        # Return the results
        return { name : agg.result for name, agg in aggregations.items() }

    def __len__(self):
        """
        Returns the number of items in the query.
        """
        # To do this, we have to force all the results to be fetched
        return len(list(iter(self)))


class Query(QueryBase):
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
                return self._compile(~Expression(field, 'present', True))
            # isnull is the opposite of present
            elif lookup == 'isnull':
                return self._compile(~Expression(field, 'present', value))
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
            raise ValueError("Unknown node type '{}'".format(repr(node)))

    def __iter__(self):
        # Just compile the filter once on first use
        if not hasattr(self, '_filter_str'):
            self._filter_str = self._compile(self._filter)
        # We need to make sure we hold on to the connection until we have finished
        # iterating
        # To ensure that the connection gets released when a partial iteration is
        # finished with, we must turn GeneratorExit into StopIteration
        with self._pool.connection() as conn:
            try:
                yield from conn.search(self._base_dn, self._filter_str, self._scope)
            except GeneratorExit:
                raise StopIteration

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Rather than running the filters in Python, run them in LDAP
        return Query(self._pool, self._base_dn,
                     self._filter & F(*args, **kwargs), self._scope)


class AnnotatedQuery(QueryBase):
    """
    An LDAP query with additional annotations.

    :param query: The underlying query
    :param \*\*annotations: The annotations to apply
    """
    def __init__(self, query, annotations):
        self._query = query
        self._annotations = dict(annotations)

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
                # the annotated query
                return (None, node)
            else:
                # Otherwise, it can be applied to the underlying query
                return (node, None)
        elif isinstance(node, AndNode):
            # This takes advantage of the fact that, because we are combining with
            # AND, the ordering doesn't matter
            left, right = [], []
            for n in node.children:
                # Note that these nodes can be combined using AND to be equivalent
                # to n
                l, r = self._split_node(n)
                if l: left.append(l)
                if r: right.append(r)
            if len(left) >= 2:
                left = AndNode(*left)
            elif len(left) == 1:
                left = left[0]
            else:
                left = None
            if len(right) >= 2:
                right = AndNode(*right)
            elif len(right) == 1:
                right = right[0]
            else:
                right = None
            return (left, right)
        elif isinstance(node, OrNode):
            # Once ORs are involved, we can't split the query - either the whole
            # node is applied to the underlying query or the whole node is applied
            # to this query directly
            for n in node.children:
                left, right = self._split_node(n)
                if right:
                    return (None, node)
            return (node, None)
        elif isinstance(node, NotNode):
            # We can't split a NOT query either
            left, right = self._split_node(node.child)
            if right:
                return (None, node)
            return (node, None)
        else:
            raise ValueError("Unknown node type '{}'".format(repr(node)))

    def __iter__(self):
        for dn, attrs in self._query:
            for attr, func in self._annotations.items():
                # Make the result of the annotation look like it comes from LDAP
                # by wrapping it in a list
                annot = func(dn, attrs)
                if isinstance(annot, Iterable) and not isinstance(annot, str):
                    annot = list(annot)
                else:
                    annot = [annot]
                attrs[attr] = annot
            yield (dn, attrs)

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Split the node into a part that can be applied to the underlying query
        # and a part that requires the annotations
        # We do this to push as much filtering into LDAP as possible
        left, right = self._split_node(F(*args, **kwargs))
        # Apply the left filter to the underlying query if there is one
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

    def _compile(self, node):
        """
        Recursively compiles a :py:class:`.filters.Node` into a boolean function
        that operates on an attribute dictionary.
        """
        func = None
        if isinstance(node, Expression):
            # Use 'exact' as the default lookup type
            field, lookup, value = node.field, node.lookup_type or 'exact', node.value
            # present is based on the whole attribute
            if lookup == 'present':
                func = lambda attrs: (bool(value) == bool(attrs.get(field, ())))
            # isnull is the inverse of present
            elif lookup == 'isnull':
                func = lambda attrs: (bool(value) != bool(attrs.get(field, ())))
            # Everything else is element-wise, i.e. is there an element of the
            # attribute that matches
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
                else:
                    raise ValueError("Unsupported lookup type - {}".format(lookup))
                func = lambda attrs: any(elem_func(v) for v in attrs.get(field, ()))
        elif isinstance(node, AndNode):
            child_funcs = [self._compile(c) for c in node.children]
            func = lambda attrs: all(f(attrs) for f in child_funcs)
        elif isinstance(node, OrNode):
            child_funcs = [self._compile(c) for c in node.children]
            func = lambda attrs: any(f(attrs) for f in child_funcs)
        elif isinstance(node, NotNode):
            child_func = self._compile(node.child)
            func = lambda attrs: not child_func(attrs)
        if func is not None:
            return func
        else:
            raise ValueError("Unknown node type '{}'".format(repr(node)))

    def __iter__(self):
        # Compile the filter once on first use
        if not hasattr(self, '_filter_func'):
            self._filter_func = self._compile(self._filter)
        for dn, attrs in self._query:
            if self._filter_func(attrs):
                yield (dn, attrs)

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Apply the filter to the underlying query
        # This risks having nested FilteredQuerys for the advantage of pushing as
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

    def _compile(self, orderings):
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
            # res1 and res2 are (dn, attrs) pairs
            _, attrs1 = res1
            _, attrs2 = res2
            # Apply each comparison in order
            # Note that we consider None to be bigger than anything else (i.e.
            # in an ascending sort, None comes after everything else)
            for attr, descending in to_apply:
                if descending:
                    x, y = attrs2.get(attr, []), attrs1.get(attr, [])
                else:
                    x, y = attrs1.get(attr, []), attrs2.get(attr, [])
                if x < y:
                    return -1
                elif x > y:
                    return 1
            return 0
        return compare

    def __iter__(self):
        # Compile the comparison function
        if not hasattr(self, '_compare_func'):
            self._compare_func = self._compile(self._orderings)
        yield from sorted(self._query, key = cmp_to_key(self._compare_func))

    def filter(self, *args, **kwargs):
        """
        See :py:meth:`QueryBase.filter`
        """
        # Apply the filter to the underlying query
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

    def __iter__(self):
        pos = -1
        for entry in self._query:
            pos += 1
            if pos < self._low:
                continue
            if self._high is not None and pos >= self._high:
                break
            if (pos - self._low) % self._step != 0:
                continue
            yield entry
