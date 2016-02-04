"""
This module provides facilities for building complex filters.

Individual filters use a ``field, lookup type, value`` structure inspired by the
`Django ORM <https://docs.djangoproject.com/en/1.8/topics/db/queries/#field-lookups>`_.

Individual filters can then be combined using logical operators (AND, OR and NOT)
to form filters of arbitrary complexity.

The filters themselves provide no specific functionality other than to build the
tree-like structure. It is up to individual consumers to process or "compile" the
filters as they require.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

from collections import namedtuple


def F(*args, **kwargs):
    """
    Utility function for easily creating :py:class:`Node`\ s.

    Positional arguments should be :py:class:`Node` objects.

    Keyword arguments should be of the form ``field__lookuptype = value``, similar
    to the Django ORM. If no lookup type is given, ``None`` is used.

    The filters are combined using AND.
    """
    filters = []
    # Check that all the given args are nodes
    for f in args:
        if not isinstance(f, Node):
            raise ValueError('Positional arguments must be nodes')
        filters.append(f)
    # Turn the keyword args into expressions
    for spec, value in kwargs.items():
        field, lookup_type, *notused = spec.split('__') + [None]
        filters.append(Expression(field, lookup_type, value))
    # If there are no filters, that is an error
    if not filters:
        raise ValueError('No arguments given')
    # If there is one filter, return it
    if len(filters) == 1:
        return filters[0]
    # Otherwise, combine them with AND
    return AndNode(*filters)


class Node:
    """
    Represents a node in the filter expression tree.

    The ``&`` (AND), ``|`` (OR) and ``~`` (NOT) operators can be used to combine
    nodes into more complex filters.
    """

    def and_(self, other):
        """
        Returns a new node that combines this node and the given node using AND.
        """
        return AndNode(self, other)

    def or_(self, other):
        """
        Returns a new node that combines this node and the given node using OR.
        """
        return OrNode(self, other)

    def not_(self):
        """
        Returns a new node that negates this node using NOT.
        """
        return NotNode(self)

    ############################################################################
    ## Magic methods for & (AND), | (OR) and ~ (NOT) operators
    ############################################################################

    def __and__(self, other):
        return self.and_(other)

    def __or__(self, other):
        return self.or_(other)

    def __invert__(self):
        return self.not_()


class Expression(namedtuple('_Expression',
                            ['field', 'lookup_type', 'value']), Node):
    """
    Node type for a single expression with a field, a lookup type and a value.

    .. py:attribute:: field

        The field to which the expression relates.

    .. py:attribute:: lookup_type

        The lookup type associated with the expression, as a plain string. If no
        lookup type is given, this can be ``None``.

    .. py:attribute:: value

        The value associated with the expression.
    """


class AndNode(Node):
    """
    Node type for combining two or more nodes using AND.
    """
    def __init__(self, first, second, *others):
        self._children = (first, second) + tuple(others)

    @property
    def children(self):
        """
        Returns the child nodes that should be combined using AND.
        """
        return self._children

    def and_(self, other):
        # Customise AND to just add a child instead of increasing the tree depth
        children = self._children + (other, )
        return AndNode(*children)


class OrNode(Node):
    """
    Node type for combining two or more nodes using OR.
    """
    def __init__(self, first, second, *others):
        self._children = (first, second) + tuple(others)

    @property
    def children(self):
        """
        Returns the child nodes that should be combined using OR.
        """
        return self._children

    def or_(self, other):
        # Customise OR to just add a child instead of increasing the tree depth
        children = self._children + (other, )
        return OrNode(*children)


class NotNode(Node):
    """
    Node type for negating a node using NOT.
    """
    def __init__(self, node):
        self._child = node

    @property
    def child(self):
        """
        Returns the node that is being negated using NOT.
        """
        return self._child

    def not_(self):
        # Customise NOT to just return the underlying node
        return self._child
