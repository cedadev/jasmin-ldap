"""
Simple annotations for use with :py:class:`.query.Query`\ s.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"


class Count:
    """
    Aggregation that counts the number of items in a query.
    """
    def __init__(self):
        self.reset()

    def reset(self):
        # Note - to make the result look like any other LDAP attribute, we wrap
        # it in a list
        self.result = [0]

    def accumulate(self, dn, attrs):
        self.result[0] += 1


class Max:
    """
    Aggregation that computes the maximum value of an attribute across a query.

    :param attribute: The attribute to compute the max of
    """
    def __init__(self, attribute):
        self._attribute = attribute
        self.reset()

    def reset(self):
        self.result = []

    def accumulate(self, dn, attrs):
        value = attrs.get(self._attribute, [])
        # The value only affects the result if it is non-empty
        if value:
            self.result = max(self.result, value)


class Min:
    """
    Aggregation that computes the minimum value of an attribute across a query.

    :param attribute: The attribute to compute the min of
    """
    def __init__(self, attribute):
        self._attribute = attribute
        self.reset()

    def reset(self):
        self.result = []

    def accumulate(self, dn, attrs):
        value = attrs.get(self._attribute, [])
        # The value only affects the result if it is non-empty
        if value:
            # If the current result is the empty list, use the value
            if self.result:
                self.result = min(self.result, value)
            else:
                self.result = value
