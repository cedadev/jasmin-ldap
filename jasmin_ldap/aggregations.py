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
        self.result = 0

    def accumulate(self, attrs):
        self.result += 1


class Max:
    """
    Aggregation that computes the maximum value of an attribute across a query.

    :param attribute: The attribute to compute the max of
    """
    def __init__(self, attribute):
        self._attribute = attribute
        self.reset()

    def reset(self):
        self.result = None

    def accumulate(self, attrs):
        try:
            value = max(attrs.get(self._attribute, []))
        except ValueError:
            # If the attribute has no values, exclude it from results
            return
        self.result = value if self.result is None else max(self.result, value)


class Min:
    """
    Aggregation that computes the minimum value of an attribute across a query.

    :param attribute: The attribute to compute the min of
    """
    def __init__(self, attribute):
        self._attribute = attribute
        self.reset()

    def reset(self):
        self.result = None

    def accumulate(self, attrs):
        try:
            value = min(attrs.get(self._attribute, []))
        except ValueError:
            # If the attribute has no values, exclude it from results
            return
        self.result = value if self.result is None else min(self.result, value)
