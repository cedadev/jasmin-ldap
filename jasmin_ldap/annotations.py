"""
Simple annotations for use with :py:class:`.query.Query`\ s.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"


def Count(attribute):
    """
    Returns an annotation that calculates the number of entries for a given
    attribute of an LDAP record.
    """
    return lambda attrs: len(attrs.get(attribute, []))


def Max(attribute):
    """
    Returns an annotation that calculates the maximum of the entries for a given
    attribute of an LDAP record.
    """
    def annot(attrs):
        # We want to return None on an empty attribute rather than throwing
        try:
            return max(attrs.get(attribute, []))
        except ValueError:
            return None
    return annot


def Min(attribute):
    """
    Returns an annotation that calculates the minimum of the entries for a given
    attribute of an LDAP record.
    """
    def annot(dn, attrs):
        # We want to return None on an empty attribute rather than throwing
        try:
            return min(attrs.get(attribute, []))
        except ValueError:
            return None
    return annot
