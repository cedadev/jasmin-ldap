"""
This module defines the exceptions that can be thrown by :py:mod:`jasmin_ldap.datamapper`.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

from types import MappingProxyType


class DataMapperError(Exception):
    """
    Base class for errors thrown by the data-mapper.
    """


class SchemaNotFoundError(DataMapperError):
    """
    Raised when there is no schema associated with a class.
    """
