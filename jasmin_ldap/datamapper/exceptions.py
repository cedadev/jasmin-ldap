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


class SchemaValidationError(DataMapperError, ValueError):
    """
    Raised when there are one or more errors validating or converting a schema.

    ``errors`` should be a mapping of field names to the error for that field
    as a 'stringy' value.

    To indicate errors that are not field-specific, the special key
    :py:attr:`SchemaValidationError.NON_FIELD_ERRORS` can be used.
    """
    #: Key for errors that apply to the schema as a whole
    NON_FIELD_ERRORS = '__all__'

    def __init__(self, errors):
        self._errors = dict(errors)
        super().__init__('One or more fields has errors')

    @property
    def errors(self):
        """
        The mapping of field names to specific errors.
        """
        return MappingProxyType(self._errors)

    def __str__(self):
        return repr(self._errors)

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, self)
