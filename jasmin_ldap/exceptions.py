"""
This module defines the exceptions that can be thrown by :py:mod:`jasmin_ldap`.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"


class LDAPError(Exception):
    """
    Raised when an LDAP error occurs.
    """


class ConnectionError(LDAPError):
    """
    Raised when there is an error with the LDAP connection itself, as opposed to
    a problem executing an operation (see :py:class:`OperationalError`).
    """


class NoServerAvailableError(ConnectionError):
    """
    Raised when a connection cannot be established to a suitable server.
    """


class OperationalError(LDAPError):
    """
    Raised when an operational error occurs, i.e. an error that results from a
    bad request rather than a problem with the connection per-se.
    """


class OperationNotAllowedError(OperationalError):
    """
    Raised when an attempt is made to perform an operation that is not allowed,
    i.e. attempting a write operation on a read-only connection.
    """


class AuthenticationError(OperationalError, ValueError):
    """
    Raised when authentication of a connection fails.
    """


class NoSuchObjectError(OperationalError, ValueError):
    """
    Raised when an operation is attempted on a non-existent object.
    """


class ObjectAlreadyExistsError(OperationalError, ValueError):
    """
    Raised when attempting to create an object that already exists.
    """


class PermissionDeniedError(OperationalError):
    """
    Raised when the connection does not have permission to perform the requested
    operation.
    """


class SchemaViolationError(OperationalError, ValueError):
    """
    Raised when a schema violation occurs.
    """
