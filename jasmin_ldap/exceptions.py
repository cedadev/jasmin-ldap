"""
This module defines the exceptions that can be thrown by :py:mod:`jasmin_ldap`.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"


class LDAPError(Exception):
    """
    Raised when an LDAP error occurs.

    Will **always** be raised with the underlying
    `ldap3 exception <https://ldap3.readthedocs.org/exceptions.html>`_ as the
    cause using the ``raise ... from`` syntax.
    """


class AuthenticationError(LDAPError, ValueError):
    """
    Raised when authentication of a connection fails.
    """


class NoSuchObjectError(LDAPError, ValueError):
    """
    Raised when an operation is attempted on a non-existent object.
    """


class ObjectAlreadyExistsError(LDAPError, ValueError):
    """
    Raised when attempting to create an object that already exists.
    """


class PermissionDeniedError(LDAPError):
    """
    Raised when the connection does not have permission to perform the requested
    operation.
    """
