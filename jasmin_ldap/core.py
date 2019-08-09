"""
This module provides a layer over `ldap3 <https://ldap3.readthedocs.org/>`_ that
is intended to be more intuitive and easier to mock.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

import logging, contextlib, collections, random

import ldap3

from . import exceptions


_log = logging.getLogger(__name__)


class ServerPool(collections.namedtuple('ServerPool', ['primary', 'replicas'])):
    """
    Represents a pool of servers consisting of a single read-write host, referred
    to as the 'primary' host, and zero or more read-only replicas. Each entry can
    be ``None``, for example if there are no replicas or if only read-only access
    is required.

    Each server can be either a server name (e.g. `ldap.organisation.com`), a full
    LDAP URI (e.g. `ldaps://ldap.organisation.com:8636`) or an `ldap3.Server` instance,
    depending on whether complex configuration is required.

    Attributes:
        primary: Hostname of the primary host.
        replicas: Hostnames of the replicas.
    """
    DEFAULT_CONNECT_TIMEOUT = 1.0

    def __new__(cls, primary = None, replicas = None):
        def as_server(server):
            if isinstance(server, ldap3.Server):
                return server
            return ldap3.Server(server, connect_timeout = cls.DEFAULT_CONNECT_TIMEOUT)
        return super().__new__(
            cls,
            as_server(primary) if primary else None,
            tuple(as_server(s) for s in (replicas or []))
        )


def _convert(values):
    """
    Tries to convert an iterable of string values from LDAP into int/float for
    comparisons.

    If the conversion fails for any element, the original strings are returned.
    """
    def _f(v):
        try:
            return int(v)
        except ValueError:
            try:
                return float(v)
            except ValueError:
                return v.decode('utf-8')
    return [_f(v) for v in values]

def _is_empty(value):
    """
    Returns True if a value is considered empty, False otherwise.
    """
    if isinstance(value, collections.Iterable) and not isinstance(value, str):
        return not bool(value)
    elif value is None:
        return True
    elif value == '':
        return True
    return False


class Connection:
    """
    Represents an authenticated LDAP connection.

    Connections can be used in a `with` statement to ensure that the connection
    is closed when it is finished with::

        servers = ServerPool('ldap://ldap.mycompany.com')
        with Connection.create(servers, user, passwd) as conn:
            # ... do something with conn ...
    """
    #: Mode for a read-only connection
    MODE_READONLY = 0
    #: Mode for a read-write connection
    MODE_READWRITE = 1

    #: Scope to search entire subtree
    SEARCH_SCOPE_SUBTREE = ldap3.SUBTREE
    #: Scope to search just a single level
    SEARCH_SCOPE_SINGLE_LEVEL = ldap3.LEVEL
    #: Scope to search for a single entity (allows searching for a DN)
    SEARCH_SCOPE_ENTITY = ldap3.BASE

    def __init__(self, conn, mode):
        self._conn = conn
        self._mode = mode

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Just attempt to close the connection, but don't supress exceptions from
        # inside the with statement
        self.close()
        return False

    @contextlib.contextmanager
    def _connection(self):
        """
        Context manager for the ldap3 connection that converts ldap3 exceptions
        to the appropriate exception from the ``exceptions`` module.
        """
        try:
            yield self._conn
        except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult as e:
            raise exceptions.ObjectAlreadyExistsError from e
        except ldap3.core.exceptions.LDAPNoSuchObjectResult as e:
            raise exceptions.NoSuchObjectError from e
        except ldap3.core.exceptions.LDAPObjectClassViolationResult as e:
            raise exceptions.SchemaViolationError from e
        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult as e:
            raise exceptions.PermissionDeniedError from e
        except ldap3.core.exceptions.LDAPOperationResult as e:
            raise exceptions.OperationalError from e
        except ldap3.core.exceptions.LDAPExceptionError as e:
            raise exceptions.ConnectionError from e
        except ldap3.core.exceptions.LDAPException as e:
            raise exceptions.LDAPError from e

    def search(self, base_dn, filter_str, scope = SEARCH_SCOPE_SINGLE_LEVEL):
        """
        Perform an LDAP search to find entries that match the given LDAP filter
        string under the given base DN and scope.

        Returns an iterable of attribute dictionaries. The attribute dictionary
        maps attribute names to a **list of values** for that attribute, even
        when there is only one value.

        Args:
            base_dn: The base DN for the search.
            filter_str: The LDAP filter string for the search.
            scope: The search scope, one of :py:const:`SEARCH_SCOPE_SUBTREE`,
                :py:const:`SEARCH_SCOPE_SINGLE_LEVEL` or
                :py:const:`SEARCH_SCOPE_ENTITY` (optional, defaults to
                :py:const:`SEARCH_SCOPE_SINGLE_LEVEL`).

        Returns:
            An iterable of attribute dictionaries

        Raises:
            Any of the exceptions from :py:mod:`~.exceptions`.
        """
        _log.debug('Performing LDAP search (base_dn: {}, filter: {})'.format(base_dn, filter_str))
        with self._connection() as conn:
            try:
                # Get a generator of results using a paged search
                # This saves memory for large result sets
                # For now, use the default page size (100 at time of writing)
                entries = conn.extend.standard.paged_search(
                    search_base = base_dn,
                    search_filter = filter_str,
                    search_scope = scope,
                    attributes = ldap3.ALL_ATTRIBUTES,
                    generator = True,
                )
                for entry in entries:
                    yield entry
                    continue
                    # Try to convert each attribute to numeric values
                    attrs = { k : _convert(v) for k, v in entry['raw_attributes'].items() }
                    # Add the dn to the attribute dictionary before yielding
                    attrs['dn'] = entry['dn']
                    yield attrs
            except ldap3.core.exceptions.LDAPNoSuchObjectResult as e:
                # NoSuchObject means an empty search
                return

    def create_entry(self, dn, attributes):
        """
        Creates an entry at the given DN with the given attributes.

        Args:
            dn: The DN to create.
            attributes: The attributes to give the new entry.

        Returns:
            ``True`` on success (should raise on failure).

        Raises:
            Any of the exceptions from :py:mod:`~.exceptions`.
        """
        _log.debug('Creating LDAP entry at dn {}'.format(dn))
        if self._mode is not self.MODE_READWRITE:
            raise exceptions.OperationNotAllowedError(
                'Write operation attempted with read-only connection'
            )
        # Prepare the attributes for insertion by removing any keys with empty values
        attributes = { k : v for k, v in attributes.items() if not _is_empty(v) }
        with self._connection() as conn:
            conn.add(dn, attributes = attributes)
        return True

    def update_entry(self, dn, attributes):
        """
        Updates the given DN with the given attributes. Note that this will **ONLY**
        affect attributes that explicitly given. Attributes that are not given
        will be left untouched.

        Args:
            dn: The DN to update.
            attributes: The attributes to update on the entry.

        Returns:
            ``True`` on success (should raise on failure).

        Raises:
            Any of the exceptions from :py:mod:`~.exceptions`.
        """
        _log.debug('Updating LDAP entry at dn {}'.format(dn))
        if self._mode is not self.MODE_READWRITE:
            raise exceptions.OperationNotAllowedError(
                'Write operation attempted with read-only connection'
            )
        def to_tuple(value):
            if isinstance(value, collections.Iterable) and not isinstance(value, str):
                return tuple(value)
            elif _is_empty(value):
                return ()
            else:
                return (value, )
        # Indicate that the attributes should replace any existing attributes
        attributes = {
            name : (ldap3.MODIFY_REPLACE, to_tuple(value))
            for name, value in attributes.items()
        }
        with self._connection() as conn:
            conn.modify(dn, attributes)
        return True

    def set_entry_password(self, dn, password):
        """
        Sets the password for the entry with the given DN.

        Args:
            dn: The DN of the entry to set the password for.
            password: The plaintext password.

        Returns:
            ``True`` on success (should raise on failure).

        Raises:
            Any of the exceptions from :py:mod:`~.exceptions`.
        """
        _log.debug('Updating password for dn {}'.format(dn))
        if self._mode is not self.MODE_READWRITE:
            raise exceptions.OperationNotAllowedError(
                'Write operation attempted with read-only connection'
            )
        with self._connection() as conn:
            conn.extend.standard.modify_password(dn, None, password)
        return True

    def delete_entry(self, dn):
        """
        Deletes the entry with the given DN.

        Args:
            dn: The DN to delete.

        Returns:
            ``True`` on success (should raise on failure).

        Raises:
            Any of the exceptions from :py:mod:`~.exceptions`.
        """
        _log.debug('Deleting LDAP entry at dn {}'.format(dn))
        if self._mode is not self.MODE_READWRITE:
            raise exceptions.OperationNotAllowedError(
                'Write operation attempted with read-only connection'
            )
        with self._connection() as conn:
            conn.delete(dn)
        return True

    def close(self):
        """
        Closes the connection.

        Returns:
            ``True`` on success (should raise on failure).

        Raises:
            Any of the exceptions from :py:mod:`~.exceptions`.
        """
        _log.debug('Closing LDAP connection')
        with self._connection() as conn:
            conn.unbind()
        return True

    @classmethod
    def create(cls, pool, user = '', password = '', mode = MODE_READONLY):
        """
        Creates a new LDAP connection with the given arguments.

        If no user is given, an anonymous connection is started. Connections will
        *always* use TLS.

        For read-write connections, only the primary is used.

        Args:
            pool: The :py:class:`ServerPool` to connect to.
            user: The DN to connect with. If not given, an anonymous connection will
                be used.
            password: The password to connect with. Must be given if `user` is given.
            mode: The required mode for the connection. Must be one of
                :py:const:`MODE_READONLY` or :py:const:`MODE_READWRITE`.
                Defaults to :py:const:`MODE_READONLY`.

        Returns:
            A :py:class:`Connection`.

        Raises:
            Any of the exceptions from :py:mod:`~.exceptions`.
        """
        if mode not in [cls.MODE_READONLY, cls.MODE_READWRITE]:
            raise ValueError('Invalid mode given')
        # In read-write mode, we can only choose the primary
        # In read-only mode, try and use the primary first (as it has the canonical
        # view of the data), but fall back to replicas if not available
        servers = list(pool.replicas) if mode is cls.MODE_READONLY else []
        random.shuffle(servers)
        if pool.primary:
            servers.insert(0, pool.primary)
        # Try each server until we get a successful connection
        for server in servers:
            try:
                _log.debug('Opening LDAP connection to {} for {}'.format(server, user))
                return cls(
                    ldap3.Connection(
                        server, user = user, password = password,
                        auto_bind = ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                        raise_exceptions = True
                    ),
                    mode
                )
            except ldap3.core.exceptions.LDAPOperationResult as e:
                # The first time we get an actual authentication failure, assume
                # that it will also be the case for the other servers and bail
                raise exceptions.AuthenticationError('Invalid user DN or password')
            except ldap3.core.exceptions.LDAPException as e:
                # For other LDAP exceptions, log them and try the next server
                _log.exception('Failed to open connection to {} for {}'.format(server, user))
        # If we exit the loop without returning a connection, there are no available servers
        raise exceptions.NoServerAvailableError('No suitable server available')
