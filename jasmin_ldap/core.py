"""
This module provides a layer over `ldap3 <https://ldap3.readthedocs.org/>`_ that
is intended to be more intuitive and easier to mock.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

import logging
import contextlib, queue, functools
from collections import Iterable

import ldap3

from .exceptions import *


_log = logging.getLogger(__name__)


class Server:
    """
    Represents an LDAP server.

    :param server: The path to the server
    """
    def __init__(self, server):
        self._server = server

    def authenticate(self, user = '', password = ''):
        """
        Attempts to authenticate the given user and password with the LDAP server
        and returns a :py:class:`Connection`.

        If no user is given, an anonymous connection is started. Connections will
        *always* use TLS.

        :param user: The DN to authenticate with (optional)
        :param password: The password to authenticate with (optional)
        :returns: The authenticated :py:class:`Connection`
        """
        try:
            _log.debug('Opening LDAP connection to {} for {}'.format(self._server, user))
            return Connection(ldap3.Connection(
                self._server, user = user, password = password,
                auto_bind = ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                raise_exceptions = True
            ))
        except ldap3.core.exceptions.LDAPOperationResult as e:
            # If the bind fails as a result of an operation failure (not a
            # connection error or similar), treat that as an auth failure
            raise AuthenticationError('Authentication failed') from e
        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPError('Error while opening connection') from e


class ConnectionPool:
    """
    Represents a pool of active connections, all bound with the same username and
    password. The pool is thread-safe in the sense that two threads cannot get
    the same connection as long as they are both using the pool properly. It
    *is* possible for a single thread to acquire two different connections though,
    if it acquires a second connection before it is finished with the first (i.e.
    if there is an in-progress paged search).

    The recommended way to use the connection pool is via the context manager
    support. This ensures the connection is released back to the pool:

    ::

        pool = ConnectionPool(...)
        with pool.connection() as conn:
            # ... Do something with the connection ...

    The connection should not be released to the pool until the consumer is finished
    with it (since it may get closed or re-used). This is particularly troublesome
    for searching - because :py:class:`Connection`\ s use paged search to fetch
    results in batches, the connection must be held until all the results have
    been iterated over.

    When a connection is acquired, the pool is checked, and if there is an idle
    connection it is returned. If there is no idle connection, a new connection
    is created and returned.

    When a connection is released to the pool, we first check to see if there is
    space for it (i.e. have we already got ``max_size`` idle connections in the
    pool). If there is space, we add it to the pool. If there is no space, the
    connection is closed.

    If there is a problem with a connection while using it, don't release it back
    to the pool. However, you shoudl ensure it is closed. When using the context
    manager support (i.e. :py:meth:`ConnectionPool.connection`), all this is
    handled for you.

    This pattern hopefully facilitates some reuse of connections while always
    making sure clients can get a connection when they want one.

    The ``q`` argument can be any object supporting the same interface as
    ``queue.Queue`` - in particular, ``multiprocessing.Queue`` can be used. This
    is also how the maximum size of the pool should be changed (i.e. by creating
    a queue with the required maximum size).

    :param server: The :py:class:`Server` or server address to use
    :param username: The DN to bind using (if not given, anonymous bind is used)
    :param password: The password to bind with
    :param q: The queue to use (optional, defaults to ``queue.Queue(5)``)
    """
    def __init__(self, server, username = '', password = '', q = None):
        if not isinstance(server, Server):
            server = Server(server)
        self._server = server
        self._bind_dn = username
        self._bind_pass = password
        self._queue = q or queue.Queue(5)

    def acquire(self):
        """
        Get a connection from the pool.

        :returns: A :py:class:`Connection`
        """
        try:
            # Return an idle connection if available
            return self._queue.get_nowait()
        except queue.Empty:
            # If none are available, create a new one
            return self._server.authenticate(self._bind_dn, self._bind_pass)

    def release(self, conn):
        """
        Releases a connection back to the pool.

        :param conn: The :py:class:`Connection` to release
        """
        try:
            # Try to put the connection into the idle queue
            self._queue.put_nowait(conn)
        except queue.Full:
            # If the queue is full, nuke the connection
            conn.close()

    def close_all(self):
        """
        Closes all the connections and empties the pool.
        """
        # Swap the queue for a queue of size 0 so that any connections returned to
        # the pool after this method is called are automatically closed
        q, self._queue = self._queue, queue.Queue(0)
        while True:
            try:
                q.get_nowait().close()
            except queue.Empty:
                break

    @contextlib.contextmanager
    def connection(self):
        """
        Context manager that manages the acquisition and release of connections
        from the pool.
        """
        conn = self.acquire()
        try:
            yield conn
            # If the operation completes successfully, return conn to the pool
            self.release(conn)
        except OperationalError:
            # If an 'acceptable' LDAPError occurs, release the connection
            self.release(conn)
            raise
        except LDAPError:
            # If any other LDAPError occurs, nuke the connection
            conn.close()
            raise
        except Exception:
            # Any other exception is probably not the connection's fault
            self.release(conn)
            raise


def _convert_ldap_errors(f):
    """
    Decorator for methods that catches and converts ldap3 errors.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult as e:
            raise ObjectAlreadyExistsError('Object already exists') from e
        except ldap3.core.exceptions.LDAPNoSuchObjectResult as e:
            raise NoSuchObjectError('Object does not exist') from e
        except ldap3.core.exceptions.LDAPObjectClassViolationResult as e:
            raise SchemaViolationError('Schema violation occured') from e
        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult as e:
            raise PermissionDeniedError('Permission denied') from e
        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPError('An LDAP error occured') from e
    return wrapper


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
    Returns True if a value is considered non-empty, False otherwise.
    """
    if isinstance(value, Iterable) and not isinstance(value, str):
        return not bool(value)
    elif value is None:
        return True
    elif value == '':
        return True
    return False


class Connection:
    """
    Represents an authenticated LDAP connection.

    Because :py:class:`Connection` has a ``close`` method, it is easy to use in
    a ``with`` statement (which ensures the connection is closed even if an error
    occurs):

    ::

        from contextlib import closing

        s = Server('ldap://ldap.mycompany.com')
        with closing(s.authenticate(user, passwd)) as c:
            # ... do something ...

    :param conn: The underlying ``ldap3.Connection``
    """
    def __init__(self, conn):
        self._conn = conn

    #: Scope to search entire subtree
    SEARCH_SCOPE_SUBTREE      = ldap3.SUBTREE
    #: Scope to search just a single level
    SEARCH_SCOPE_SINGLE_LEVEL = ldap3.LEVEL
    #: Scope to search for a single entity (allows searching for a DN)
    SEARCH_SCOPE_ENTITY = ldap3.BASE

    @_convert_ldap_errors
    def search(self, base_dn, filter_str, scope = SEARCH_SCOPE_SINGLE_LEVEL):
        """
        Perform an LDAP search to find entries that match the given LDAP filter
        string under the given base DN and scope.

        Returns an iterable of attribute dictionaries. The attribute dictionary
        maps attribute names to a **list of values** for that attribute, even
        when there is only one value.

        :param base_dn: The base DN for the search
        :param filter_str: The LDAP filter string for the search
        :param scope: The search scope, one of ``Connection.SEARCH_SCOPE_SUBTREE``,
                      ``Connection.SEARCH_SCOPE_SINGLE_LEVEL`` or
                      ``Connection.SEARCH_SCOPE_ENTITY`` (optional)
        :returns: An iterable of attribute dictionaries
        """
        _log.debug('Performing LDAP search (base_dn: {}, filter: {})'.format(base_dn, filter_str))
        try:
            # Get a generator of results using a paged search
            # This saves memory for large result sets
            # For now, use the default page size (100 at time of writing)
            entries = self._conn.extend.standard.paged_search(
                search_base = base_dn,
                search_filter = filter_str,
                search_scope = scope,
                attributes = ldap3.ALL_ATTRIBUTES,
                generator = True,
            )
            for entry in entries:
                # Try to convert each attribute to numeric values
                attrs = { k : _convert(v) for k, v in entry['raw_attributes'].items() }
                # Add the dn to the attribute dictionary before yielding
                attrs['dn'] = entry['dn']
                yield attrs
        except ldap3.core.exceptions.LDAPNoSuchObjectResult as e:
            # NoSuchObject means an empty search
            return
        except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult as e:
            raise ObjectAlreadyExistsError('Object already exists') from e
        except ldap3.core.exceptions.LDAPObjectClassViolationResult as e:
            raise SchemaViolationError('Schema violation occured') from e
        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult as e:
            raise PermissionDeniedError('Permission denied') from e
        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPError('An LDAP error occured') from e

    @_convert_ldap_errors
    def create_entry(self, dn, attributes):
        """
        Creates an entry at the given DN with the given attributes.

        :param dn: The DN to create
        :param attributes: The attributes to give the new entry
        :returns: ``True`` on success (should raise on failure)
        """
        _log.debug('Creating LDAP entry at dn {}'.format(dn))
        # Prepare the attributes for insertion by removing any keys with empty values
        attributes = { k : v for k, v in attributes.items() if not _is_empty(v) }
        self._conn.add(dn, attributes = attributes)
        return True

    @_convert_ldap_errors
    def update_entry(self, dn, attributes):
        """
        Updates the given DN with the given attributes. Note that this will **ONLY**
        affect attributes that explicitly given. Attributes that are not given
        will be left untouched.

        :param dn: The DN to update
        :param attributes: The attributes to update on the entry
        :returns: ``True`` on success (should raise on failure)
        """
        _log.debug('Updating LDAP entry at dn {}'.format(dn))
        def to_tuple(value):
            if isinstance(value, Iterable) and not isinstance(value, str):
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
        self._conn.modify(dn, attributes)
        return True

    @_convert_ldap_errors
    def set_entry_password(self, dn, password):
        """
        Sets the password for the entry with the given DN.

        :param dn: The DN of the entry to set the password for
        :param password: The plaintext password
        :returns: ``True`` on success (should raise on failure)
        """
        _log.debug('Updating password for dn {}'.format(dn))
        self._conn.extend.standard.modify_password(dn, None, password)
        return True

    @_convert_ldap_errors
    def rename_entry(self, old_dn, new_dn):
        """
        Moves the entry at ``old_dn`` to ``new_dn``.

        :param old_dn: The current DN of the item
        :param new_dn: The new DN of the item
        :returns: ``True`` on success (should raise on failure)
        """
        _log.debug('Renaming LDAP entry from {} to {}'.format(old_dn, new_dn))
        # This is implemented as an add + a remove
        # First, get the attributes of the existing entry
        try:
            existing = next(self.search(old_dn, '(objectClass=*)', self.SEARCH_SCOPE_ENTITY))
            existing.pop('dn')
            existing.pop('cn')
        except StopIteration:
            raise NoSuchObjectError('No object at {}'.format(old_dn))
        # Remove the old entry
        self.delete_entry(old_dn)
        # Create the new entry
        self.create_entry(new_dn, existing)
        return True

    @_convert_ldap_errors
    def delete_entry(self, dn):
        """
        Deletes the entry with the given DN.

        :param dn: The DN to delete
        :returns: ``True`` on success (should raise on failure)
        """
        _log.debug('Deleting LDAP entry at dn {}'.format(dn))
        self._conn.delete(dn)
        return True

    @_convert_ldap_errors
    def close(self):
        """
        Closes the connection.

        :returns: ``True`` on success (should raise on failure)
        """
        _log.debug('Closing LDAP connection')
        self._conn.unbind()
        return True
