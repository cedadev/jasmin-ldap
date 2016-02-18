"""
This module provides a layer over `ldap3 <https://ldap3.readthedocs.org/>`_ that
is intended to be more intuitive and easier to mock.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

import contextlib, queue

import ldap3

from .exceptions import *


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
            return Connection(ldap3.Connection(
                self._server, user = user, password = password,
                auto_bind = ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                raise_exceptions = True
            ))
        except ldap3.LDAPOperationResult as e:
            # If the bind fails as a result of an operation failure (not a
            # connection error or similar), treat that as an auth failure
            raise AuthenticationError('Authentication failed') from e
        except ldap3.LDAPException as e:
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
        except (NoSuchObjectError):
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


class Connection:
    """
    Represents an authenticated LDAP connection.

    Because :py:class:`Connection` has a ``close`` method, it is easy to use in
    a ``with`` statement (which ensures the connection is closed even if an error
    occurs):

    ::

        from contextlib import closing

        server = Server('ldap://ldap.mycompany.com')
        with closing(s.authenticate(user, passwd)) as c:
            # ... do something ...

    :param conn: The underlying ``ldap3.Connection``
    """
    def __init__(self, conn):
        self._conn = conn

    #: Scope to search entire subtree
    SEARCH_SCOPE_SUBTREE      = ldap3.SEARCH_SCOPE_WHOLE_SUBTREE
    #: Scope to search just a single level
    SEARCH_SCOPE_SINGLE_LEVEL = ldap3.SEARCH_SCOPE_SINGLE_LEVEL

    def search(self, base_dn, filter_str, scope = SEARCH_SCOPE_SINGLE_LEVEL):
        """
        Perform an LDAP search to find entries that match the given LDAP filter
        string under the given base DN and scope.

        Returns an iterable of tuples, where each tuple contains ``(dn, attributes)``.

        ``attributes`` is a dictionary mapping attribute name to a **list of values**
        for that attribute. Note that a list of values is **always** returned,
        even when there is only value.

        :param base_dn: The base DN for the search
        :param filter_str: The LDAP filter string for the search
        :returns: An iterable of ``(dn, attributes)`` tuples
        """
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
                yield (entry['dn'], entry['attributes'])
        except ldap3.LDAPException as e:
            raise LDAPError('Error while searching') from e

    def get_entry(self, dn):
        """
        Gets an entry using its DN, or ``None`` if the DN doesn't exist.

        :param dn: The DN to find
        :returns: The dictionary of attributes for the DN, or ``None``
        """
        raise NotImplementedError

    def create_entry(self, dn, attributes):
        """
        Creates an entry at the given DN with the given attributes.

        :param dn: The DN to create
        :param attributes: The attributes to give the new entry
        :returns: ``True`` on success (should raise on failure)
        """
        try:
            self._conn.add(dn, attributes = attributes)
            return True
        except ldap3.LDAPEntryAlreadyExistsResult as e:
            raise ObjectAlreadyExistsError('Object already exists at {}'.format(dn)) from e
        except ldap3.LDAPStrongerAuthRequiredResult as e:
            raise PermissionDeniedError('Not authenticated to create entries') from e
        except ldap3.LDAPException as e:
            raise LDAPError('Error while creating entry') from e

    def update_entry(self, dn, attributes):
        """
        Updates the given DN with the given attributes. Note that this will **ONLY**
        affect attributes that explicitly given. Attributes that are not given
        will be left untouched.

        :param dn: The DN to update
        :param attributes: The attributes to update on the entry
        :returns: ``True`` on success (should raise on failure)
        """
        raise NotImplementedError

    def set_entry_password(self, dn, password):
        """
        Sets the password for the entry with the given DN.

        :param dn: The DN of the entry to set the password for
        :param password: The plaintext password
        :returns: ``True`` on success (should raise on failure)
        """
        try:
            self._conn.extend.standard.modify_password(dn, None, password)
            return True
        except ldap3.LDAPNoSuchObjectResult as e:
            # The DN doesn't exist
            raise NoSuchObjectError('DN does not exist: {}'.format(dn)) from e
        except ldap3.LDAPStrongerAuthRequiredResult as e:
            raise PermissionDeniedError('Not authenticated to set passwords') from e
        except ldap3.LDAPException as e:
            raise LDAPError('Error while setting entry password') from e

    def delete_entry(self, dn):
        """
        Deletes the entry with the given DN.

        :param dn: The DN to delete
        :returns: ``True`` on success (should raise on failure)
        """
        raise NotImplementedError

    def close(self):
        """
        Closes the connection.

        :returns: ``True`` on success (should raise on failure)
        """
        try:
            self._conn.unbind()
        except ldap3.LDAPException as e:
            raise LDAPError('Error while closing connection') from e
        return True
