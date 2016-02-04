"""
This module provides functions that return validators.

A validator is a callable that takes a value and either returns the validated
(possibly modified) value or raises a ``ValueError``.

The functions in this module take a set of arguments (at the very least, a
customisable failure message) and produce a validator.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

import os, tempfile, subprocess
from collections import Iterable


def required(msg = 'Field is required'):
    """
    Returns a validator that verifies that the given value exists, i.e. is not
    ``None``.
    """
    def f(value):
        if value is None:
            raise ValueError(msg)
        return value
    return f


def default(dflt):
    """
    Returns a validator that 'validates' the given value by returning a default
    if it is ``None``.
    
    If ``dflt`` is a callable, it is called with no arguments to produce a default
    value. Otherwise, ``dflt`` itself is used.
    """
    def f(value):
        if value is None:
            return dflt() if callable(dflt) else dflt
        return value
    return f


def not_empty(msg = 'Field must not be empty'):
    """
    Returns a validator that verifies that the given value is not empty. Only
    applicable for iterables, including strings, and ``None``, where ``None`` is
    considered empty. Other values pass through.
    """
    def f(value):
        if value is None or (isinstance(value, Iterable) and not value):
            raise ValueError(msg)
        return value
    return f


def each(validator, not_iterable_msg = 'Value must be iterable'):
    """
    Returns a validator that applies the given validator for each element of an
    iterable.
    """
    def f(values):
        if not isinstance(values, Iterable):
            raise TypeError(not_iterable_msg)
        return tuple(validator(v) for v in values)
    return f 


def is_ssh_key(msg = 'Not a valid SSH key'):
    """
    Returns a validator that verifies that the given value is a valid SSH key.
    """
    def f(value):
        # Strip whitespace and raise an error if that results in an empty value
        value = value.strip()
        if not value:
            raise ValueError(msg)
        # Check that the SSH key is valid using ssh-keygen
        fd, temp = tempfile.mkstemp()
        with os.fdopen(fd, mode = 'w') as f:
            f.write(value)
        try:
            # We don't really care about the content of stdout/err
            # We just care if the command succeeded or not...
            subprocess.check_call(
                'ssh-keygen -l -f {}'.format(temp), shell = True,
                stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            raise ValueError(msg)
        return value
    return f
