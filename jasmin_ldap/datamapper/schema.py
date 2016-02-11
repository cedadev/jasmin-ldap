"""
This module handles the creation of LDAP schemas for objects.

A schema handles the mapping of fields from LDAP onto the fields for an object.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

from collections import namedtuple, Iterable
from functools import reduce

from .exceptions import SchemaValidationError


class Field:
    """
    Represents a field in a schema, i.e. a mapping of a property name to an LDAP
    attribute.

    :param name: The name of the field in the schema
    :param attribute: The name of the LDAP attribute that the field maps to
                      (optional, defaults to the field name)
    :param multivalued: Indicates if the field can have multiple values
                        (optional, defaults to ``False``)
    :param from_str: Used to convert a value from LDAP to a Python object
                     (optional, defaults to ``str``)
    :param to_str: Used to convert a Python object to a string for LDAP
                   (optional, defaults to ``str``)
    """
    def __init__(self, name, attribute = None,
                       multivalued = False, from_str = str, to_str = str):
        self.name = name
        self.attribute = attribute or name
        # Always store the attribute as lower-case
        self.attribute = self.attribute.lower()
        self.multivalued = multivalued
        self.from_str = from_str
        self.to_str = to_str

    def to_python(self, values):
        """
        Receives data from the associated LDAP attribute and returns a value
        derived from that data.

        The input data will always be a list/tuple of strings.

        :param values: An iterable of values from LDAP
        :returns: The derived value
        """
        converted = (self.from_str(v) for v in values)
        return tuple(converted) if self.multivalued else next(iter(converted), None)

    def to_ldap(self, value):
        """
        Receives a value and converts it into a set of LDAP values (i.e. a tuple
        of strings).

        :param value: The Python object to convert to LDAP attributes
        :returns: An iterable of string values suitable for LDAP
        """
        if value is None:
            return ()
        if self.multivalued:
            return tuple(self.to_str(v) for v in value)
        else:
            return (self.to_str(value), )


class CNField(Field):
    """
    Specialised field that represents the CN in an LDAP schema.

    :param name: The name of the field in the schema (optional, defaults to ``cn``)
    """
    def __init__(self, name = 'cn'):
        super().__init__(name, 'cn')


class Schema:
    """
    A schema applies semantic information to LDAP records to produce a
    well-structured dictionary of values (or a validation error).

    Currently, a schema can only represent a single level of an LDAP tree, and
    does not support mapping parts of the ``dn`` to fields, other than the ``cn``.

    :param base_dn: The base ``dn`` at which the schema applies
    :param object_classes: An iterable of object classes for the schema
    :param cn_field: The field mapping to the CN (an instance of :py:class:`CNField`)
    :param \*fields: The fields for the schema (instances of :py:class:`Field`)
    """
    def __init__(self, base_dn, object_classes, cn_field, *fields):
        self.base_dn = base_dn
        self.object_classes = tuple(object_classes)
        self.cn_field = cn_field
        self.fields = (cn_field, ) + tuple(fields)

    def field_for_name(self, name):
        for f in self.fields:
            if f.name == name:
                return f
        raise KeyError("No field for name '{}'".format(name))

    def field_for_attribute(self, attribute):
        for f in self.fields:
            if f.attribute == attribute.lower():
                return f
        raise KeyError("No field for attribute '{}'".format(attribute))

    def _prop_or_key(self, obj, prop):
        # Attempts property access then key-based access for prop on obj, returning
        # the first successful result or None
        try:
            return getattr(obj, prop)
        except AttributeError:
            pass
        # If that fails, try key-based access
        try:
            return obj[prop]
        except (TypeError, KeyError, IndexError):
            return None

    def build_dn(self, obj):
        """
        Builds the ``dn`` for the given object.

        This method attempts to use property access and key-based access to get
        field values, so value can be either an object with suitable properties
        or a mapping with suitable keys. Property access is preferred if successful.

        Raises ``ValueError`` if the ``cn`` field fails validation.
        """
        try:
            value = self._prop_or_key(obj, self.cn_field.name)
            cn = next(iter(self.cn_field.to_ldap(value)))
            return 'cn={},{}'.format(cn, self.base_dn)
        except (KeyError, StopIteration):
            raise ValueError('Could not discover cn')

    def to_python(self, dn, attrs):
        """
        Converts the given ``dn`` and LDAP attribute dictionary to a dictionary of
        field values as defined by the schema.

        This method will always return a dictionary, even if some of the entries
        in the dictionary are ``None``.

        :param dn: The ``dn`` of the object
        :param attrs: The LDAP attribute dictionary
        :returns: The property values
        """
        values = {}
        for field in self.fields:
            try:
                values[field.name] = field.to_python(attrs[field.attribute])
            except KeyError:
                # If the field is not present in the attributes, use None
                values[field.name] = None
        return values

    def to_ldap(self, obj):
        """
        Converts the given object to a (``dn``, LDAP attribute dictionary) pair as
        defined by the schema.

        This method attempts to use property access and key-based access to get
        field values, so value can be either an object with suitable properties
        or a mapping with suitable keys. Property access is preferred if successful.

        :param obj: The object to convert
        :returns: A ``(dn, LDAP attrs)`` pair
        """
        attrs = {}
        for field in self.fields:
            value = self._prop_or_key(obj, field.name)
            attrs[field.attribute] = field.to_ldap(value)
        dn = 'cn={},{}'.format(next(iter(attrs['cn'])), self.base_dn)
        # Inject the object classes before returning
        attrs['objectClass'] = self.object_classes
        return dn, attrs
