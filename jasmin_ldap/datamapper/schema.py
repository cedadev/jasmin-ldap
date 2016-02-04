"""
This module handles the creation of LDAP schemas for objects.

A schema handles the mapping of fields from LDAP onto the fields for an object.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

from collections import Iterable
from functools import reduce

from ..validators import required, not_empty

from .exceptions import SchemaValidationError


class Field:
    """
    Represents a field in a schema.

    Field values are either strings (scalar) or tuples of strings (multi-valued).

    :param attribute: The name of the LDAP attribute that the field maps to
    :param multivalued: Indicates if the field can have multiple values
                        (optional, defaults to ``False``)
    :param validators: An iterable of additional validators for the field
                       (optional, see :py:mod:`jasmin_ldap.validators`)
    """
    def __init__(self, attribute, multivalued = False, validators = []):
        self.attribute = attribute
        self.multivalued = multivalued
        self.validators = list(validators)

    def to_python(self, values):
        """
        Receives data from the associated LDAP attribute and returns a value
        derived from that data.

        The input data should always be a list/tuple of strings.

        For multi-valued fields, the returned value will always be a tuple of strings.

        For scalar fields, the returned value will be ``None`` (if ``values`` is
        empty) or a single string (the first element of ``values``).

        This method **does not** use the validators.
        """
        return tuple(values) if self.multivalued else next(iter(values), None)

    def to_ldap(self, value):
        """
        Receives a value and converts it into a set of LDAP values (i.e. a tuple
        of strings).

        The user-provided validators are first run on the raw Python object, and
        will raise ``ValueError`` if any of them fail.

        The value can be any Python object, and will be handled as follows:

           * ``None`` indicates the absence of a value
           * For non-string iterables, each element will be converted to a string
           * For all other objects, the object itself is converted to a string

        Once this conversion has taken place, the field will then decide if the
        value is suitable by running the validators (both built-in and
        user-provided). A ``ValueError`` will be raised if the value is not
        suitable.
        """
        # Run the validators on the raw value - let any ValueErrors bubble
        value = reduce(lambda a, v: v(a), self.validators, value)
        # Return a suitable representation of the value, if possible
        if value is None:
            return ()
        elif isinstance(value, Iterable) and not isinstance(value, str):
            if not self.multivalued:
                raise ValueError('Iterable value given for scalar field')
            return tuple(str(v) for v in value)
        else:
            if self.multivalued:
                raise ValueError('Non-iterable value given for multi-valued field')
            return (str(value), )


class CnField(Field):
    """
    Specialised field type for the ``cn`` attribute of LDAP records.

    The ``cn`` must be a scalar field with the required and non-empty validators.

    :param validators: An iterable of additional validators for the field
                       (optional, see :py:mod:`jasmin_ldap.validators`)
    """
    def __init__(self, validators = []):
        super().__init__('cn', False, [required(), not_empty()] + list(validators))


class Schema:
    """
    A schema applies semantic information to LDAP records to produce a
    well-structured dictionary of values (or a validation error).

    Currently, a schema can only represent a single level of an LDAP tree, and
    does not support mapping parts of the ``dn`` to fields (except for the ``cn``).

    To define a schema, create a subclass of this class and add
    :py:class:`Field`\ s as attributes of the class. These attributes define the
    mapping of field names to LDAP attributes, and the characteristics of those
    mappings.

    .. note::
        There **must** be :py:class:`CnField` defined.
    """
    #: The base ``dn`` at which the schema applies
    __base_dn__ = None

    #: The object classes used by entries in LDAP
    __object_classes__ = ()

    def __init__(self):
        # Make sure a base dn is specified
        if not self.__base_dn__:
            raise TypeError(
                "No base dn defined for '{}'".format(self.__class__.__qualname__)
            )
        # At least one object class is required
        if not self.__object_classes__:
            raise TypeError(
                "No object classes defined for '{}'".format(self.__class__.__qualname__)
            )
        # Work out the schema fields from the defined properties
        # Store the mapping for the cn while we are there
        self.fields = {}
        self._cn_field = None
        for name, value in type(self).__dict__.items():
            if isinstance(value, Field):
                self.fields[name] = value
                if isinstance(value, CnField):
                    if self._cn_field:
                        raise TypeError('Only one cn field is allowed')
                    self._cn_field = name
        if not self._cn_field:
            raise TypeError('A cn field is required')

    def _prop_or_key(self, obj, prop):
        """
        Attempts property access then key-based access for prop on obj, returning
        the first successful result. If prop is not available as a property or
        a key, None is returned.
        """
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
        # Retrieve the value corresponding to the cn from the object (or None)
        cn = self._prop_or_key(obj, self._cn_field)
        # Convert it to LDAP format and extract the first element
        # Let any ValueErrors bubble
        try:
            cn = next(iter(self.fields[self._cn_field].to_ldap(cn)))
        except StopIteration:
            # A CnField should NEVER let this happen
            raise ValueError('Could not discover cn')
        return 'cn={},{}'.format(cn, self.__base_dn__)

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
        for name, field in self.fields.items():
            try:
                values[name] = field.to_python(attrs[field.attribute])
            except KeyError:
                # If the field is not present in the attributes, use None
                values[name] = None
        return values

    def to_ldap(self, obj):
        """
        Converts the given object to a (``dn``, LDAP attribute dictionary) pair as
        defined by the schema.

        This method attempts to use property access and key-based access to get
        field values, so value can be either an object with suitable properties
        or a mapping with suitable keys. Property access is preferred if successful.

        Raises :py:class:`.exceptions.SchemaValidationError` on failure.

        :param obj: The object to convert
        :returns: A ``(dn, LDAP attrs)`` pair
        """
        attrs = {}
        errors = {}
        for name, field in self.fields.items():
            value = self._prop_or_key(obj, name)
            # Then try the field conversion
            try:
                attrs[field.attribute] = field.to_ldap(value)
            except ValueError as e:
                errors[name] = str(e)
        # Try to build the dn
        # We don't use build_dn since we don't want to extract the value and
        # run the validators again
        try:
            dn = 'cn={},{}'.format(next(iter(attrs['cn'])), self.__base_dn__)
        except (KeyError, StopIteration):
            errors.setdefault(self._cn_field, 'Field is required')
        # If we have errors, raise them
        if errors:
            raise SchemaValidationError(errors)
        # Inject the object classes before returning
        attrs['objectClass'] = self.__object_classes__
        return dn, attrs
