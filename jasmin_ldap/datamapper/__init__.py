"""
This is the main module for the LDAP data-mapper library.

See https://en.wikipedia.org/wiki/Data_mapper_pattern for more info on the
data-mapper pattern.
"""

__author__ = "Matt Pryor"
__copyright__ = "Copyright 2015 UK Science and Technology Facilities Council"

from .exceptions import *
from .manager import *
from .query import *
from .schema import *
