"""
vivisect.demangle.swift - Swift symbol demangling ($s / _T0 / $S prefix).

Phase 0: Stub.  Phase 5 will implement the Swift demangler.

Reference:
    - Swift mangling specification (swift-mangling.rst)
"""

import logging

from vivisect.demangle.common import DemangledSymbol, normalize_name

logger = logging.getLogger(__name__)

__all__ = ['demangle_swift']


def demangle_swift(mangled, structured=False):
    """
    Demangle a Swift mangled symbol ($s / _T0 / $S prefix).

    Phase 0: Returns the original name.
    """
    original = mangled
    mangled = normalize_name(mangled)

    if not structured:
        return original

    return DemangledSymbol(
        format='swift',
        full_name=original,
        name=original,
        original_mangled=original,
        parse_warnings=['Swift demangler not yet implemented (Phase 5)'],
    )