"""
vivisect.demangle.dlang - D language symbol demangling (_D prefix).

Phase 0: Stub.  Phase 5 will implement the full D demangler.

Reference:
    - LLVM DLangDemangle.cpp
    - D ABI documentation
"""

import logging

from vivisect.demangle.common import DemangledSymbol, normalize_name

logger = logging.getLogger(__name__)

__all__ = ['demangle_d']


def demangle_d(mangled, structured=False):
    """
    Demangle a D language mangled symbol (_D prefix).

    Phase 0: Returns the original name.
    """
    original = mangled
    mangled = normalize_name(mangled)

    if not structured:
        return original

    return DemangledSymbol(
        format='d',
        full_name=original,
        name=original,
        original_mangled=original,
        parse_warnings=['D demangler not yet implemented (Phase 5)'],
    )