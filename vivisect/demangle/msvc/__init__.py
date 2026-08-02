"""
vivisect.demangle.msvc - Microsoft Visual C++ ABI demangling (? prefix).

Phase 0: Stub that returns the original name.  The pure-Python parser
will be implemented in Phase 3.

The MSVC C++ ABI is used by Microsoft Visual C++ and ICC on Windows.
Mangled symbols start with ``?`` and use ``@``-terminated scope chains.

Reference:
    - LLVM MicrosoftDemangle.cpp
    - Microsoft undname.c documentation
"""

import logging

from vivisect.demangle.common import DemangledSymbol, normalize_name

logger = logging.getLogger(__name__)

__all__ = ['demangle_msvc']


def demangle_msvc(mangled, structured=False):
    """
    Demangle an MSVC C++ ABI mangled symbol (? prefix).

    Phase 0: Returns the original name unchanged.  Phase 3 will implement
    the full MSVC demangler.

    Args:
        mangled (str): The mangled symbol string.
        structured (bool): If True, return a DemangledSymbol object.

    Returns:
        str or DemangledSymbol: The original mangled name (Phase 0 stub).
    """
    original = mangled
    mangled = normalize_name(mangled)

    if not structured:
        return original

    return DemangledSymbol(
        format='msvc',
        full_name=original,
        name=original,
        original_mangled=original,
        parse_warnings=['MSVC demangler not yet implemented (Phase 3)'],
    )