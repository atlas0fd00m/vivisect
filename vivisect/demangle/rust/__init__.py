"""
vivisect.demangle.rust - Rust symbol demangling.

Phase 0: Stub.  Phase 4 will implement both legacy (_Z) and v0 (_R) Rust
mangling.

Reference:
    - RFC 2603 (Rust v0 mangling)
    - rustc-demangle crate
"""

import logging

from vivisect.demangle.common import DemangledSymbol, normalize_name

logger = logging.getLogger(__name__)

__all__ = ['demangle_rust']


def demangle_rust(mangled, structured=False):
    """
    Demangle a Rust mangled symbol.

    Phase 0: Returns the original name.  Phase 4 will implement legacy
    (_Z prefix, with $ escape decoding) and v0 (_R prefix, RFC 2603).
    """
    original = mangled
    mangled = normalize_name(mangled)

    if not structured:
        return original

    return DemangledSymbol(
        format='rust',
        full_name=original,
        name=original,
        original_mangled=original,
        parse_warnings=['Rust demangler not yet implemented (Phase 4)'],
    )