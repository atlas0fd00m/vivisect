"""
vivisect.demangle.itanium - Itanium C++ ABI demangling (_Z prefix).

Phase 0: Uses ``cxxfilt`` as a fallback if available.  The pure-Python
parser will be implemented in Phase 1.

The Itanium C++ ABI is used by GCC, Clang, and ICC on Linux/macOS.
Mangled symbols start with ``_Z`` (or ``__Z`` for old GCC).

Reference:
    - Itanium C++ ABI section 5.1 (External Names)
    - GNU libiberty cp-demangle.c (the gold standard)
    - LLVM ItaniumDemangle.cpp
"""

import logging

from vivisect.demangle.common import DemangledSymbol, normalize_name

logger = logging.getLogger(__name__)

__all__ = ['demangle_itanium']


def demangle_itanium(mangled, structured=False):
    """
    Demangle an Itanium C++ ABI mangled symbol (_Z prefix).

    Phase 0: Falls back to ``cxxfilt`` if available.  If ``cxxfilt`` is
    not installed or fails, returns the original name (graceful
    degradation).

    Args:
        mangled (str): The mangled symbol string.
        structured (bool): If True, return a DemangledSymbol object.

    Returns:
        str or DemangledSymbol: The demangled name, or the original if
        demangling fails.
    """
    original = mangled
    mangled = normalize_name(mangled)

    demangled = None
    try:
        import cxxfilt
        demangled = cxxfilt.demangle(mangled)
    except Exception as e:
        logger.debug('cxxfilt demangle failed for %r: %r', mangled, e)
        demangled = None

    # cxxfilt returns the original if it can't demangle
    if demangled is None or demangled == mangled:
        if structured:
            return DemangledSymbol(
                format='itanium',
                full_name=original,
                name=original,
                original_mangled=original,
                parse_warnings=['cxxfilt unavailable or unable to demangle'],
            )
        return original

    if not structured:
        return demangled

    # Build a minimal structured result from the cxxfilt string.
    # Phase 1 will replace this with a full AST.
    sym = DemangledSymbol(
        format='itanium',
        full_name=demangled,
        original_mangled=original,
    )
    _parse_basic_structure(sym, demangled)
    return sym


def _parse_basic_structure(sym, demangled):
    """
    Best-effort extraction of basic structure from a demangled string.

    This is a placeholder for Phase 1's real AST.  It extracts scope/name
    split and detects vtables/typeinfo/guard variables.
    """
    # Special names
    if demangled.startswith('vtable for '):
        sym.kind = 'vtable'
        sym.name = demangled[len('vtable for '):]
        sym.scope = sym.name.split('::')
        return
    if demangled.startswith('typeinfo for '):
        sym.kind = 'typeinfo'
        sym.name = demangled[len('typeinfo for '):]
        sym.scope = sym.name.split('::')
        return
    if demangled.startswith('typeinfo name for '):
        sym.kind = 'typeinfo_name'
        sym.name = demangled[len('typeinfo name for '):]
        sym.scope = sym.name.split('::')
        return
    if demangled.startswith('VTT for '):
        sym.kind = 'vtt'
        sym.name = demangled[len('VTT for '):]
        sym.scope = sym.name.split('::')
        return
    if demangled.startswith('guard variable for '):
        sym.kind = 'guard'
        sym.name = demangled[len('guard variable for '):]
        sym.scope = sym.name.split('::')
        return

    # Function or variable: split scope from the last ::
    if '::' in demangled:
        # Find the last :: that's not inside template args (<>)
        depth = 0
        split_pos = -1
        for i in range(len(demangled) - 1):
            c = demangled[i]
            if c == '<':
                depth += 1
            elif c == '>':
                depth -= 1
            elif depth == 0 and c == ':' and demangled[i + 1] == ':':
                split_pos = i

        if split_pos > -1:
            sym.scope = demangled[:split_pos].split('::')
            sym.name = demangled[split_pos + 2:]
        else:
            sym.name = demangled
    else:
        sym.name = demangled

    # Detect template
    if '<' in sym.name:
        sym.is_template = True

    # Detect constructor/destructor (common naming patterns)
    # e.g. foo::bar::ClassName::ClassName() is a constructor
    if sym.scope and sym.name:
        last_scope = sym.scope[-1] if sym.scope else ''
        if sym.name == last_scope + '(' or sym.name.startswith(last_scope + '('):
            sym.kind = 'ctor'
        elif sym.name.startswith('~'):
            sym.kind = 'dtor'

    if sym.kind == 'unknown':
        if '(' in sym.name:
            sym.kind = 'function'
        else:
            sym.kind = 'variable'