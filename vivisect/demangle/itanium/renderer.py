"""
vivisect.demangle.itanium.renderer - Render Itanium AST nodes to demangled strings.

Walks the AST produced by ``vivisect.demangle.itanium.parser`` and produces
the human-readable demangled name string, matching the output format of
``c++filt`` / ``__cxa_demangle``.
"""

import logging

from vivisect.demangle.itanium import ast_nodes as ast
from vivisect.demangle.itanium import grammar

logger = logging.getLogger(__name__)

__all__ = ['render', 'Renderer']


def render(node, subs=None, template_params=None):
    """Render an AST node to a demangled string.

    Args:
        node: The root AST node.
        subs: The substitution table from the parser (list of AST nodes).
            Required to resolve substitution references.
        template_params: Template parameter values (dict index -> AST node).
    """
    r = Renderer(subs=subs, template_params=template_params)
    return r.render(node)


class Renderer:
    """
    Render Itanium AST nodes to demangled strings.

    The renderer maintains a context for:
        - Substitution table (for S_, S0_, etc. references)
        - Template parameter substitution (T_ values)
    """

    def __init__(self, subs=None, template_params=None):
        self.subs = subs if subs is not None else []
        self.template_params = template_params if template_params is not None else {}
        self._in_template_args = False

    def render(self, node):
        """Dispatch to the appropriate render method based on node type."""
        if node is None:
            return ''
        method = getattr(self, '_render_%s' % type(node).__name__, None)
        if method is None:
            logger.debug('no renderer for %s', type(node).__name__)
            return repr(node)
        return method(node)

    def _render_Name(self, node):
        name_str = self.render(node.qualified_name)
        if node.is_function and node.bare_function:
            func_str = self._render_function_signature(node)
            return func_str
        return name_str

    def _render_function_signature(self, node):
        """Render a Name node that has a bare_function (i.e. a function)."""
        name_str = self.render(node.qualified_name)

        if node.bare_function is None or not node.bare_function.types:
            return name_str + '()'

        # The bare function type contains return type + params (for functions
        # that are not member functions) or just params (for member functions).
        # At the top level, the return type is NOT included in cxxfilt output
        # for regular functions.  It IS included for template specializations.
        types = node.bare_function.types

        # Check if the first type is a return type or a parameter.
        # In the Itanium ABI, for a top-level function encoding, the first
        # type is the return type ONLY if the function is a template
        # specialization.  Otherwise, the bare-function-type is just the
        # parameter list.
        #
        # Heuristic: if the name is a template, the first type is the return.
        # Otherwise, all types are parameters.
        is_template = self._is_template_name(node.qualified_name)

        if is_template and len(types) > 1:
            return_type = self.render(types[0])
            params = types[1:]  # skip return type
        else:
            return_type = None
            params = types  # all are parameters

        param_strs = [self.render(t) for t in params]
        # Per cxxfilt convention: a single 'void' param = empty param list
        if len(param_strs) == 1 and param_strs[0] == 'void':
            param_strs = []

        # For member functions, CV-qualifiers and ref-qualifiers go AFTER
        # the parameter list, not after the name.  But _render_NestedName
        # already appended them to name_str.  We need to strip them from
        # name_str and re-append after the params.
        cv_suffix = ''
        qn = node.qualified_name
        if isinstance(qn, ast.NestedName):
            if qn.cv_qualifiers:
                cv_suffix = ' ' + qn.cv_qualifiers
                # Strip the cv_qualifiers that _render_NestedName appended
                name_str = name_str[:-len(cv_suffix)]
            if qn.ref_qualifier:
                ref_suffix = ' ' + qn.ref_qualifier
                # ref_qualifier may have been appended after cv
                if name_str.endswith(ref_suffix):
                    name_str = name_str[:-len(ref_suffix)]
                    cv_suffix += ref_suffix
                elif name_str.endswith(qn.ref_qualifier):
                    name_str = name_str[:-len(qn.ref_qualifier)]
                    cv_suffix += ' ' + qn.ref_qualifier

        result = '%s(%s)' % (name_str, ', '.join(param_strs))
        if cv_suffix:
            result += cv_suffix
        # For template specializations, prepend the return type
        if return_type is not None:
            result = '%s %s' % (return_type, result)
        return result
    def _is_template_name(self, node):
        """Check if a name node is a template instantiation."""
        if isinstance(node, ast.NestedName):
            return self._is_template_unqualified(node.unqualified_name)
        if isinstance(node, ast.UnqualifiedName):
            return node.kind == 'template'
        return False

    def _is_template_unqualified(self, unq):
        if isinstance(unq, ast.UnqualifiedName):
            return unq.kind == 'template'
        return False

    def _render_SourceName(self, node):
        return node.name

    def _render_UnqualifiedName(self, node):
        if node.kind == 'source':
            result = self.render(node.value)
            # Append ABI tags
            if node.abi_tags:
                result += ''.join('[abi:%s]' % t for t in node.abi_tags)
            return result
        if node.kind == 'operator':
            sym = node.value.symbol
            # cxxfilt convention: alphabetic operator names get a space
            # (operator new, operator delete, operator cast), symbolic ones don't
            # (operator+, operator-, operator<<)
            if sym and sym[0].isalpha():
                return 'operator %s' % sym
            return 'operator%s' % sym
        if node.kind == 'ctor':
            return self._render_ctor_dtor(node.value, is_destructor=False)
        if node.kind == 'dtor':
            return self._render_ctor_dtor(node.value, is_destructor=True)
        if node.kind == 'template':
            # The value is a TemplateArgs node
            return self.render(node.value)
        return str(node.value)

    def _render_ctor_dtor(self, node, is_destructor=False):
        """Constructor/destructor uses the class name."""
        # The class name is the last source name seen (self.last_name)
        # For now, return a placeholder; the NestedName renderer handles this
        if is_destructor:
            return '~<dtor>'
        return '<ctor>'

    def _render_NestedName(self, node):
        parts = []
        i = 0
        prefix = node.prefix
        while i < len(prefix):
            p = prefix[i]
            if isinstance(p, ast.UnqualifiedName) and p.kind == 'template':
                # Template: append args to the previous component
                if parts:
                    parts[-1] += self.render(p)
                else:
                    parts.append(self.render(p))
            else:
                parts.append(self.render(p))
            i += 1

        # Handle the unqualified name
        unq = node.unqualified_name
        if isinstance(unq, ast.UnqualifiedName) and unq.kind == 'template':
            # The unqualified name is template args — append to last prefix
            if parts:
                parts[-1] += self.render(unq)
            else:
                parts.append(self.render(unq))
        else:
            unq_str = self.render(unq)
            parts.append(unq_str)

        # Handle constructor/destructor: replace the last component with
        # the class name (which is the last prefix component that's a source name)
        if isinstance(unq, ast.UnqualifiedName):
            if unq.kind in ('ctor', 'dtor') and len(node.prefix) > 0:
                class_name = self._get_class_name_from_prefix(prefix)
                if class_name:
                    if unq.kind == 'dtor':
                        parts[-1] = '~' + class_name
                    else:
                        parts[-1] = class_name

        result = '::'.join(parts)

        # Apply CV-qualifiers and ref-qualifiers for member functions
        suffix = ''
        if node.cv_qualifiers:
            suffix += ' ' + node.cv_qualifiers
        if node.ref_qualifier:
            suffix += node.ref_qualifier

        return result + suffix

    def _get_class_name_from_prefix(self, prefix):
        """Get the unqualified class name from the prefix chain."""
        if not prefix:
            return ''
        last = prefix[-1]
        if isinstance(last, ast.SourceName):
            return self._extract_class_name(last.name)
        if isinstance(last, ast.UnqualifiedName):
            if last.kind == 'source' and isinstance(last.value, ast.SourceName):
                return last.value.name
            # For template classes, the class name is the source name
            # in the prefix element BEFORE the template args.
            # e.g., prefix = [std, allocator, <template-args>] -> "allocator"
            if last.kind == 'template':
                if len(prefix) >= 2:
                    prev = prefix[-2]
                    if isinstance(prev, ast.SourceName):
                        return self._extract_class_name(prev.name)
                    if isinstance(prev, ast.UnqualifiedName):
                        if isinstance(prev.value, ast.SourceName):
                            return prev.value.name
                        # Could be a substitution like Ss/Si/So/Sd
                        if isinstance(prev.value, ast.Substitution) and prev.value.std_sub:
                            name = grammar.STD_SUBS.get(prev.value.std_sub, '')
                            return self._extract_class_name(name)
        return self.render(last)

    def _extract_class_name(self, full_name):
        """Extract the unqualified class name from a full name string."""
        # Strip template args (everything from first '<' onwards)
        if '<' in full_name:
            full_name = full_name[:full_name.index('<')]
        # Get last component after ::
        if '::' in full_name:
            full_name = full_name.split('::')[-1]
        return full_name

    def _render_OperatorName(self, node):
        return node.symbol

    def _render_CtorDtorName(self, node):
        # Placeholder — handled by NestedName renderer
        return ''

    def _render_TemplateArgs(self, node):
        args = [self.render(a) for a in node.args]
        # cxxfilt puts a space before > when the last arg ends with >
        # to avoid >> being confused with right-shift
        result = '<%s>' % ', '.join(args)
        if args and args[-1].rstrip().endswith('>'):
            result = '<%s >' % ', '.join(args)
        return result

    def _render_TemplateArg(self, node):
        if node.kind == 'type':
            return self.render(node.value)
        if node.kind == 'expression':
            return str(node.value)
        if node.kind == 'pack':
            if isinstance(node.value, list):
                return ', '.join(self.render(a) if isinstance(a, ast.Node) else str(a) for a in node.value)
            return str(node.value)
        if node.kind == 'primary':
            return str(node.value)
        return str(node.value)

    def _render_BuiltinType(self, node):
        return node.name

    def _render_PointerType(self, node):
        target = node.target
        # Pointer to function: special formatting (ret (*)(params))
        if isinstance(target, ast.FunctionType):
            bare = target.bare_function
            if bare is None or not bare.types:
                return 'void (*)()'
            ret = self.render(bare.types[0])
            params = [self.render(t) for t in bare.types[1:]]
            if len(params) == 1 and params[0] == 'void':
                params = []
            result = '%s (*)(%s)' % (ret, ', '.join(params))
            if target.cv:
                result += ' ' + target.cv
            if target.ref:
                result += ' ' + target.ref
            return result
        # Check for CV-qualified function type (e.g., const function pointer)
        if isinstance(target, ast.CVQualifiedType) and isinstance(target.base, ast.FunctionType):
            inner = target.base
            bare = inner.bare_function
            if bare is None or not bare.types:
                ret_str = 'void (*)()'
            else:
                ret = self.render(bare.types[0])
                params = [self.render(t) for t in bare.types[1:]]
                if len(params) == 1 and params[0] == 'void':
                    params = []
                ret_str = '%s (*)(%s)' % (ret, ', '.join(params))
            return ret_str
        return '%s*' % self.render(target)

    def _is_function_pointer(self, node):
        """Check if a node represents a function (for pointer formatting)."""
        return isinstance(node, (ast.FunctionType, ast.BareFunctionType))

    def _render_function_pointer_inner(self, node):
        """Render the inner part of a function pointer."""
        if isinstance(node, ast.FunctionType):
            return self._render_FunctionType(node)
        return self.render(node)

    def _render_ReferenceType(self, node):
        return '%s&' % self.render(node.target)

    def _render_RvalueReferenceType(self, node):
        return '%s&&' % self.render(node.target)

    def _render_CVQualifiedType(self, node):
        base = self.render(node.base)
        # cxxfilt puts CV-qualifiers after the base type: "char const*" not "const char*"
        return '%s %s' % (base, node.qualifiers)

    def _render_FunctionType(self, node):
        bare = node.bare_function
        if bare is None or not bare.types:
            return 'void ()'
        ret = self.render(bare.types[0])
        params = [self.render(t) for t in bare.types[1:]]
        if len(params) == 1 and params[0] == 'void':
            params = []
        result = '%s (%s)' % (ret, ', '.join(params))
        if node.cv:
            result += ' ' + node.cv
        if node.ref:
            result += ' ' + node.ref
        return result

    def _render_BareFunctionType(self, node):
        if not node.types:
            return ''
        return ', '.join(self.render(t) for t in node.types)

    def _render_Substitution(self, node):
        if node.std_sub:
            return grammar.STD_SUBS.get(node.std_sub, 'std')
        # Resolve indexed substitution from the table
        if node.index is not None and node.index < len(self.subs):
            target = self.subs[node.index]
            return self.render(target)
        return '/*sub%d*/' % node.index if node.index is not None else '/*sub*/'

    def _render_TemplateParam(self, node):
        return '/*T%d*/' % node.index

    def _render_SpecialName(self, node):
        kind = node.kind
        target_str = self.render(node.target) if node.target else ''
        if kind == 'vtable':
            return 'vtable for %s' % target_str
        if kind == 'VTT':
            return 'VTT for %s' % target_str
        if kind == 'typeinfo':
            return 'typeinfo for %s' % target_str
        if kind == 'typeinfo name':
            return 'typeinfo name for %s' % target_str
        if kind == 'guard variable':
            return 'guard variable for %s' % target_str
        if kind == 'reference temp':
            return 'reference temporary for %s' % target_str
        if kind == 'tls init':
            return 'TLS init function for %s' % target_str
        if kind == 'tls wrapper':
            return 'TLS wrapper function for %s' % target_str
        return '%s for %s' % (kind, target_str)

    def _render_Array(self, node):
        element = self.render(node.element_type)
        return '%s [%s]' % (element, node.dimension)

    def _render_PointerToMember(self, node):
        # M <class-type> <member-type>
        # If member-type is a function type (possibly CV-qualified),
        # render as: ret (Class::*)(params) cv-quals ref-qual
        class_str = self.render(node.class_type)
        member = node.member_type

        # Unwrap CV-qualifiers to find the underlying function type
        cv = ''
        ref = ''
        func_type = member
        if isinstance(func_type, ast.CVQualifiedType):
            cv = func_type.qualifiers
            func_type = func_type.base

        if isinstance(func_type, ast.FunctionType):
            bare = func_type.bare_function
            if bare and bare.types:
                ret = self.render(bare.types[0])
                params = [self.render(t) for t in bare.types[1:]]
                if len(params) == 1 and params[0] == 'void':
                    params = []
                # Merge cv/ref from outer CVQualified with any on FunctionType itself
                cv = cv or func_type.cv
                ref = ref or func_type.ref
                result = '%s (%s::*)(%s)' % (ret, class_str, ', '.join(params))
                if cv:
                    result += ' ' + cv
                if ref:
                    result += ' ' + ref
                return result
            return 'void (%s::*)()' % class_str
        # Non-function member
        member_str = self.render(member)
        return '%s %s::*' % (member_str, class_str)

    def _render_VendorExtendedType(self, node):
        return node.name

    def _render_Decltype(self, node):
        return 'decltype(%s)' % str(node.expression)

    def _render_ModuleName(self, node):
        return node.name

    def _render_AbiTag(self, node):
        return '[abi:%s]' % node.tag