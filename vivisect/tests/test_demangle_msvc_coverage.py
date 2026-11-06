"""
Comprehensive coverage tests for the MSVC C++ demangling module.

These tests target code paths not covered by the existing test suite,
focusing on: all operator codes, RTTI, templates, calling conventions,
CV modifiers, access codes, special handling functions, variable codes,
extended types, UDT names, function indirect types, embedded names,
MDString, encoded numbers, scope fragments, error handling, AST node
__repr__ methods, renderer paths, and __init__.py paths.
"""

import unittest

from vivisect.demangle.msvc import ast_nodes as ast
from vivisect.demangle.msvc import demangle_msvc
from vivisect.demangle.msvc.parser import MSVCParser, ParseError
from vivisect.demangle.msvc.renderer import (
    render,
    _build_prefix,
    _render_vftable,
    _render_variable,
    _render_name_component,
    _render_qualified_name,
    _render_function_signature,
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _parse(mangled):
    """Parse a mangled symbol and return the AST."""
    parser = MSVCParser(mangled)
    return parser.parse()


# ---------------------------------------------------------------------------
# All operator codes (OPERATORS dict, codes 0-Z except B)
# ---------------------------------------------------------------------------


class TestMSVCAllOperatorCodes(unittest.TestCase):
    """Test every single-char operator code in OPERATORS."""

    OPERATOR_NAMES = {
        "2": "operator new",
        "3": "operator delete",
        "4": "operator=",
        "5": "operator>>",
        "6": "operator<<",
        "7": "operator!",
        "8": "operator==",
        "9": "operator!=",
        "A": "operator[]",
        "C": "operator->",
        "D": "operator*",
        "E": "operator++",
        "F": "operator--",
        "G": "operator-",
        "H": "operator+",
        "I": "operator&",
        "J": "operator->*",
        "K": "operator/",
        "L": "operator%",
        "M": "operator<",
        "N": "operator<=",
        "O": "operator>",
        "P": "operator>=",
        "Q": "operator,",
        "R": "operator()",
        "S": "operator~",
        "T": "operator^",
        "U": "operator|",
        "V": "operator&&",
        "W": "operator||",
        "X": "operator*=",
        "Y": "operator+=",
        "Z": "operator-=",
    }

    def test_all_operator_codes(self):
        for code, expected_name in self.OPERATOR_NAMES.items():
            with self.subTest(code=code, name=expected_name):
                mangled = "??%s@YAXH@Z" % code
                result = demangle_msvc(mangled)
                self.assertIsInstance(result, str)
                self.assertIn(expected_name, result)

    def test_operator_codes_via_parser(self):
        for code, expected_name in self.OPERATOR_NAMES.items():
            with self.subTest(code=code):
                mangled = "??%s@YAXH@Z" % code
                sym = _parse(mangled)
                self.assertIsInstance(sym.qualified_name.basic_name, ast.SpecialName)
                self.assertEqual(sym.qualified_name.basic_name.name, expected_name)
                self.assertTrue(sym.qualified_name.basic_name.is_operator)


# ---------------------------------------------------------------------------
# Type cast operator (code B)
# ---------------------------------------------------------------------------


class TestMSVCTypeCastOperator(unittest.TestCase):
    """Test the type cast operator (code B)."""

    def test_type_cast_operator(self):
        mangled = "??BMyClass@@QAEXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.qualified_name.basic_name, ast.SpecialName)
        self.assertTrue(sym.qualified_name.basic_name.is_type_cast)

    def test_type_cast_operator_demangle(self):
        result = demangle_msvc("??BMyClass@@QAEXH@Z")
        self.assertIsInstance(result, str)
        self.assertIn("operator", result)


# ---------------------------------------------------------------------------
# Extended operators (OPERATORS_EXT, via ???_ prefix)
# ---------------------------------------------------------------------------


class TestMSVCExtendedOperators(unittest.TestCase):
    """Test two-char operator codes (OPERATORS_EXT) via ???_ prefix."""

    EXT_NAMES = {
        "0": "operator/=",
        "1": "operator%=",
        "2": "operator>>=",
        "3": "operator<<=",
        "4": "operator&=",
        "5": "operator|=",
        "6": "operator^=",
        "7": "`vftable'",
        "8": "`vbtable'",
        "9": "`vcall'",
        "A": "`typeof'",
        "B": "`local static guard'",
        "D": "`vbase destructor'",
        "E": "`vector deleting destructor'",
        "F": "`default constructor closure'",
        "G": "`scalar deleting destructor'",
        "H": "`vector constructor iterator'",
        "I": "`vector destructor iterator'",
        "J": "`vector vbase constructor iterator'",
        "K": "`virtual displacement map'",
        "L": "`eh vector constructor iterator'",
        "M": "`eh vector destructor iterator'",
        "N": "`eh vector vbase constructor iterator'",
        "O": "`copy constructor closure'",
        "S": "`local vftable'",
        "T": "`local vftable constructor closure'",
        "U": "operator new[]",
        "V": "operator delete[]",
        "W": "`omni callsig'",
        "X": "`placement delete closure'",
        "Y": "`placement delete[] closure'",
    }

    def test_ext_operator_codes(self):
        for code, expected_name in self.EXT_NAMES.items():
            with self.subTest(code=code, name=expected_name):
                mangled = "???_%s@@" % code
                result = demangle_msvc(mangled)
                self.assertIsInstance(result, str)
                self.assertIn(expected_name, result)

    def test_ext_operator_via_parser(self):
        for code, expected_name in self.EXT_NAMES.items():
            with self.subTest(code=code):
                mangled = "???_%s@@" % code
                sym = _parse(mangled)
                self.assertEqual(sym.kind, "embedded")
                bn = sym.qualified_name.basic_name
                self.assertIsInstance(bn, ast.SpecialName)
                self.assertEqual(bn.name, expected_name)


# ---------------------------------------------------------------------------
# MDString (OPERATORS_EXT code C)
# ---------------------------------------------------------------------------


class TestMSVCMdString(unittest.TestCase):
    """Test MDString parsing (???_C prefix).

    Note: 'C' is deliberately excluded from OPERATORS_EXT in the parser
    (comment says "handled specially"), but the special handling code at
    line 567-569 is inside the `if code2 in OPERATORS_EXT` block, making
    it unreachable. So ???_C raises ParseError. We test that behavior.
    """

    def test_md_string_raises_parse_error(self):
        with self.assertRaises(ParseError):
            _parse("???_Chello@@")

    def test_md_string_demangle_graceful(self):
        result = demangle_msvc("???_Chelloworld@@")
        self.assertIsInstance(result, str)

    def test_md_string_empty_raises(self):
        with self.assertRaises(ParseError):
            _parse("???_C@@")


# ---------------------------------------------------------------------------
# Extended3 operators (OPERATORS_EXT3, via ???__ prefix)
# ---------------------------------------------------------------------------


class TestMSVCExtended3Operators(unittest.TestCase):
    """Test three-char operator codes (OPERATORS_EXT3) via ???__ prefix."""

    EXT3_NAMES = {
        "A": "`managed vector constructor iterator'",
        "B": "`managed vector destructor iterator'",
        "C": "`eh vector copy constructor iterator'",
        "D": "`eh vector vbase copy constructor iterator'",
        "G": "`vector copy constructor iterator'",
        "H": "`vector vbase copy constructor iterator'",
        "I": "`managed vector copy constructor iterator'",
        "J": "`local static thread guard'",
    }

    def test_ext3_operator_codes(self):
        for code, expected_name in self.EXT3_NAMES.items():
            with self.subTest(code=code, name=expected_name):
                mangled = "???__%s@@" % code
                result = demangle_msvc(mangled)
                self.assertIsInstance(result, str)
                self.assertIn(expected_name, result)

    def test_ext3_dynamic_initializer(self):
        mangled = "???__Efoo@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("dynamic initializer for", bn.name)
        self.assertIn("foo", bn.name)

    def test_ext3_dynamic_atexit_destructor(self):
        mangled = "???__Fbar@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("dynamic atexit destructor for", bn.name)
        self.assertIn("bar", bn.name)

    def test_ext3_udl_operator(self):
        mangled = "???__Klit@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn('operator "" ', bn.name)
        self.assertIn("lit", bn.name)


# ---------------------------------------------------------------------------
# RTTI names
# ---------------------------------------------------------------------------


class TestMSVCRTTI(unittest.TestCase):
    """Test RTTI type descriptors and names."""

    def test_rtti_type_descriptor_with_type(self):
        # ??_0H → "int `RTTI Type Descriptor'"
        mangled = "??_0H"
        sym = _parse(mangled)
        self.assertEqual(sym.kind, "rtti")
        bn = sym.qualified_name.basic_name
        self.assertIn("RTTI Type Descriptor", bn.name)
        self.assertIn("int", bn.name)

    def test_rtti_base_class_array(self):
        mangled = "??_2"
        sym = _parse(mangled)
        self.assertEqual(sym.kind, "rtti")
        self.assertIn("RTTI Base Class Array", sym.qualified_name.basic_name.name)

    def test_rtti_class_hierarchy_descriptor(self):
        mangled = "??_3"
        sym = _parse(mangled)
        self.assertEqual(sym.kind, "rtti")
        self.assertIn("RTTI Class Hierarchy Descriptor", sym.qualified_name.basic_name.name)

    def test_rtti_complete_object_locator(self):
        mangled = "??_4"
        sym = _parse(mangled)
        self.assertEqual(sym.kind, "rtti")
        self.assertIn("RTTI Complete Object Locator", sym.qualified_name.basic_name.name)

    def test_rtti_unknown_code_raises(self):
        with self.assertRaises(ParseError):
            _parse("??_5")

    def test_rtti_via_special_name_r0(self):
        # ???_R0 → RTTI Type Descriptor (via _parse_special_name)
        mangled = "???_R0@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("RTTI Type Descriptor", bn.name)

    def test_rtti_via_special_name_r2(self):
        mangled = "???_R2@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("RTTI Base Class Array", bn.name)

    def test_rtti_via_special_name_r3(self):
        mangled = "???_R3@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("RTTI Class Hierarchy Descriptor", bn.name)

    def test_rtti_via_special_name_r4(self):
        mangled = "???_R4@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("RTTI Complete Object Locator", bn.name)

    def test_rtti_via_special_name_unknown_raises(self):
        with self.assertRaises(ParseError):
            _parse("???_R5@@")

    def test_rtti_structured(self):
        sym = demangle_msvc("??_0H", structured=True)
        self.assertEqual(sym.kind, "rtti")


# ---------------------------------------------------------------------------
# RTTI Base Class Descriptor (encoded numbers)
# ---------------------------------------------------------------------------


class TestMSVCRTTIBaseClassDescriptor(unittest.TestCase):
    """Test RTTI Base Class Descriptor with encoded numbers."""

    def test_zero_numbers(self):
        mangled = "???_R1@@@@@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("(0,0,0,0)", bn.name)

    def test_negative_numbers(self):
        mangled = "???_R1?A?B?C@@@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("(-1,-2,-3,0)", bn.name)

    def test_hex_numbers(self):
        mangled = "???_R1$AB@@@@@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        # $AB = int("AB", 16) = 171
        self.assertIn("171", bn.name)

    def test_digit_numbers(self):
        mangled = "???_R1523@@@@@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("523", bn.name)


# ---------------------------------------------------------------------------
# Template parsing
# ---------------------------------------------------------------------------


class TestMSVCTemplateParsing(unittest.TestCase):
    """Test template name and argument parsing."""

    def test_template_with_type_arg(self):
        mangled = "?$Foo@@H@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("Foo", result)

    def test_template_with_int_arg(self):
        mangled = "?$Foo@@5@YAXH@Z"
        sym = _parse(mangled)
        qn = sym.qualified_name
        self.assertEqual(qn.base_name.name, "Foo")
        self.assertIn("5", qn.args)

    def test_template_with_multi_digit_arg(self):
        mangled = "?$Foo@@52@YAXH@Z"
        sym = _parse(mangled)
        self.assertIn("52", sym.qualified_name.args)

    def test_template_with_question_type_arg(self):
        mangled = "?$Foo@@?H@YAXH@Z"
        sym = _parse(mangled)
        self.assertIn("?int", sym.qualified_name.args)

    def test_nested_template(self):
        mangled = "?$Foo@@?$Bar@H@@YAXH@Z"
        sym = _parse(mangled)
        qn = sym.qualified_name
        self.assertEqual(qn.base_name.name, "Foo")
        self.assertEqual(len(qn.args), 1)
        inner = qn.args[0]
        self.assertIsInstance(inner, ast.TemplateName)
        self.assertEqual(inner.base_name.name, "Bar")
        self.assertIn("int", inner.args)

    def test_template_no_type_info(self):
        mangled = "?$Foo@@H@"
        sym = _parse(mangled)
        self.assertEqual(sym.kind, "template")

    def test_template_empty_args(self):
        mangled = "?$Foo@@YAXH@Z"
        sym = _parse(mangled)
        self.assertEqual(sym.qualified_name.base_name.name, "Foo")

    def test_template_in_qualified_name_raises(self):
        # ???$Foo@@ — '$' is not a valid special name code, raises ParseError
        with self.assertRaises(ParseError):
            _parse("???$Foo@@")

    def test_template_demangle_returns_string(self):
        # Top-level ?$ templates produce TemplateName as qualified_name,
        # which render() can't handle (expects QualifiedName). demangle_msvc
        # catches the exception and returns the original mangled string.
        result = demangle_msvc("?$Foo@@H@YAXH@Z")
        self.assertIsInstance(result, str)

    def test_template_with_ellipsis_arg(self):
        # Z as ... in template arg context (not intercepted by arg parser)
        mangled = "?$Foo@@Z@YAXH@Z"
        sym = _parse(mangled)
        self.assertIn("...", sym.qualified_name.args)


# ---------------------------------------------------------------------------
# Calling conventions
# ---------------------------------------------------------------------------


class TestMSVCCallingConventions(unittest.TestCase):
    """Test all calling convention codes not already covered."""

    def test_pascal(self):
        result = demangle_msvc("?foo@@YCH@Z")
        self.assertIn("__pascal", result)

    def test_fastcall(self):
        result = demangle_msvc("?foo@@YIH@Z")
        self.assertIn("__fastcall", result)

    def test_empty_cc_k(self):
        result = demangle_msvc("?foo@@YKH@Z")
        self.assertIsInstance(result, str)

    def test_clrcall(self):
        result = demangle_msvc("?foo@@YMH@Z")
        self.assertIn("__clrcall", result)

    def test_cdecl_b(self):
        result = demangle_msvc("?foo@@YBHH@Z")
        self.assertIn("__cdecl", result)

    def test_pascal_d(self):
        result = demangle_msvc("?foo@@YDHH@Z")
        self.assertIn("__pascal", result)

    def test_thiscall_f(self):
        result = demangle_msvc("?bar@MyClass@@FAEXH@Z")
        self.assertIn("__thiscall", result)

    def test_stdcall_h(self):
        result = demangle_msvc("?foo@@YHHH@Z")
        self.assertIn("__stdcall", result)

    def test_fastcall_j(self):
        result = demangle_msvc("?foo@@YJHH@Z")
        self.assertIn("__fastcall", result)

    def test_empty_cc_l(self):
        result = demangle_msvc("?foo@@YLHH@Z")
        self.assertIsInstance(result, str)

    def test_clrcall_n(self):
        result = demangle_msvc("?foo@@YNHH@Z")
        self.assertIn("__clrcall", result)


# ---------------------------------------------------------------------------
# CV modifiers
# ---------------------------------------------------------------------------


class TestMSVCCVModifiers(unittest.TestCase):
    """Test CV modifier codes for member functions."""

    CV_CODES = {
        "A": "",
        "B": "const",
        "C": "volatile",
        "D": "const volatile",
        "E": "",
        "F": "const",
        "G": "volatile",
        "H": "const volatile",
        "I": "",
        "J": "const",
        "K": "volatile",
        "L": "const volatile",
        "M": "",
        "N": "",
        "O": "const",
        "P": "volatile",
        "Q": "const volatile",
    }

    def test_all_cv_modifiers(self):
        for code, expected in self.CV_CODES.items():
            with self.subTest(code=code):
                mangled = "?bar@MyClass@@Q%sEXH@Z" % code
                result = demangle_msvc(mangled)
                self.assertIsInstance(result, str)
                if expected:
                    self.assertIn(expected, result)

    def test_unknown_cv_modifier_warning(self):
        mangled = "?bar@MyClass@@UREXH@Z"
        parser = MSVCParser(mangled)
        sym = parser.parse()
        # R is not in cv_map → warning
        self.assertTrue(any("unknown CV modifier" in w for w in parser.warnings))


# ---------------------------------------------------------------------------
# Access codes (member function access levels)
# ---------------------------------------------------------------------------


class TestMSVCAccessCodes(unittest.TestCase):
    """Test member function access codes covering static/virtual/thunk variants."""

    def test_private_static_c(self):
        result = demangle_msvc("?m@MyClass@@CGHH@Z")
        self.assertIn("private:", result)
        self.assertIn("static", result)

    def test_private_static_d(self):
        result = demangle_msvc("?m@MyClass@@DGHH@Z")
        self.assertIn("private:", result)
        self.assertIn("static", result)

    def test_private_virtual_e(self):
        result = demangle_msvc("?m@MyClass@@EAEXH@Z")
        self.assertIn("private:", result)
        self.assertIn("virtual", result)

    def test_private_virtual_f(self):
        result = demangle_msvc("?m@MyClass@@FAEXH@Z")
        self.assertIn("private:", result)
        self.assertIn("virtual", result)

    def test_private_thunk_g(self):
        result = demangle_msvc("?m@MyClass@@GAEXH@Z")
        self.assertIn("[thunk]:", result)
        self.assertIn("private:", result)

    def test_private_thunk_h(self):
        result = demangle_msvc("?m@MyClass@@HAEXH@Z")
        self.assertIn("[thunk]:", result)

    def test_protected_static_k(self):
        result = demangle_msvc("?m@MyClass@@KGHH@Z")
        self.assertIn("protected:", result)
        self.assertIn("static", result)

    def test_protected_static_l(self):
        result = demangle_msvc("?m@MyClass@@LGHH@Z")
        self.assertIn("protected:", result)
        self.assertIn("static", result)

    def test_protected_virtual_m(self):
        result = demangle_msvc("?m@MyClass@@MAEXH@Z")
        self.assertIn("protected:", result)
        self.assertIn("virtual", result)

    def test_protected_virtual_n(self):
        result = demangle_msvc("?m@MyClass@@NAEXH@Z")
        self.assertIn("protected:", result)
        self.assertIn("virtual", result)

    def test_protected_thunk_o(self):
        result = demangle_msvc("?m@MyClass@@OAEXH@Z")
        self.assertIn("[thunk]:", result)
        self.assertIn("protected:", result)

    def test_protected_thunk_p(self):
        result = demangle_msvc("?m@MyClass@@PAEXH@Z")
        self.assertIn("[thunk]:", result)

    def test_public_static_t(self):
        result = demangle_msvc("?m@MyClass@@TGHH@Z")
        self.assertIn("public:", result)
        self.assertIn("static", result)

    def test_public_virtual_v(self):
        result = demangle_msvc("?m@MyClass@@VAEXH@Z")
        self.assertIn("public:", result)
        self.assertIn("virtual", result)

    def test_public_thunk_w(self):
        result = demangle_msvc("?m@MyClass@@WAEXH@Z")
        self.assertIn("[thunk]:", result)
        self.assertIn("public:", result)

    def test_public_thunk_x(self):
        result = demangle_msvc("?m@MyClass@@XAEXH@Z")
        self.assertIn("[thunk]:", result)

    def test_public_nonstatic_r(self):
        result = demangle_msvc("?m@MyClass@@RAEXH@Z")
        self.assertIn("public:", result)


# ---------------------------------------------------------------------------
# Special handling functions ($ prefix in type info)
# ---------------------------------------------------------------------------


class TestMSVCSpecialHandlingFunctions(unittest.TestCase):
    """Test $-prefixed special function types."""

    def test_shf_private_0(self):
        mangled = "?foo@@$0AEXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)
        self.assertEqual(sym.type_info.access, "private")

    def test_shf_private_1(self):
        mangled = "?foo@@$1AEXH@Z"
        sym = _parse(mangled)
        self.assertEqual(sym.type_info.access, "private")

    def test_shf_protected_2(self):
        mangled = "?foo@@$2AEXH@Z"
        sym = _parse(mangled)
        self.assertEqual(sym.type_info.access, "protected")

    def test_shf_protected_3(self):
        mangled = "?foo@@$3AEXH@Z"
        sym = _parse(mangled)
        self.assertEqual(sym.type_info.access, "protected")

    def test_shf_public_4(self):
        mangled = "?foo@@$4AEXH@Z"
        sym = _parse(mangled)
        self.assertEqual(sym.type_info.access, "public")

    def test_shf_public_5(self):
        mangled = "?foo@@$5AEXH@Z"
        sym = _parse(mangled)
        self.assertEqual(sym.type_info.access, "public")

    def test_shf_extern_c_j(self):
        mangled = "?foo@@$$J0YAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_shf_extern_c_n(self):
        mangled = "?foo@@$$N0YAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_shf_extern_c_o(self):
        mangled = "?foo@@$$O0YAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_shf_recurse_f(self):
        mangled = "?foo@@$$FYAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)
        self.assertEqual(sym.type_info.calling_convention, "__cdecl")

    def test_shf_recurse_h(self):
        mangled = "?foo@@$$HYAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_shf_recurse_l(self):
        mangled = "?foo@@$$LYAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_shf_recurse_m(self):
        mangled = "?foo@@$$MYAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_shf_recurse_q(self):
        mangled = "?foo@@$$QYAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_shf_vtordispex_r(self):
        mangled = "?foo@@$$R0AEXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)
        self.assertEqual(sym.type_info.access, "private")

    def test_shf_vtordispex_r_public(self):
        mangled = "?foo@@$$R4AEXH@Z"
        sym = _parse(mangled)
        self.assertEqual(sym.type_info.access, "public")

    def test_shf_vtordispex_r_protected(self):
        mangled = "?foo@@$$R2AEXH@Z"
        sym = _parse(mangled)
        self.assertEqual(sym.type_info.access, "protected")

    def test_shf_vcall_b(self):
        mangled = "?foo@@$$B"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)
        self.assertFalse(sym.type_info.is_member)

    def test_shf_unknown_code_raises(self):
        with self.assertRaises(ParseError):
            _parse("?foo@@$X")

    def test_shf_unknown_code2_raises(self):
        with self.assertRaises(ParseError):
            _parse("?foo@@$$X")


# ---------------------------------------------------------------------------
# Variable info codes (0-7)
# ---------------------------------------------------------------------------


class TestMSVCVariableCodes(unittest.TestCase):
    """Test variable info codes 0-7."""

    def test_protected_static_1(self):
        result = demangle_msvc("?var@MyClass@@1HA")
        self.assertIn("protected:", result)
        self.assertIn("static", result)

    def test_nonstatic_3(self):
        result = demangle_msvc("?var@MyClass@@3HA")
        self.assertIsInstance(result, str)

    def test_nonstatic_4(self):
        result = demangle_msvc("?var@MyClass@@4HA")
        self.assertIsInstance(result, str)

    def test_guard_5(self):
        mangled = "?guard@@5"
        sym = _parse(mangled)
        self.assertTrue(sym.type_info.is_guard)

    def test_vftable_6(self):
        mangled = "?foo@@6"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.VFTable)

    def test_vbtable_7(self):
        mangled = "?foo@@7"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.VFTable)

    def test_variable_with_based_prefix(self):
        mangled = "?foo@@_3HA"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.VariableInfo)


# ---------------------------------------------------------------------------
# $ extended types
# ---------------------------------------------------------------------------


class TestMSVCDollarTypes(unittest.TestCase):
    """Test $ prefix extended type codes in data type parsing."""

    def test_dollar_function_indirect(self):
        mangled = "?func@@YAX$AAHH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("func", result)

    def test_dollar_function_indirect_no_cc(self):
        mangled = "?func@@YAX$AKHH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_dollar_nullptr_t(self):
        result = demangle_msvc("?func@@YAX$T@Z")
        self.assertIn("std::nullptr_t", result)

    def test_dollar_empty_v(self):
        result = demangle_msvc("?func@@YAX$V@Z")
        self.assertIsInstance(result, str)

    def test_dollar_ellipsis_z(self):
        result = demangle_msvc("?func@@YAX$Z@Z")
        self.assertIn("...", result)

    def test_dollar_reference_c(self):
        result = demangle_msvc("?func@@YAX$CH@Z")
        self.assertIn("int&", result)

    def test_dollar_rvalue_ref_q(self):
        result = demangle_msvc("?func@@YAX$QH@Z")
        self.assertIn("int&&", result)

    def test_dollar_rvalue_ref_r(self):
        result = demangle_msvc("?func@@YAX$RH@Z")
        self.assertIn("int&&", result)

    def test_dollar_pointer_b(self):
        result = demangle_msvc("?func@@YAX$BH@Z")
        self.assertIn("int*", result)

    def test_dollar_unknown_type_warning(self):
        mangled = "?func@@YAX$XH@Z"
        parser = MSVCParser(mangled)
        parser.parse()
        self.assertTrue(any("unknown $ type code" in w for w in parser.warnings))


# ---------------------------------------------------------------------------
# _ prefix extended types
# ---------------------------------------------------------------------------


class TestMSVCUnderscoreTypes(unittest.TestCase):
    """Test _ prefix extended primitive types not already covered."""

    def test_underscore_dollar_inner(self):
        mangled = "?f@@YAX_$H@Z"
        result = demangle_msvc(mangled)
        self.assertIn("int", result)

    def test_underscore_unknown_warning(self):
        mangled = "?f@@YAX__@Z"
        parser = MSVCParser(mangled)
        parser.parse()
        self.assertTrue(any("unknown extended type" in w for w in parser.warnings))

    def test_underscore_g(self):
        result = demangle_msvc("?f@@YAX_G@Z")
        self.assertIn("unsigned short", result)

    def test_underscore_i(self):
        result = demangle_msvc("?f@@YAX_I@Z")
        self.assertIn("unsigned int", result)

    def test_underscore_k(self):
        result = demangle_msvc("?f@@YAX_K@Z")
        self.assertIn("unsigned __int64", result)

    def test_underscore_l(self):
        result = demangle_msvc("?f@@YAX_L@Z")
        self.assertIn("__int128", result)

    def test_underscore_m(self):
        result = demangle_msvc("?f@@YAX_M@Z")
        self.assertIn("unsigned __int128", result)

    def test_underscore_q(self):
        result = demangle_msvc("?f@@YAX_Q@Z")
        self.assertIn("char8_t", result)

    def test_underscore_s(self):
        result = demangle_msvc("?f@@YAX_S@Z")
        self.assertIn("char16_t", result)

    def test_underscore_u(self):
        result = demangle_msvc("?f@@YAX_U@Z")
        self.assertIn("char32_t", result)


# ---------------------------------------------------------------------------
# Reference types (A and B in _parse_data_type)
# ---------------------------------------------------------------------------


class TestMSVCReferenceTypes(unittest.TestCase):
    """Test reference type parsing (A and B codes)."""

    def test_far_reference_b(self):
        result = demangle_msvc("?func@@YAXBBH@Z")
        self.assertIn("int&", result)

    def test_reference_a_with_cv(self):
        result = demangle_msvc("?func@@YAXABH@Z")
        self.assertIn("int&", result)


# ---------------------------------------------------------------------------
# UDT names with special characters
# ---------------------------------------------------------------------------


class TestMSVCUDTNames(unittest.TestCase):
    """Test user-defined type names with ?, $, anonymous namespace."""

    def test_udt_anonymous_namespace(self):
        mangled = "?func@@YAXU?A@MyStruct@@@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("anonymous", result)

    def test_udt_backref(self):
        mangled = "?func@@YAXU?0MyStruct@@@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("MyStruct", result)

    def test_udt_template_name(self):
        mangled = "?func@@YAXU$Foo@H@@@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("Foo", result)

    def test_udt_truncated(self):
        mangled = "?func@@YAXUMyStruct"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# Embedded names
# ---------------------------------------------------------------------------


class TestMSVCEmbeddedNames(unittest.TestCase):
    """Test embedded name parsing (??? prefix).

    Note: ????0MyClass@@ (embedded constructor) fails because the fourth ?
    is not a valid special name code in _parse_special_name.
    """

    def test_embedded_four_question_raises(self):
        with self.assertRaises(ParseError):
            _parse("????0MyClass@@")

    def test_embedded_demangle_graceful(self):
        result = demangle_msvc("????0MyClass@@")
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# Vtable and vbtable
# ---------------------------------------------------------------------------


class TestMSVCVtableVbtable(unittest.TestCase):
    """Test vtable and vbtable parsing."""

    def test_vbtable(self):
        mangled = "??_8MyClass@@6B@"
        sym = _parse(mangled)
        self.assertEqual(sym.kind, "vbtable")
        self.assertIsInstance(sym.type_info, ast.VFTable)

    def test_vbtable_demangle(self):
        result = demangle_msvc("??_8MyClass@@6B@")
        self.assertIn("vftable", result)
        self.assertIn("MyClass", result)


# ---------------------------------------------------------------------------
# Scope fragments
# ---------------------------------------------------------------------------


class TestMSVCScopeFragments(unittest.TestCase):
    """Test scope fragment parsing: anonymous namespace, backref, template, unknown."""

    def test_anonymous_namespace_in_scope(self):
        # ?func@ns@?A@@ = func in ns::`anonymous namespace'
        mangled = "?func@ns@?A@@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("ns", result)
        self.assertIn("func", result)

    def test_anonymous_namespace_via_parser(self):
        mangled = "?func@ns@?A@@YAXH@Z"
        sym = _parse(mangled)
        scope_types = [type(s) for s in sym.qualified_name.scope]
        self.assertIn(ast.AnonymousNamespace, scope_types)

    def test_numeric_backref_in_scope(self):
        mangled = "?func@?0@ns@@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("ns", result)

    def test_unknown_question_in_scope(self):
        mangled = "?func@?X@ns@@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_template_in_scope_via_question(self):
        mangled = "?func@?$Foo@H@@ns@@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("Foo", result)
        self.assertIn("ns", result)

    def test_template_in_scope_via_dollar(self):
        mangled = "?func@$Foo@H@@ns@@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("Foo", result)


# ---------------------------------------------------------------------------
# Error handling paths
# ---------------------------------------------------------------------------


class TestMSVCErrorHandling(unittest.TestCase):
    """Test ParseError exceptions for malformed inputs."""

    def test_expect_method_success(self):
        parser = MSVCParser("@test")
        result = parser._expect("@")
        self.assertEqual(result, "@")

    def test_expect_method_failure(self):
        parser = MSVCParser("Xtest")
        with self.assertRaises(ParseError):
            parser._expect("@")

    def test_unknown_type_code_at_end(self):
        # 9 is not a valid type code — but in arg context ParseError is caught
        # Use it as a return type to avoid the arg-level catch
        with self.assertRaises(ParseError):
            _parse("?foo@@YA9H@Z")

    def test_unknown_special_name_code(self):
        with self.assertRaises(ParseError):
            _parse("??a@YAXH@Z")

    def test_unknown_operator_ext_code(self):
        with self.assertRaises(ParseError):
            _parse("???_Z@@")

    def test_unknown_operator_ext3_code(self):
        with self.assertRaises(ParseError):
            _parse("???__Z@@")

    def test_unknown_double_question_underscore(self):
        with self.assertRaises(ParseError):
            _parse("??_9@@")

    def test_non_question_start(self):
        with self.assertRaises(ParseError):
            _parse("hello")

    def test_empty_input(self):
        with self.assertRaises(ParseError):
            _parse("")

    def test_hashed_object(self):
        with self.assertRaises(ParseError):
            _parse("??@ABC123@")

    def test_unknown_type_info_code(self):
        with self.assertRaises(ParseError):
            _parse("?foo@@8H@Z")

    def test_non_parse_error_exception(self):
        # ??_1$ZZ → ValueError in int("ZZ", 16) → caught as Exception
        result = demangle_msvc("??_1$ZZ@@@@")
        self.assertIsInstance(result, str)

    def test_empty_fragment_name_raises(self):
        parser = MSVCParser("@@")
        with self.assertRaises(ParseError):
            parser._parse_fragment_name()


# ---------------------------------------------------------------------------
# Argument parsing edge cases
# ---------------------------------------------------------------------------


class TestMSVCArgumentParsing(unittest.TestCase):
    """Test edge cases in argument parsing."""

    def test_args_end_with_z(self):
        mangled = "?foo@@YAXHZ"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_args_end_of_input(self):
        mangled = "?foo@@YAXH"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_args_parse_error_break(self):
        mangled = "?foo@@YAXH9@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_question_in_type(self):
        mangled = "?foo@@YAX?H@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_all_void_params_render(self):
        func = ast.FunctionType(
            calling_convention="__cdecl",
            return_type="void",
            parameters=["void"],
            is_member=False,
        )
        sig = _render_function_signature(func, "foo")
        self.assertIn("void", sig)


# ---------------------------------------------------------------------------
# AST node __repr__ methods
# ---------------------------------------------------------------------------


class TestMSVCASTNodeRepr(unittest.TestCase):
    """Test __repr__ for all AST node classes."""

    def test_fragment_name_repr(self):
        node = ast.FragmentName("foo")
        r = repr(node)
        self.assertIn("foo", r)
        self.assertIn("FragmentName", r)

    def test_special_name_repr(self):
        node = ast.SpecialName("operator+", kind="operator")
        r = repr(node)
        self.assertIn("operator+", r)
        self.assertIn("operator", r)

    def test_template_name_repr(self):
        node = ast.TemplateName(ast.FragmentName("Foo"), ["int"])
        r = repr(node)
        self.assertIn("Foo", r)
        self.assertIn("int", r)
        self.assertIn("TemplateName", r)

    def test_qualified_name_repr(self):
        node = ast.QualifiedName([ast.FragmentName("ns")], ast.FragmentName("foo"))
        r = repr(node)
        self.assertIn("ns", r)
        self.assertIn("foo", r)
        self.assertIn("QualifiedName", r)

    def test_anonymous_namespace_repr(self):
        node = ast.AnonymousNamespace()
        r = repr(node)
        self.assertIn("AnonymousNamespace", r)

    def test_primitive_type_repr(self):
        node = ast.PrimitiveType("int")
        r = repr(node)
        self.assertIn("int", r)
        self.assertIn("PrimitiveType", r)

    def test_pointer_type_repr(self):
        node = ast.PointerType("int", is_const=True, is_volatile=False, is_far=True)
        r = repr(node)
        self.assertIn("int", r)
        self.assertIn("PointerType", r)
        self.assertIn("True", r)

    def test_reference_type_repr(self):
        node = ast.ReferenceType("int")
        r = repr(node)
        self.assertIn("int", r)
        self.assertIn("ReferenceType", r)

    def test_rvalue_reference_type_repr(self):
        node = ast.RvalueReferenceType("int")
        r = repr(node)
        self.assertIn("int", r)
        self.assertIn("RvalueReferenceType", r)

    def test_user_defined_type_repr(self):
        node = ast.UserDefinedType("struct", "MyStruct")
        r = repr(node)
        self.assertIn("struct", r)
        self.assertIn("MyStruct", r)
        self.assertIn("UserDefinedType", r)

    def test_function_type_repr(self):
        node = ast.FunctionType(
            calling_convention="__cdecl",
            return_type="void",
            parameters=["int"],
            is_member=True,
        )
        r = repr(node)
        self.assertIn("__cdecl", r)
        self.assertIn("void", r)
        self.assertIn("FunctionType", r)

    def test_variable_info_repr(self):
        node = ast.VariableInfo(access="public", is_static=True, var_type="int")
        r = repr(node)
        self.assertIn("public", r)
        self.assertIn("VariableInfo", r)

    def test_vftable_repr(self):
        node = ast.VFTable(scope=ast.QualifiedName([], ast.FragmentName("Foo")))
        r = repr(node)
        self.assertIn("VFTable", r)

    def test_msvc_symbol_repr(self):
        qn = ast.QualifiedName([], ast.FragmentName("foo"))
        node = ast.MSVCSymbol(qualified_name=qn, kind="function")
        r = repr(node)
        self.assertIn("MSVCSymbol", r)
        self.assertIn("function", r)


# ---------------------------------------------------------------------------
# Renderer code paths
# ---------------------------------------------------------------------------


class TestMSVCRendererPaths(unittest.TestCase):
    """Test specific renderer code paths."""

    def test_render_none(self):
        self.assertEqual(render(None), "")

    def test_render_qualified_name_none(self):
        self.assertEqual(_render_qualified_name(None), "")

    def test_render_template_name_component(self):
        tmpl = ast.TemplateName(ast.FragmentName("Foo"), ["int"])
        result = _render_name_component(tmpl)
        self.assertEqual(result, "Foo<int>")

    def test_render_anonymous_namespace_component(self):
        result = _render_name_component(ast.AnonymousNamespace())
        self.assertIn("anonymous", result)

    def test_render_string_component(self):
        result = _render_name_component("plain_string")
        self.assertEqual(result, "plain_string")

    def test_render_unknown_component_fallback(self):
        class Unknown:
            def __str__(self):
                return "unknown_str"

        result = _render_name_component(Unknown())
        self.assertEqual(result, "unknown_str")

    def test_render_function_with_thunk(self):
        func = ast.FunctionType(
            calling_convention="__thiscall",
            return_type="void",
            parameters=["int"],
            is_member=True,
            is_thunk=True,
            access="public",
        )
        prefix = _build_prefix(func)
        self.assertIn("[thunk]:", prefix)

    def test_render_function_with_cv_modifiers(self):
        func = ast.FunctionType(
            calling_convention="__thiscall",
            return_type="void",
            parameters=["int"],
            is_member=True,
            cv_modifiers="const",
        )
        sig = _render_function_signature(func, "MyClass::method")
        self.assertIn("const", sig)

    def test_render_variable_guard_with_name(self):
        var = ast.VariableInfo(is_guard=True)
        result = _render_variable(var, "guard_name")
        self.assertEqual(result, "guard_name")

    def test_render_variable_guard_no_name(self):
        var = ast.VariableInfo(is_guard=True)
        result = _render_variable(var, "")
        self.assertIn("local static guard", result)

    def test_render_variable_no_type(self):
        var = ast.VariableInfo()
        result = _render_variable(var, "myvar")
        self.assertEqual(result, "myvar")

    def test_render_vftable_with_scope(self):
        scope_qname = ast.QualifiedName([], ast.FragmentName("MyClass"))
        vft = ast.VFTable(scope=scope_qname)
        result = _render_vftable(vft, "ignored")
        self.assertIn("MyClass", result)
        self.assertIn("vftable", result)

    def test_render_function_no_qualified_name(self):
        func = ast.FunctionType(
            calling_convention="__cdecl",
            return_type="void",
            parameters=["int"],
            is_member=False,
        )
        sym = ast.MSVCSymbol(qualified_name=None, type_info=func, kind="function")
        result = render(sym)
        self.assertIsInstance(result, str)

    def test_render_variable_no_qualified_name(self):
        var = ast.VariableInfo(var_type="int")
        sym = ast.MSVCSymbol(qualified_name=None, type_info=var, kind="variable")
        result = render(sym)
        self.assertIsInstance(result, str)

    def test_render_vftable_no_qualified_name(self):
        vft = ast.VFTable(scope=None)
        sym = ast.MSVCSymbol(qualified_name=None, type_info=vft, kind="vtable")
        result = render(sym)
        self.assertIsInstance(result, str)

    def test_render_function_with_prefix_and_no_name(self):
        func = ast.FunctionType(
            calling_convention="__thiscall",
            return_type="void",
            parameters=["int"],
            is_member=True,
            access="public",
        )
        sym = ast.MSVCSymbol(qualified_name=None, type_info=func, kind="function")
        result = render(sym)
        self.assertIn("public:", result)

    def test_render_variable_with_prefix_and_no_name(self):
        var = ast.VariableInfo(access="public", is_static=True, var_type="int")
        sym = ast.MSVCSymbol(qualified_name=None, type_info=var, kind="variable")
        result = render(sym)
        self.assertIn("public:", result)

    def test_render_symbol_with_no_type_info(self):
        qn = ast.QualifiedName([], ast.FragmentName("foo"))
        sym = ast.MSVCSymbol(qualified_name=qn, type_info=None, kind="unknown")
        result = render(sym)
        self.assertEqual(result, "foo")


# ---------------------------------------------------------------------------
# __init__.py code paths
# ---------------------------------------------------------------------------


class TestMSVCInitPaths(unittest.TestCase):
    """Test __init__.py code paths."""

    def test_structured_fallback_on_failure(self):
        sym = demangle_msvc("??@ABC123@", structured=True)
        self.assertEqual(sym.format, "msvc")
        self.assertEqual(sym.full_name, "??@ABC123@")
        self.assertTrue(sym.parse_warnings)

    def test_structured_vbtable_kind(self):
        sym = demangle_msvc("???_8@@", structured=True)
        self.assertEqual(sym.kind, "vbtable")

    def test_structured_rtti_kind(self):
        sym = demangle_msvc("??_0H", structured=True)
        self.assertEqual(sym.kind, "rtti")

    def test_structured_ctor_kind(self):
        sym = demangle_msvc("??0Constructor@@QAE@X@Z", structured=True)
        self.assertEqual(sym.kind, "ctor")

    def test_structured_template_with_angle_brackets(self):
        # demangle_msvc for ?$ templates returns original due to render() crash,
        # so structured output won't detect template args from the demangled string.
        # Instead test _parse_basic_structure's angle-bracket detection directly
        # by using a non-MSVC-format symbol that contains < in the name.
        sym = demangle_msvc("?foo<bar>@@YAXH@Z", structured=True)
        # _parse_basic_structure detects < in name → is_template
        self.assertTrue(sym.is_template)

    def test_structured_static_function(self):
        sym = demangle_msvc("?baz@MyClass@@SGXH@Z", structured=True)
        self.assertTrue(sym.is_static)
        self.assertEqual(sym.access, "public")

    def test_structured_static_variable(self):
        sym = demangle_msvc("?svar@MyClass@@2HA", structured=True)
        self.assertTrue(sym.is_static)
        self.assertEqual(sym.access, "public")

    def test_structured_function_access_private(self):
        sym = demangle_msvc("?priv@MyClass@@AAEXH@Z", structured=True)
        self.assertEqual(sym.access, "private")

    def test_non_exception_error_returns_original(self):
        # This triggers a ValueError (non-ParseError) in _parse_encoded_number
        result = demangle_msvc("??_1$ZZ@@@@")
        self.assertEqual(result, "??_1$ZZ@@@@")

    def test_structured_non_exception_error(self):
        sym = demangle_msvc("??_1$ZZ@@@@", structured=True)
        self.assertEqual(sym.format, "msvc")
        self.assertTrue(sym.parse_warnings)

    def test_structured_dtor_kind(self):
        # Use a class name that doesn't contain "ctor" as a substring,
        # since _parse_basic_structure checks 'ctor' before '~'/'dtor'
        sym = demangle_msvc("??1MyCls@@UAE@X@Z", structured=True)
        self.assertEqual(sym.kind, "dtor")

    def test_structured_operator_kind(self):
        sym = demangle_msvc("??2@YAPAXI@Z", structured=True)
        self.assertEqual(sym.kind, "operator")

    def test_structured_no_scope_name(self):
        sym = demangle_msvc("?foo@@YAXH@Z", structured=True)
        self.assertEqual(sym.name, "foo")
        self.assertFalse(sym.is_member)


# ---------------------------------------------------------------------------
# Misc parser paths
# ---------------------------------------------------------------------------


class TestMSVCMiscParserPaths(unittest.TestCase):
    """Test miscellaneous parser code paths."""

    def test_based_prefix_in_type_info(self):
        mangled = "?foo@@_YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_dollar_type_info_special_handling(self):
        mangled = "?foo@@$0AEXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_render_template_helper(self):
        parser = MSVCParser("?$Foo@@H@YAXH@Z")
        sym = parser.parse()
        qn = sym.qualified_name
        if isinstance(qn, ast.TemplateName):
            rendered = parser._render_template(qn)
            self.assertIn("Foo", rendered)

    def test_type_string_method(self):
        parser = MSVCParser("H")
        result = parser._parse_type_string()
        self.assertEqual(result, "int")

    def test_at_end_method(self):
        parser = MSVCParser("?foo@@YAXH@Z")
        parser.pos = len(parser.mangled)
        self.assertTrue(parser._at_end())
        parser.pos = 0
        self.assertFalse(parser._at_end())

    def test_peek_at_end(self):
        parser = MSVCParser("AB")
        parser.pos = 2
        self.assertEqual(parser._peek(), "\x00")

    def test_next_at_end_raises(self):
        parser = MSVCParser("AB")
        parser.pos = 2
        with self.assertRaises(ParseError):
            parser._next()

    def test_primitive_z_ellipsis_in_template(self):
        # Z as ... in template arg context — parser produces TemplateName
        # with args=['...'], but render() crashes, so demangle returns original
        sym = _parse("?$Foo@@Z@YAXH@Z")
        self.assertIn("...", sym.qualified_name.args)

    def test_primitive_o_long_double(self):
        result = demangle_msvc("?f@@YAXO@Z")
        self.assertIn("long double", result)

    def test_primitive_c_char(self):
        result = demangle_msvc("?f@@YAXC@Z")
        self.assertIn("char", result)

    def test_primitive_e_unsigned_char(self):
        result = demangle_msvc("?f@@YAXE@Z")
        self.assertIn("unsigned char", result)

    def test_pointer_r_type(self):
        result = demangle_msvc("?f@@YAXRAH@Z")
        self.assertIsInstance(result, str)

    def test_pointer_s_type(self):
        result = demangle_msvc("?f@@YAXSAH@Z")
        self.assertIsInstance(result, str)

    def test_pointer_q_type(self):
        result = demangle_msvc("?f@@YAXQAH@Z")
        self.assertIsInstance(result, str)

    def test_pointer_with_cv(self):
        result = demangle_msvc("?f@@YAXPBH@Z")
        self.assertIn("const", result)
        self.assertIn("int*", result)

    def test_pointer_const_volatile(self):
        result = demangle_msvc("?f@@YAXPDH@Z")
        self.assertIn("const volatile", result)

    def test_enum_w4(self):
        result = demangle_msvc("?f@@YAXW4MyEnum@@@Z")
        self.assertIn("enum", result)
        self.assertIn("MyEnum", result)

    def test_nested_class_scope_render(self):
        result = demangle_msvc("?method@Inner@Outer@@UAEXH@Z")
        self.assertIn("Outer::Inner::method", result)

    def test_ctor_no_scope_keeps_empty_name(self):
        # Constructor with no scope — basic_name.name stays empty
        mangled = "??0@@QAE@X@Z"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertTrue(bn.is_ctor)
        # No scope → name stays empty
        self.assertEqual(bn.name, "")

    def test_dtor_no_scope_keeps_empty_name(self):
        mangled = "??1@@UAE@X@Z"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertTrue(bn.is_dtor)

    def test_encoded_number_at_sign(self):
        parser = MSVCParser("@")
        result = parser._parse_encoded_number()
        self.assertEqual(result, "0")

    def test_encoded_number_digit(self):
        parser = MSVCParser("5@")
        result = parser._parse_encoded_number()
        self.assertEqual(result, "5")


if __name__ == "__main__":
    unittest.main()
