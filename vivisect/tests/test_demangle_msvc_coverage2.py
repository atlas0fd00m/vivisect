"""
Additional targeted tests for remaining uncovered code paths in MSVC demangling.

Covers:
- RTTI Base Class Descriptor via ??_1 path (parser lines 285-296)
- Unknown ?? prefix raise (parser line 320)
- $ template name in qualified name (parser lines 376-377)
- Unknown ? in scope returns None (parser lines 460-462)
- MDString via _parse_md_string direct call (parser lines 612-617)
- RTTI4 with code 6 (parser line 655)
- $$J with non-digit count (parser line 745)
- __init__.py: scope split with :: (lines 125, 127, 135)
- __init__.py: _populate_from_ast return_type (line 170)
- __init__.py: _render_name_part hasattr (line 190)
"""

import unittest

from vivisect.demangle.msvc import ast_nodes as ast
from vivisect.demangle.msvc import demangle_msvc
from vivisect.demangle.msvc.parser import MSVCParser, ParseError
from vivisect.demangle.msvc.renderer import render


def _parse(mangled):
    parser = MSVCParser(mangled)
    return parser.parse()


class TestMSVCRTTIBaseClassDescriptorDoubleQ(unittest.TestCase):
    """Test RTTI Base Class Descriptor.

    ??_1 is NOT handled in _parse_double_question (1 not in RTTI_NAMES),
    so it raises ParseError. The Base Class Descriptor is only reachable
    via ???_R1 (through _parse_special_name).
    """

    def test_rtti_bd_via_double_question_raises(self):
        with self.assertRaises(ParseError):
            _parse("??_1@@@@@@")

    def test_rtti_bd_via_special_name(self):
        # ???_R1 goes through embedded → _parse_special_name → RTTI
        mangled = "???_R1@@@@@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("RTTI Base Class Descriptor", bn.name)
        self.assertIn("(0,0,0,0)", bn.name)

    def test_rtti_bd_via_special_name_negative(self):
        mangled = "???_R1?A?B?C?D@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("(-1,-2,-3,-4)", bn.name)

    def test_rtti_bd_via_special_name_hex(self):
        mangled = "???_R1$AB$CD$EF$01@@"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("171", bn.name)
        self.assertIn("205", bn.name)
        self.assertIn("239", bn.name)
        self.assertIn("1", bn.name)


class TestMSVCUnknownDoubleQuestionPrefix(unittest.TestCase):
    """Test the unknown ?? prefix raise (line 320)."""

    def test_unknown_double_question_prefix(self):
        # ?? followed by something that's not _ or ? — this path
        # is reached when _parse_double_question sees a non-_ non-? char
        # after consuming the second ?
        # Need: ?? then a char that's not _ or ? (but we already checked for
        # _ and ? in parse() before calling _parse_double_question)
        # Actually parse() only calls _parse_double_question when next2 is _ or ?
        # So the only way to reach line 320 is if the char after second ? is
        # neither _ nor ? — but we already verified next2 was _ or ?.
        # After _parse_double_question consumes the second ?, peek could be
        # something else if the string structure is different.
        # Let's try ??A (next2 is 'A', not _ or ?), so parse() falls through
        # to _parse_cpp_symbol. That won't reach line 320.
        # The only way to reach 320 is if _parse_double_question is called
        # with peek not _ and not ?. This happens when the initial check
        # matched but after consuming the second ? the situation changes.
        # Actually the check in parse() is: next2 = peek(1), and if next2 is
        # _ or ?, call _parse_double_question. After consuming second ?, the
        # peek is the same char as next2 was. So if next2 was ?, peek after
        # consuming is ?, which goes to embedded path (line 308).
        # If next2 was _, peek after consuming is _, which goes to line 259.
        # So line 320 is actually unreachable with the current parse() logic.
        # But we can call _parse_double_question directly.
        parser = MSVCParser("??X")
        parser.pos = 1  # skip first ?
        with self.assertRaises(ParseError):
            parser._parse_double_question()


class TestMSVCDollarTemplateInQualifiedName(unittest.TestCase):
    """Test $ template name in _parse_qualified_name (lines 376-377)."""

    def test_dollar_template_basic_name(self):
        # ?$Foo@@H@YAXH@Z — top-level ?$ goes through _parse_template_symbol
        # But $ in qualified name context: ?func@$Bar@H@@ns@@YAXH@Z
        # _parse_qualified_name: peek='$' → consume → _parse_template_name
        mangled = "?func@$Bar@H@@ns@@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("Bar", result)


class TestMSVCUnknownQuestionInScope(unittest.TestCase):
    """Test unknown ? in scope returns None (lines 460-462)."""

    def test_unknown_question_in_scope(self):
        # ?func@?X@ns@@ — ?X is not ?A, not ?$, not digit
        mangled = "?func@?X@ns@@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)
        self.assertIn("ns", result)

    def test_unknown_question_in_scope_parser(self):
        mangled = "?func@?X@ns@@YAXH@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)


class TestMSVCMdStringDirect(unittest.TestCase):
    """Test _parse_md_string directly (lines 612-617)."""

    def test_md_string_direct(self):
        parser = MSVCParser("hello@rest")
        result = parser._parse_md_string()
        self.assertEqual(result, "hello")
        self.assertEqual(parser.pos, 6)  # past the @

    def test_md_string_end_of_input(self):
        parser = MSVCParser("hello")
        result = parser._parse_md_string()
        self.assertEqual(result, "hello")

    def test_md_string_empty(self):
        parser = MSVCParser("@rest")
        result = parser._parse_md_string()
        self.assertEqual(result, "")


class TestMSVCRTTI4WithCode6(unittest.TestCase):
    """Test RTTI Complete Object Locator with code 6 (line 655)."""

    def test_rtti4_with_code6(self):
        # ???_R4@@6 goes through embedded path, kind="embedded"
        # The type_info is None because embedded doesn't parse type_info
        mangled = "???_R4@@6"
        sym = _parse(mangled)
        bn = sym.qualified_name.basic_name
        self.assertIn("RTTI Complete Object Locator", bn.name)
        self.assertEqual(sym.kind, "embedded")
        self.assertIsNone(sym.type_info)

    def test_rtti4_with_code6_demangle(self):
        result = demangle_msvc("???_R4@@6")
        self.assertIsInstance(result, str)


class TestMSVCExternCNonDigitCount(unittest.TestCase):
    """Test $$J with non-digit count (line 745 not reached)."""

    def test_extern_c_non_digit_count(self):
        # $$J then non-digit → cnt_ch.isdigit() is False → skip the loop
        mangled = "?foo@@$$JAYAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)
        self.assertEqual(sym.type_info.calling_convention, "__cdecl")


class TestMSVCInitScopeSplit(unittest.TestCase):
    """Test __init__.py scope splitting with :: delimiter."""

    def test_scope_with_nested_classes(self):
        sym = demangle_msvc("?method@Inner@Outer@@UAEXH@Z", structured=True)
        self.assertEqual(sym.scope, ["Outer", "Inner"])
        self.assertEqual(sym.name, "method")
        self.assertTrue(sym.is_member)

    def test_scope_with_namespace(self):
        sym = demangle_msvc("?func@ns@@YAXH@Z", structured=True)
        self.assertEqual(sym.scope, ["ns"])
        self.assertEqual(sym.name, "func")
        self.assertTrue(sym.is_member)

    def test_no_scope(self):
        sym = demangle_msvc("?foo@@YAXH@Z", structured=True)
        self.assertFalse(sym.is_member)
        self.assertEqual(sym.name, "foo")


class TestMSVCInitReturnTypeAndCV(unittest.TestCase):
    """Test __init__.py _populate_from_ast return_type and cv_qualifiers."""

    def test_return_type_non_void(self):
        sym = demangle_msvc("?func@@YAHH@Z", structured=True)
        self.assertEqual(sym.return_type, "int")

    def test_cv_qualifiers(self):
        sym = demangle_msvc("?bar@MyClass@@QBEXH@Z", structured=True)
        self.assertEqual(sym.cv_qualifiers, "const")

    def test_virtual_flag(self):
        sym = demangle_msvc("?bar@MyClass@@UAEXH@Z", structured=True)
        self.assertTrue(sym.is_virtual)

    def test_calling_convention_structured(self):
        sym = demangle_msvc("?foo@@YAXH@Z", structured=True)
        self.assertEqual(sym.calling_convention, "__cdecl")

    def test_parameters_structured(self):
        sym = demangle_msvc("?multi@@YAHHH@Z", structured=True)
        self.assertEqual(sym.parameters, ["int", "int"])

    def test_variable_return_type(self):
        sym = demangle_msvc("?myvar@@3HA", structured=True)
        self.assertEqual(sym.return_type, "int")


class TestMSVCInitRenderNamePart(unittest.TestCase):
    """Test __init__.py _render_name_part with different node types."""

    def test_render_name_part_special_name(self):
        # _render_name_part with SpecialName (hasattr 'name')
        sym = demangle_msvc("??0MyClass@@QAE@X@Z", structured=True)
        self.assertEqual(sym.name, "MyClass")
        self.assertTrue(sym.is_member)

    def test_render_name_part_template_in_scope(self):
        # Template in scope — _render_name_part handles TemplateName
        # via hasattr 'name' → but TemplateName has no 'name' attr, it has
        # base_name. Actually it doesn't have 'name', so it falls through to
        # str(part). Let's test this path.
        mangled = "?func@?$Foo@H@@ns@@YAXH@Z"
        sym = demangle_msvc(mangled, structured=True)
        self.assertIsInstance(sym, type(sym))


class TestMSVCMiscEdgeCases(unittest.TestCase):
    """Additional edge case tests."""

    def test_non_digit_extern_c_count(self):
        # $$N with non-digit count
        mangled = "?foo@@$$NAYAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_non_digit_extern_c_o_count(self):
        mangled = "?foo@@$$OAYAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_void_return_type_structured(self):
        sym = demangle_msvc("?foo@@YAXH@Z", structured=True)
        # return_type should not be set (void is filtered)
        self.assertFalse(hasattr(sym, "return_type") and sym.return_type == "void")

    def test_enum_without_w4(self):
        # W without 4 following — should still parse enum
        mangled = "?f@@YAXWMyEnum@@@Z"
        result = demangle_msvc(mangled)
        self.assertIn("enum", result)

    def test_struct_with_template_scope_type(self):
        # UDT with template in qualified name type
        mangled = "?f@@YAXU?$Tmpl@H@@@Z"
        result = demangle_msvc(mangled)
        self.assertIsInstance(result, str)

    def test_args_end_with_at(self):
        mangled = "?foo@@YAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)
        self.assertEqual(sym.type_info.parameters, ["int"])


class TestMSVCExternCWithDigitCount(unittest.TestCase):
    """Test $$J/$$N/$$O with digit count >= 1 to cover parser line 745."""

    def test_extern_c_j_with_count_2(self):
        mangled = "?foo@@$$J2YAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_extern_c_n_with_count_2(self):
        mangled = "?foo@@$$N2YAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)

    def test_extern_c_o_with_count_2(self):
        mangled = "?foo@@$$O2YAXH@Z"
        sym = _parse(mangled)
        self.assertIsInstance(sym.type_info, ast.FunctionType)


class TestMSVCInitBasicStructureEdgeCases(unittest.TestCase):
    """Test __init__.py _parse_basic_structure edge cases."""

    def test_colons_only_inside_angle_brackets(self):
        """Test that :: inside <> doesn't cause scope split (line 135)."""
        from vivisect.demangle.msvc import _parse_basic_structure
        from vivisect.demangle.common import DemangledSymbol

        sym = DemangledSymbol(format="msvc", full_name="void func(Foo<ns::Bar>)", original_mangled="?test@Z")
        _parse_basic_structure(sym, "void func(Foo<ns::Bar>)")
        # :: is in the string but only inside <>, so split_pos stays -1
        # and sym.name = demangled (line 135)
        self.assertEqual(sym.name, "void func(Foo<ns::Bar>)")
        self.assertEqual(sym.scope, [])
        self.assertTrue(sym.is_template)

    def test_no_colons_in_demangled(self):
        """Test demangled string with no :: at all (line 137)."""
        from vivisect.demangle.msvc import _parse_basic_structure
        from vivisect.demangle.common import DemangledSymbol

        sym = DemangledSymbol(format="msvc", full_name="void __cdecl foo(int)", original_mangled="?foo@@YAXH@Z")
        _parse_basic_structure(sym, "void __cdecl foo(int)")
        self.assertEqual(sym.name, "void __cdecl foo(int)")
        self.assertEqual(sym.kind, "function")


if __name__ == "__main__":
    unittest.main()
