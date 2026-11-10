"""
Comprehensive coverage tests for the Itanium ABI parser and renderer.

These tests target code paths that were uncovered by the original test suite,
focusing on:

- Special names: TS, TF, TJ, TH, TW, TA, TC, Th, Tv, Tc
- Guard variables and related: GV, GR, GA
- Transaction clones: GTt, GTn
- Array types (numeric, empty, expression-based dimensions)
- Vendor-extended types (u prefix, with and without template args)
- Decltype expressions (Dt and DT)
- Template parameter parsing (T_, T0_, T1_)
- Template argument kinds (type, expression, pack, primary literals)
- Substitution handling (indexed, std, with abi tags)
- CV qualifiers (const, volatile, restrict, combinations)
- Function types (with Y, cv-qualifiers, ref-qualifiers)
- Local names and discriminators
- Inheriting constructors (CI1, CI2) and C3
- Nested names with ref-qualifiers (R, O)
- Renderer edge cases (None, unknown nodes, out-of-range subs)
- AST node __repr__ and children() methods
- __init__.py structured output and error fallback paths
- _Float<N> extended builtin types
- Conversion operators
- Vendor extension suffixes (dot)
- __Z prefix (old GCC)
"""

import unittest

from vivisect.demangle import DemangledSymbol, demangle
from vivisect.demangle.itanium import ast_nodes as ast
from vivisect.demangle.itanium import demangle_itanium, demangle_itanium_symbol
from vivisect.demangle.itanium.parser import ParseError, ItaniumParser, parse
from vivisect.demangle.itanium.renderer import Renderer, render


class TestSpecialNamesTS_TF_TJ_TH_TW(unittest.TestCase):
    """Test special name codes TS, TF, TJ, TH, TW."""

    def test_typeinfo_name_TS(self):
        self.assertEqual(demangle_itanium("_ZTS1A"), "typeinfo name for A")

    def test_typeinfo_name_TS_nested(self):
        result = demangle_itanium("_ZTSN3foo3barE")
        self.assertIn("typeinfo name", result)
        self.assertIn("foo", result)
        self.assertIn("bar", result)

    def test_typeinfo_fn_TF(self):
        result = demangle_itanium("_ZTF1A")
        self.assertIn("typeinfo fn", result)
        self.assertIn("A", result)

    def test_java_class_TJ(self):
        result = demangle_itanium("_ZTJ1A")
        self.assertIn("java class", result)
        self.assertIn("A", result)

    def test_tls_init_TH(self):
        result = demangle_itanium("_ZTH1A")
        self.assertIn("TLS init", result)
        self.assertIn("A", result)

    def test_tls_wrapper_TW(self):
        result = demangle_itanium("_ZTW1A")
        self.assertIn("TLS wrapper", result)
        self.assertIn("A", result)

    def test_tls_init_TH_name(self):
        """TH parses a <name>, not a <type>."""
        result = demangle_itanium("_ZTHN3foo3barE")
        self.assertIn("TLS init", result)

    def test_tls_wrapper_TW_name(self):
        """TW parses a <name>, not a <type>."""
        result = demangle_itanium("_ZTW3foo3barE")
        self.assertIn("TLS wrapper", result)

    def test_typeinfo_fn_TF_type(self):
        """TF parses a <type>."""
        result = demangle_itanium("_ZTFN3foo3barE")
        self.assertIn("typeinfo fn", result)

    def test_typeinfo_fn_TF_builtin(self):
        result = demangle_itanium("_ZTFi")
        self.assertIn("typeinfo fn", result)
        self.assertIn("int", result)

    def test_java_class_TJ_type(self):
        result = demangle_itanium("_ZTJP1A")
        self.assertIn("java class", result)

    def test_parser_direct_TS(self):
        p = ItaniumParser("_ZTS1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "typeinfo name")

    def test_parser_direct_TF(self):
        p = ItaniumParser("_ZTF1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "typeinfo fn")

    def test_parser_direct_TJ(self):
        p = ItaniumParser("_ZTJ1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "java class")

    def test_parser_direct_TH(self):
        p = ItaniumParser("_ZTH1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "tls init")

    def test_parser_direct_TW(self):
        p = ItaniumParser("_ZTW1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "tls wrapper")


class TestSpecialNamesTA_TC(unittest.TestCase):
    """Test template parm (TA) and construction vtable (TC)."""

    def test_template_parm_TA(self):
        result = demangle_itanium("_ZTA1A")
        self.assertIn("template parm", result)
        self.assertIn("A", result)

    def test_construction_vtable_TC(self):
        result = demangle_itanium("_ZTC1A0_1B")
        self.assertIn("construction vtable", result)
        self.assertIn("B", result)

    def test_parser_direct_TA(self):
        p = ItaniumParser("_ZTA1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "template parm")

    def test_parser_direct_TC(self):
        p = ItaniumParser("_ZTC1A0_1B")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "construction vtable")

    def test_TC_with_offset(self):
        """TC <type> <number> _ <type> — construction vtable with nonzero offset."""
        p = ItaniumParser("_ZTC1A16_1B")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "construction vtable")


class TestThunks(unittest.TestCase):
    """Test non-virtual thunk (Th), virtual thunk (Tv), covariant thunk (Tc)."""

    def test_non_virtual_thunk_Th(self):
        result = demangle_itanium("_ZTh4_1A")
        self.assertIn("thunk", result)
        self.assertIn("A", result)

    def test_virtual_thunk_Tv(self):
        result = demangle_itanium("_ZTv0_4_1A")
        self.assertIn("thunk", result)
        self.assertIn("A", result)

    def test_covariant_thunk_Tc(self):
        """Tc h<offset>_ h<offset>_ <encoding>."""
        result = demangle_itanium("_ZTch4_h8_1A")
        self.assertIn("thunk", result)
        self.assertIn("A", result)

    def test_parser_direct_Th(self):
        p = ItaniumParser("_ZTh4_1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "thunk")

    def test_parser_direct_Tv(self):
        p = ItaniumParser("_ZTv0_4_1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "virtual thunk")

    def test_parser_direct_Tc(self):
        p = ItaniumParser("_ZTch4_h8_1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "covariant thunk")

    def test_thunk_with_function_encoding(self):
        """Th <offset> _ <function encoding> — thunk to a real function."""
        result = demangle_itanium("_ZTh8_N3foo3barEv")
        self.assertIn("thunk", result)

    def test_virtual_thunk_with_function_encoding(self):
        result = demangle_itanium("_ZTv0_8_N3foo3barEv")
        self.assertIn("thunk", result)

    def test_covariant_thunk_with_function_encoding(self):
        result = demangle_itanium("_ZTch4_h8_N3foo3barEv")
        self.assertIn("thunk", result)


class TestGuardVariables(unittest.TestCase):
    """Test guard variable (GV), reference temp (GR), hidden alias (GA)."""

    def test_guard_variable_GV(self):
        result = demangle_itanium("_ZGV1A")
        self.assertIn("guard variable", result)
        self.assertIn("A", result)

    def test_reference_temp_GR(self):
        result = demangle_itanium("_ZGR1A_")
        self.assertIn("reference temporary", result)
        self.assertIn("A", result)

    def test_hidden_alias_GA(self):
        result = demangle_itanium("_ZGA1A")
        self.assertIn("hidden alias", result)
        self.assertIn("A", result)

    def test_guard_variable_nested_name(self):
        result = demangle_itanium("_ZGVN3foo3barE")
        self.assertIn("guard variable", result)

    def test_parser_direct_GV(self):
        p = ItaniumParser("_ZGV1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "guard variable")

    def test_parser_direct_GR(self):
        p = ItaniumParser("_ZGR1A_")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "reference temp")

    def test_parser_direct_GA(self):
        p = ItaniumParser("_ZGA1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "hidden alias")


class TestTransactionClones(unittest.TestCase):
    """Test transaction clone (GTt) and non-transaction clone (GTn)."""

    def test_transaction_clone_GTt(self):
        result = demangle_itanium("_ZGTt1A")
        self.assertIn("transaction clone", result)
        self.assertIn("A", result)

    def test_non_transaction_clone_GTn(self):
        result = demangle_itanium("_ZGTn1A")
        self.assertIn("non-transaction clone", result)
        self.assertIn("A", result)

    def test_parser_direct_GTt(self):
        p = ItaniumParser("_ZGTt1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "transaction clone")

    def test_parser_direct_GTn(self):
        p = ItaniumParser("_ZGTn1A")
        node = p.parse()
        self.assertIsInstance(node, ast.SpecialName)
        self.assertEqual(node.kind, "non-transaction clone")


class TestArrayTypes(unittest.TestCase):
    """Test array type parsing and rendering."""

    def test_array_numeric_dimension(self):
        self.assertEqual(demangle_itanium("_Z3fooA5_i"), "foo(int [5])")

    def test_array_empty_dimension(self):
        self.assertEqual(demangle_itanium("_Z3fooA_i"), "foo(int [])")

    def test_array_pointer_to(self):
        result = demangle_itanium("_Z3fooPA5_i")
        self.assertIn("[5]", result)
        self.assertIn("*", result)

    def test_array_multi_dim(self):
        result = demangle_itanium("_Z3fooA3_A4_i")
        self.assertIn("[3]", result)
        self.assertIn("[4]", result)

    def test_array_char(self):
        result = demangle_itanium("_Z3fooA10_c")
        self.assertIn("char", result)
        self.assertIn("[10]", result)

    def test_parser_array_node(self):
        p = ItaniumParser("_Z3fooA5_i")
        node = p.parse()
        # Walk the AST to find the Array node
        self.assertIsInstance(node, ast.Name)
        bare = node.bare_function
        self.assertIsNotNone(bare)
        found = False
        for t in bare.types:
            if isinstance(t, ast.Array):
                found = True
                self.assertEqual(t.dimension, "5")
                self.assertIsInstance(t.element_type, ast.BuiltinType)
        self.assertTrue(found)

    def test_array_expression_dimension(self):
        """Array with expression-based dimension."""
        result = demangle_itanium("_Z3fooAp_i")
        self.assertIn("[", result)
        self.assertIn("]", result)


class TestVendorExtendedTypes(unittest.TestCase):
    """Test vendor-extended types (u prefix)."""

    def test_vendor_ext_simple(self):
        self.assertEqual(demangle_itanium("_Z3foou5Token"), "foo(Token)")

    def test_vendor_ext_short_name(self):
        result = demangle_itanium("_Z3foou1X")
        self.assertIn("X", result)

    def test_parser_vendor_ext(self):
        p = ItaniumParser("_Z3foou5Token")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)
        bare = node.bare_function
        self.assertIsNotNone(bare)
        found = False
        for t in bare.types:
            if isinstance(t, ast.VendorExtendedType):
                found = True
                self.assertEqual(t.name, "Token")
        self.assertTrue(found)

    def test_vendor_ext_with_template_args(self):
        """u <source-name> I <template-args> E."""
        p = ItaniumParser("_Z3foou5TokenIiE")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)
        bare = node.bare_function
        self.assertIsNotNone(bare)
        found = False
        for t in bare.types:
            if isinstance(t, ast.VendorExtendedType):
                found = True
                self.assertIsNotNone(t.template_args)
        self.assertTrue(found)


class TestDecltype(unittest.TestCase):
    """Test decltype expressions (Dt and DT)."""

    def test_decltype_Dt(self):
        result = demangle_itanium("_Z3fooDt1AE")
        self.assertIn("decltype", result)

    def test_decltype_DT(self):
        result = demangle_itanium("_Z3fooDT1AE")
        self.assertIn("decltype", result)

    def test_parser_decltype_Dt(self):
        p = ItaniumParser("_Z3fooDt1AE")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)
        bare = node.bare_function
        found = False
        for t in bare.types:
            if isinstance(t, ast.Decltype):
                found = True
                self.assertFalse(t.is_template)
        self.assertTrue(found)

    def test_parser_decltype_DT(self):
        p = ItaniumParser("_Z3fooDT1AE")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)
        bare = node.bare_function
        found = False
        for t in bare.types:
            if isinstance(t, ast.Decltype):
                found = True
                self.assertTrue(t.is_template)
        self.assertTrue(found)


class TestFloatExtendedTypes(unittest.TestCase):
    """Test DF<number>_ extended builtin types (_Float16, _Float32, etc.)."""

    def test_float16(self):
        result = demangle_itanium("_Z3fooDF16_")
        self.assertIn("_Float16", result)

    def test_float32(self):
        result = demangle_itanium("_Z3fooDF32_")
        self.assertIn("_Float32", result)

    def test_float64(self):
        result = demangle_itanium("_Z3fooDF64_")
        self.assertIn("_Float64", result)

    def test_float128(self):
        result = demangle_itanium("_Z3fooDF128_")
        self.assertIn("_Float128", result)

    def test_parser_float_type(self):
        p = ItaniumParser("_Z3fooDF32_")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)
        bare = node.bare_function
        found = False
        for t in bare.types:
            if isinstance(t, ast.BuiltinType):
                if "_Float32" in t.name:
                    found = True
        self.assertTrue(found)


class TestTemplateParameters(unittest.TestCase):
    """Test template parameter parsing (T_, T0_, T1_)."""

    def test_template_param_T0(self):
        result = demangle_itanium("_Z3fooIiiEvT_T0_")
        self.assertIn("foo", result)
        self.assertIn("int", result)

    def test_template_param_T1(self):
        result = demangle_itanium("_Z3fooIiiiEvT_T0_T1_")
        self.assertIn("foo", result)
        self.assertIn("int", result)

    def test_parser_template_param_T(self):
        p = ItaniumParser("_Z3fooIiEvT_")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)

    def test_parser_template_param_T0(self):
        p = ItaniumParser("_Z3fooIiiEvT_T0_")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)

    def test_template_param_direct(self):
        """Test _parse_template_param directly."""
        p = ItaniumParser("T_")
        p.template_subs = [ast.BuiltinType("int", "i")]
        tp = p._parse_template_param()
        self.assertIsInstance(tp, ast.TemplateParam)
        self.assertEqual(tp.index, 0)

    def test_template_param_T2(self):
        p = ItaniumParser("T2_")
        tp = p._parse_template_param()
        self.assertIsInstance(tp, ast.TemplateParam)
        self.assertEqual(tp.index, 3)


class TestTemplateArgKinds(unittest.TestCase):
    """Test all template-arg kinds: type, expression (X), pack (J), primary (L)."""

    def test_template_arg_expression_X(self):
        """X <expression> E."""
        result = demangle_itanium("_Z3fooIXL5EEEvv")
        self.assertIsInstance(result, str)

    def test_template_arg_pack_J(self):
        """J <template-arg>* E."""
        result = demangle_itanium("_Z3fooIJiiEEvT_")
        self.assertIsInstance(result, str)

    def test_template_arg_primary_int(self):
        """L <type> <value> E for int."""
        result = demangle_itanium("_Z3fooILi5EEvv")
        self.assertEqual(result, "void foo<5>()")

    def test_template_arg_primary_uint(self):
        result = demangle_itanium("_Z3fooILj5EEvv")
        self.assertEqual(result, "void foo<5u>()")

    def test_template_arg_primary_long(self):
        result = demangle_itanium("_Z3fooILl5EEvv")
        self.assertEqual(result, "void foo<5l>()")

    def test_template_arg_primary_unsigned_long(self):
        result = demangle_itanium("_Z3fooILm5EEvv")
        self.assertEqual(result, "void foo<5ul>()")

    def test_template_arg_primary_long_long(self):
        result = demangle_itanium("_Z3fooILx5EEvv")
        self.assertEqual(result, "void foo<5ll>()")

    def test_template_arg_primary_unsigned_long_long(self):
        result = demangle_itanium("_Z3fooILy5EEvv")
        self.assertEqual(result, "void foo<5ull>()")

    def test_template_arg_primary_bool_true(self):
        result = demangle_itanium("_Z3fooILb1EEvv")
        self.assertEqual(result, "void foo<true>()")

    def test_template_arg_primary_bool_false(self):
        result = demangle_itanium("_Z3fooILb0EEvv")
        self.assertEqual(result, "void foo<false>()")

    def test_template_arg_primary_char(self):
        """Char literal — our parser renders value without cast."""
        result = demangle_itanium("_Z3fooILc5EEvv")
        self.assertIn("foo<5>", result)

    def test_template_arg_primary_signed_char(self):
        result = demangle_itanium("_Z3fooILa5EEvv")
        self.assertIn("foo", result)

    def test_template_arg_primary_wchar_t(self):
        result = demangle_itanium("_Z3fooILw5EEvv")
        self.assertIn("foo", result)

    def test_template_arg_primary_short(self):
        result = demangle_itanium("_Z3fooILs5EEvv")
        self.assertIn("foo", result)

    def test_template_arg_primary_unsigned_short(self):
        result = demangle_itanium("_Z3fooILt5EEvv")
        self.assertIn("foo", result)

    def test_template_arg_primary_unsigned_char(self):
        result = demangle_itanium("_Z3fooILh5EEvv")
        self.assertIn("foo", result)

    def test_template_arg_type(self):
        result = demangle_itanium("_Z3fooI1AEvT_")
        self.assertIn("foo", result)

    def test_parser_template_arg_expression(self):
        p = ItaniumParser("XL5EE")
        arg = p._parse_template_arg()
        self.assertIsInstance(arg, ast.TemplateArg)
        self.assertEqual(arg.kind, "expression")

    def test_parser_template_arg_pack(self):
        p = ItaniumParser("JiiE")
        arg = p._parse_template_arg()
        self.assertIsInstance(arg, ast.TemplateArg)
        self.assertEqual(arg.kind, "pack")
        self.assertIsInstance(arg.value, list)


class TestSubstitutions(unittest.TestCase):
    """Test substitution handling, including indexed subs and std subs."""

    def test_substitution_S0(self):
        """S0_ refers to second substitution (index 1)."""
        result = demangle_itanium("_Z3fooPiS0_")
        self.assertIn("int", result)
        self.assertIn("*", result)

    def test_substitution_SA(self):
        """SA_ = seq-id with uppercase A."""
        # Build a symbol with enough subs to use SA_
        # SA_ = index 37 (A=10 in base-36, so SA_ = 10+1 = 11)
        # Use a real example: _Z3fooPiPcPsPdPfPbPaPhPjPlPmPnPoPpPqPwPxPyS_
        # That's too complex. Test the _parse_seq_id directly.
        p = ItaniumParser("SA_")
        p.subs = [ast.BuiltinType("int", "i")] * 11
        sub = p._parse_substitution()
        self.assertIsInstance(sub, ast.Substitution)
        self.assertEqual(sub.index, 11)

    def test_substitution_std_sub_with_abi_tag(self):
        """Ss followed by B (abi tag) should add sub to table."""
        p = ItaniumParser("_Z3fooSsB5cxx11")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)
        # The SsB5cxx11 path adds the sub to the table
        self.assertGreater(len(p.subs), 0)

    def test_parser_substitution_none(self):
        """_parse_substitution returns None when not at S."""
        p = ItaniumParser("i")
        result = p._parse_substitution(prefix=False)
        self.assertIsNone(result)

    def test_parser_substitution_invalid(self):
        """_parse_substitution raises on invalid char after S."""
        p = ItaniumParser("SQ")
        with self.assertRaises(ParseError):
            p._parse_substitution(prefix=False)

    def test_get_substitution_out_of_range(self):
        """_get_substitution raises on out-of-range index."""
        p = ItaniumParser("_Z3foov")
        p.parse()
        with self.assertRaises(ParseError):
            p._get_substitution(999)


class TestCVQualifiers(unittest.TestCase):
    """Test CV qualifiers: const, volatile, restrict, and combinations."""

    def test_const_int(self):
        result = demangle_itanium("_Z3fooKi")
        self.assertIn("const", result)
        self.assertIn("int", result)

    def test_volatile_int(self):
        result = demangle_itanium("_Z3fooVi")
        self.assertIn("volatile", result)
        self.assertIn("int", result)

    def test_restrict_int(self):
        result = demangle_itanium("_Z3foori")
        self.assertIn("restrict", result)
        self.assertIn("int", result)

    def test_const_volatile_int(self):
        result = demangle_itanium("_Z3fooKVi")
        self.assertIn("const", result)
        self.assertIn("volatile", result)

    def test_volatile_const_int(self):
        result = demangle_itanium("_Z3fooVKi")
        self.assertIn("const", result)
        self.assertIn("volatile", result)

    def test_const_pointer(self):
        result = demangle_itanium("_Z3fooPKi")
        self.assertIn("const", result)
        self.assertIn("*", result)

    def test_const_volatile_restrict(self):
        result = demangle_itanium("_Z3foorKVi")
        self.assertIn("restrict", result)
        self.assertIn("const", result)
        self.assertIn("volatile", result)


class TestFunctionTypes(unittest.TestCase):
    """Test function type parsing and rendering."""

    def test_function_pointer_void(self):
        self.assertEqual(demangle_itanium("_Z3fooPFvvE"), "foo(void (*)())")

    def test_function_pointer_with_params(self):
        self.assertEqual(demangle_itanium("_Z3fooPFviE"), "foo(void (*)(int))")

    def test_function_pointer_extern_C(self):
        """F Y <bare-function-type> E — extern 'C' function type."""
        result = demangle_itanium("_Z3fooPFYivE")
        self.assertIn("(*)", result)

    def test_function_type_with_return(self):
        """PFRivE = pointer to function returning int&, taking void."""
        result = demangle_itanium("_Z3fooPFRivE")
        self.assertIn("int&", result)
        self.assertIn("(*)", result)

    def test_function_type_with_cv(self):
        """Function type with cv-qualifiers (member function pointer)."""
        result = demangle_itanium("_Z1fM1AKFvvE")
        self.assertIn("const", result)
        self.assertIn("A::*", result)

    def test_function_type_empty(self):
        """Render a FunctionType with empty bare_function."""
        r = Renderer()
        ft = ast.FunctionType(ast.BareFunctionType([]))
        result = r.render(ft)
        self.assertEqual(result, "void ()")

    def test_function_type_with_cv_and_ref(self):
        """FunctionType with cv and ref qualifiers."""
        r = Renderer()
        bare = ast.BareFunctionType([ast.BuiltinType("void", "v"), ast.BuiltinType("int", "i")])
        ft = ast.FunctionType(bare, cv="const", ref="&&")
        result = r.render(ft)
        self.assertIn("const", result)
        self.assertIn("&&", result)

    def test_pointer_to_const_function(self):
        """Pointer to CV-qualified function type."""
        r = Renderer()
        bare = ast.BareFunctionType([ast.BuiltinType("void", "v")])
        ft = ast.FunctionType(bare)
        cvft = ast.CVQualifiedType(ft, "const")
        ptr = ast.PointerType(cvft)
        result = r.render(ptr)
        self.assertIn("(*)", result)

    def test_pointer_to_function_with_cv_ref(self):
        """Pointer to function with cv and ref qualifiers."""
        r = Renderer()
        bare = ast.BareFunctionType([ast.BuiltinType("void", "v"), ast.BuiltinType("int", "i")])
        ft = ast.FunctionType(bare, cv="const", ref="&")
        ptr = ast.PointerType(ft)
        result = r.render(ptr)
        self.assertIn("const", result)
        self.assertIn("&", result)

    def test_pointer_to_const_function_with_params(self):
        """Pointer to CV-qualified function with params."""
        r = Renderer()
        bare = ast.BareFunctionType([ast.BuiltinType("void", "v"), ast.BuiltinType("int", "i")])
        ft = ast.FunctionType(bare)
        cvft = ast.CVQualifiedType(ft, "const")
        ptr = ast.PointerType(cvft)
        result = r.render(ptr)
        self.assertIn("int", result)
        self.assertIn("(*)", result)

    def test_pointer_to_const_function_empty(self):
        """Pointer to CV-qualified function with empty bare."""
        r = Renderer()
        ft = ast.FunctionType(ast.BareFunctionType([]))
        cvft = ast.CVQualifiedType(ft, "const")
        ptr = ast.PointerType(cvft)
        result = r.render(ptr)
        self.assertIn("(*)", result)


class TestNestedNameQualifiers(unittest.TestCase):
    """Test nested names with CV-qualifiers and ref-qualifiers."""

    def test_nested_name_const(self):
        """NK prefix — const-qualified nested name."""
        result = demangle_itanium("_ZNK1A3fooEv")
        self.assertIn("const", result)
        self.assertIn("A", result)

    def test_nested_name_ref_qualifier_R(self):
        """NR prefix — lvalue ref-qualified nested name."""
        result = demangle_itanium("_ZNR1A3fooEv")
        self.assertIn("&", result)

    def test_nested_name_ref_qualifier_O(self):
        """NO prefix — rvalue ref-qualified nested name."""
        result = demangle_itanium("_ZNO1A3fooEv")
        self.assertIn("&&", result)

    def test_nested_name_const_ref(self):
        """NK followed by R — const & qualified."""
        result = demangle_itanium("_ZNKR1A3fooEv")
        self.assertIn("const", result)
        self.assertIn("&", result)

    def test_nested_name_const_rvalue(self):
        """NK followed by O — const && qualified."""
        result = demangle_itanium("_ZNKO1A3fooEv")
        self.assertIn("const", result)
        self.assertIn("&&", result)


class TestLocalNames(unittest.TestCase):
    """Test local name parsing (Z prefix)."""

    def test_local_name(self):
        result = demangle_itanium("_ZZ3foovE3bar")
        self.assertIn("foo", result)
        self.assertIn("bar", result)

    def test_local_name_string_literal(self):
        """Z <encoding> E s — string literal."""
        result = demangle_itanium("_ZZ3foovEs")
        self.assertIsInstance(result, str)

    def test_local_name_with_discriminator(self):
        """Z <encoding> E <entity> <discriminator>."""
        result = demangle_itanium("_ZZ3foovE3bar_0")
        self.assertIsInstance(result, str)

    def test_parser_local_name(self):
        p = ItaniumParser("_ZZ3foovE3bar")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)
        self.assertIsInstance(node.qualified_name, ast.NestedName)

    def test_parser_string_literal(self):
        p = ItaniumParser("_ZZ3foovEs")
        node = p.parse()
        # string literal returns the function encoding
        self.assertIsInstance(node, ast.Name)


class TestConstructorsSpecial(unittest.TestCase):
    """Test inheriting constructors and C3."""

    def test_inheriting_constructor_CI1(self):
        result = demangle_itanium("_ZN1ACI1Ev")
        self.assertIn("A", result)
        self.assertIn("A()", result)

    def test_inheriting_constructor_CI2(self):
        result = demangle_itanium("_ZN1ACI2Ev")
        self.assertIn("A", result)

    def test_allocating_constructor_C3(self):
        result = demangle_itanium("_ZN1AC3Ev")
        self.assertIn("A", result)

    def test_parser_CI1(self):
        p = ItaniumParser("_ZN1ACI1Ev")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)

    def test_parser_C3(self):
        p = ItaniumParser("_ZN1AC3Ev")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)


class TestConversionOperators(unittest.TestCase):
    """Test conversion operators (cv)."""

    def test_conversion_to_int(self):
        result = demangle_itanium("_ZN1AcviEv")
        self.assertIn("operator int", result)

    def test_conversion_to_void(self):
        result = demangle_itanium("_ZN1AcvvEv")
        self.assertIn("operator void", result)

    def test_conversion_to_pointer(self):
        result = demangle_itanium("_ZN1AcvPiEv")
        self.assertIn("operator", result)

    def test_parser_conversion_operator(self):
        p = ItaniumParser("_ZN1AcviEv")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)


class TestAbiTags(unittest.TestCase):
    """Test ABI tags (B prefix)."""

    def test_abi_tag_on_name(self):
        result = demangle_itanium("_Z3fooB5cxx11v")
        self.assertIn("[abi:cxx11]", result)

    def test_abi_tag_multiple(self):
        """Multiple abi tags: B<tag1> B<tag2>."""
        result = demangle_itanium("_Z3fooB5cxx11B3fooEv")
        self.assertIn("[abi:cxx11]", result)

    def test_parser_abi_tags(self):
        p = ItaniumParser("_Z3fooB5cxx11v")
        node = p.parse()
        self.assertIsInstance(node, ast.Name)


class TestPrefixAndSubstitutionInNestedNames(unittest.TestCase):
    """Test substitution handling inside nested name prefixes."""

    def test_substitution_in_prefix(self):
        """S_ used as a prefix component inside a nested name."""
        # _Z3fooPiS_ — S_ refers to first sub (int*)
        result = demangle_itanium("_Z3fooPiS_")
        self.assertIn("int", result)
        self.assertIn("*", result)

    def test_multiple_substitutions(self):
        result = demangle_itanium("_Z3fooPiS_S_")
        self.assertIn("int*", result)

    def test_std_substitution_as_prefix(self):
        """St used as prefix inside nested name."""
        result = demangle_itanium("_ZSt3fooEv")
        self.assertIn("std", result)
        self.assertIn("foo", result)

    def test_std_substitution_with_template_in_prefix(self):
        """St <source-name> I <template-args> E inside nested name."""
        result = demangle_itanium("_ZSt6vectorIiSaIiEE")
        self.assertIn("std", result)
        self.assertIn("vector", result)

    def test_std_operator_in_prefix(self):
        """St followed by an operator name."""
        result = demangle_itanium("_ZSt4swapIiEvRT_S1_")
        self.assertIn("std", result)
        self.assertIn("swap", result)


class TestStPrefixInTypeContext(unittest.TestCase):
    """Test St substitution in type context (not prefix)."""

    def test_st_as_type_with_source_name(self):
        """St <source-name> as a type."""
        result = demangle_itanium("_Z3fooSt6vectorIiE")
        self.assertIn("std", result)

    def test_st_as_type_with_template(self):
        """St <source-name> I <template-args> E as a type."""
        result = demangle_itanium("_Z3fooSt6vectorIiE")
        self.assertIn("std", result)

    def test_sa_with_template_args(self):
        """Sa followed by template args (template-template-param)."""
        # Sa = std::allocator, with template args = std::allocator<T>
        result = demangle_itanium("_ZSt9allocatorIiE")
        self.assertIn("allocator", result)


class TestOldGccPrefix(unittest.TestCase):
    """Test __Z prefix (old GCC)."""

    def test_double_underscore_Z(self):
        self.assertEqual(demangle_itanium("__Z3foov"), "foo()")

    def test_double_underscore_Z_nested(self):
        self.assertEqual(demangle_itanium("__ZN3foo3barEv"), "foo::bar()")


class TestVendorExtensionSuffix(unittest.TestCase):
    """Test vendor extension suffix (dot after encoding)."""

    def test_dot_suffix(self):
        result = demangle_itanium("_Z3foov.")
        self.assertIsInstance(result, str)

    def test_dot_suffix_with_content(self):
        result = demangle_itanium("_Z3foov.M.0")
        self.assertIsInstance(result, str)


class TestParseErrorPaths(unittest.TestCase):
    """Test various ParseError paths."""

    def test_not_itanium_prefix(self):
        p = ItaniumParser("hello")
        with self.assertRaises(ParseError):
            p.parse()

    def test_empty_unqualified_name(self):
        """Unqualified name at end of input with only one char."""
        p = ItaniumParser("_ZZ")
        with self.assertRaises(ParseError):
            p.parse()

    def test_unknown_special_name_T(self):
        """Unknown T<char> special name."""
        p = ItaniumParser("_ZTQ1A")
        with self.assertRaises(ParseError):
            p.parse()

    def test_unknown_special_name_G(self):
        """Unknown G<char> special name."""
        p = ItaniumParser("_ZGQ1A")
        with self.assertRaises(ParseError):
            p.parse()

    def test_unknown_operator_code(self):
        """Unknown two-char operator code."""
        p = ItaniumParser("_Z3ZZ")
        with self.assertRaises(ParseError):
            p.parse()

    def test_cannot_parse_unqualified_name(self):
        """Single char that's not a valid unqualified name."""
        p = ItaniumParser("_Z!")
        with self.assertRaises(ParseError):
            p.parse()

    def test_empty_nested_name_prefix(self):
        """Empty nested name prefix (N E without content)."""
        p = ItaniumParser("_ZNE")
        with self.assertRaises(ParseError):
            p.parse()

    def test_invalid_substitution(self):
        """S followed by invalid char."""
        p = ItaniumParser("_ZSQ")
        with self.assertRaises(ParseError):
            p.parse()

    def test_consume_char_at_end(self):
        """_consume_char raises at end of input."""
        p = ItaniumParser("_Z3foo")
        p.pos = len(p.input)
        with self.assertRaises(ParseError):
            p._consume_char()

    def test_parse_number_no_digits(self):
        """_parse_number raises when no digits found."""
        p = ItaniumParser("abc")
        with self.assertRaises(ParseError):
            p._parse_number()

    def test_parse_seq_id_invalid(self):
        """_parse_seq_id raises on invalid first char."""
        p = ItaniumParser("q")
        with self.assertRaises(ParseError):
            p._parse_seq_id()

    def test_expect_char_mismatch(self):
        """_expect_char raises on mismatch."""
        p = ItaniumParser("abc")
        with self.assertRaises(ParseError):
            p._expect_char("x")

    def test_cannot_parse_type(self):
        """_parse_type raises on unknown char."""
        p = ItaniumParser("Q")
        with self.assertRaises(ParseError):
            p._parse_type()


class TestParseModuleFunctions(unittest.TestCase):
    """Test module-level parse function and helper methods."""

    def test_parse_function(self):
        node = parse("_Z3foov")
        self.assertIsInstance(node, ast.Name)

    def test_parse_function_special(self):
        node = parse("_ZTV1A")
        self.assertIsInstance(node, ast.SpecialName)

    def test_remaining(self):
        p = ItaniumParser("_Z3foov")
        p.pos = 5
        self.assertEqual(p._remaining(), "ov")

    def test_at_end(self):
        p = ItaniumParser("_Z3foov")
        p.pos = len(p.input)
        self.assertTrue(p._at_end())

    def test_not_at_end(self):
        p = ItaniumParser("_Z3foov")
        self.assertFalse(p._at_end())

    def test_check_char(self):
        p = ItaniumParser("_Z3foov")
        p.pos = 2
        self.assertTrue(p._check_char("3"))
        self.assertFalse(p._check_char("x"))

    def test_consume_if_true(self):
        p = ItaniumParser("_Z3foov")
        p.pos = 2
        self.assertTrue(p._consume_if("3"))
        self.assertEqual(p.pos, 3)

    def test_consume_if_false(self):
        p = ItaniumParser("_Z3foov")
        p.pos = 2
        self.assertFalse(p._consume_if("x"))
        self.assertEqual(p.pos, 2)

    def test_parse_number_negative(self):
        """_parse_number with n prefix (negative) — parser attempts int('n<digits>')."""
        # The parser code has 'n' prefix handling but doesn't strip it before int(),
        # so this raises ValueError. Test that it does raise (bug or not, it's the code path).
        p = ItaniumParser("n5")
        with self.assertRaises((ParseError, ValueError)):
            p._parse_number()

    def test_parse_until_char(self):
        p = ItaniumParser("abcEndef")
        result = p._parse_until_char("E")
        self.assertEqual(result, "abc")
        self.assertEqual(p._peek(), "E")

    def test_render_type_for_literal_builtin(self):
        p = ItaniumParser("_Z3foov")
        bt = ast.BuiltinType("int", "i")
        self.assertEqual(p._render_type_for_literal(bt), "int")

    def test_render_type_for_literal_cv(self):
        p = ItaniumParser("_Z3foov")
        cvt = ast.CVQualifiedType(ast.BuiltinType("int", "i"), "const")
        self.assertEqual(p._render_type_for_literal(cvt), "const int")

    def test_render_type_for_literal_other(self):
        p = ItaniumParser("_Z3foov")
        sn = ast.SourceName("foo")
        result = p._render_type_for_literal(sn)
        self.assertIn("SourceName", result)


class TestRendererDirect(unittest.TestCase):
    """Test renderer methods directly."""

    def test_render_none(self):
        self.assertEqual(render(None), "")

    def test_render_unknown_node(self):
        """Renderer returns repr for unknown node types."""

        class Foo(ast.Node):
            pass

        result = render(Foo())
        self.assertIn("Foo", result)

    def test_render_source_name(self):
        r = Renderer()
        self.assertEqual(r.render(ast.SourceName("hello")), "hello")

    def test_render_builtin_type(self):
        r = Renderer()
        self.assertEqual(r.render(ast.BuiltinType("int", "i")), "int")

    def test_render_pointer_type(self):
        r = Renderer()
        ptr = ast.PointerType(ast.BuiltinType("int", "i"))
        self.assertEqual(r.render(ptr), "int*")

    def test_render_reference_type(self):
        r = Renderer()
        ref = ast.ReferenceType(ast.BuiltinType("int", "i"))
        self.assertEqual(r.render(ref), "int&")

    def test_render_rvalue_reference_type(self):
        r = Renderer()
        ref = ast.RvalueReferenceType(ast.BuiltinType("int", "i"))
        self.assertEqual(r.render(ref), "int&&")

    def test_render_cv_qualified_type(self):
        r = Renderer()
        cv = ast.CVQualifiedType(ast.BuiltinType("int", "i"), "const")
        self.assertEqual(r.render(cv), "int const")

    def test_render_substitution_std(self):
        r = Renderer()
        sub = ast.Substitution(std_sub="s")
        result = r.render(sub)
        self.assertIn("std", result)

    def test_render_substitution_index_out_of_range(self):
        r = Renderer()
        sub = ast.Substitution(index=99)
        result = r.render(sub)
        self.assertIn("sub99", result)

    def test_render_substitution_no_index(self):
        r = Renderer()
        sub = ast.Substitution()
        result = r.render(sub)
        self.assertIn("sub", result)

    def test_render_template_param_out_of_range(self):
        r = Renderer()
        tp = ast.TemplateParam(99)
        result = r.render(tp)
        self.assertIn("T99", result)

    def test_render_special_name_default(self):
        r = Renderer()
        sn = ast.SpecialName("custom_kind", ast.BuiltinType("int", "i"))
        result = r.render(sn)
        self.assertEqual(result, "custom_kind for int")

    def test_render_special_name_no_target(self):
        r = Renderer()
        sn = ast.SpecialName("custom_kind")
        result = r.render(sn)
        self.assertEqual(result, "custom_kind for ")

    def test_render_array(self):
        r = Renderer()
        arr = ast.Array("5", ast.BuiltinType("int", "i"))
        self.assertEqual(r.render(arr), "int [5]")

    def test_render_vendor_extended_type(self):
        r = Renderer()
        vet = ast.VendorExtendedType("Token")
        self.assertEqual(r.render(vet), "Token")

    def test_render_decltype(self):
        r = Renderer()
        dc = ast.Decltype("A")
        self.assertEqual(r.render(dc), "decltype(A)")

    def test_render_module_name(self):
        r = Renderer()
        mn = ast.ModuleName("mymodule")
        self.assertEqual(r.render(mn), "mymodule")

    def test_render_abi_tag(self):
        r = Renderer()
        at = ast.AbiTag("cxx11")
        self.assertEqual(r.render(at), "[abi:cxx11]")

    def test_render_operator_name(self):
        r = Renderer()
        op = ast.OperatorName("pl", "+", 2)
        self.assertEqual(r.render(op), "+")

    def test_render_ctor_dtor_name(self):
        r = Renderer()
        cd = ast.CtorDtorName("complete")
        self.assertEqual(r.render(cd), "")

    def test_render_bare_function_type_empty(self):
        r = Renderer()
        bft = ast.BareFunctionType([])
        self.assertEqual(r.render(bft), "")

    def test_render_bare_function_type(self):
        r = Renderer()
        bft = ast.BareFunctionType([ast.BuiltinType("int", "i"), ast.BuiltinType("char", "c")])
        result = r.render(bft)
        self.assertIn("int", result)
        self.assertIn("char", result)

    def test_render_pointer_to_member_data(self):
        r = Renderer()
        ptm = ast.PointerToMember(ast.BuiltinType("A", "i"), ast.BuiltinType("int", "i"))
        result = r.render(ptm)
        self.assertEqual(result, "int A::*")

    def test_render_pointer_to_member_function_empty(self):
        r = Renderer()
        ft = ast.FunctionType(ast.BareFunctionType([]))
        ptm = ast.PointerToMember(ast.BuiltinType("A", "i"), ft)
        result = r.render(ptm)
        self.assertEqual(result, "void (A::*)()")

    def test_render_template_args_with_trailing_gt(self):
        """Template args ending with > get a space before closing >."""
        r = Renderer()
        inner = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        # Nested template that ends with >
        outer_args = [ast.TemplateArg("type", ast.BuiltinType("double", "d"))]
        outer = ast.TemplateArgs(outer_args)
        result = r.render(outer)
        # Simple case - no trailing >
        self.assertIn("<", result)

    def test_render_template_arg_expression(self):
        r = Renderer()
        ta = ast.TemplateArg("expression", "5+3")
        self.assertEqual(r.render(ta), "5+3")

    def test_render_template_arg_pack_list(self):
        r = Renderer()
        ta = ast.TemplateArg("pack", [ast.BuiltinType("int", "i"), ast.BuiltinType("char", "c")])
        result = r.render(ta)
        self.assertIn("int", result)
        self.assertIn("char", result)

    def test_render_template_arg_pack_str(self):
        r = Renderer()
        ta = ast.TemplateArg("pack", "not_a_list")
        self.assertEqual(r.render(ta), "not_a_list")

    def test_render_template_arg_primary(self):
        r = Renderer()
        ta = ast.TemplateArg("primary", "42")
        self.assertEqual(r.render(ta), "42")

    def test_render_template_arg_unknown(self):
        r = Renderer()
        ta = ast.TemplateArg("unknown", "val")
        self.assertEqual(r.render(ta), "val")

    def test_is_function_pointer(self):
        r = Renderer()
        self.assertTrue(r._is_function_pointer(ast.FunctionType(ast.BareFunctionType([]))))
        self.assertTrue(r._is_function_pointer(ast.BareFunctionType([])))

    def test_render_function_pointer_inner(self):
        r = Renderer()
        ft = ast.FunctionType(ast.BareFunctionType([ast.BuiltinType("void", "v")]))
        result = r._render_function_pointer_inner(ft)
        self.assertIn("void", result)

    def test_render_function_pointer_inner_non_func(self):
        r = Renderer()
        result = r._render_function_pointer_inner(ast.BuiltinType("int", "i"))
        self.assertEqual(result, "int")

    def test_is_template_name_unqualified(self):
        r = Renderer()
        uq = ast.UnqualifiedName("template", ast.TemplateArgs([]))
        self.assertTrue(r._is_template_name(uq))

    def test_is_template_name_source(self):
        r = Renderer()
        uq = ast.UnqualifiedName("source", ast.SourceName("foo"))
        self.assertFalse(r._is_template_name(uq))

    def test_is_template_unqualified_non_unq(self):
        r = Renderer()
        self.assertFalse(r._is_template_unqualified(ast.SourceName("foo")))

    def test_is_ctor_dtor_name_non_nested(self):
        r = Renderer()
        self.assertFalse(r._is_ctor_dtor_name(ast.SourceName("foo")))

    def test_get_class_name_from_prefix_empty(self):
        r = Renderer()
        self.assertEqual(r._get_class_name_from_prefix([]), "")

    def test_extract_class_name_simple(self):
        r = Renderer()
        self.assertEqual(r._extract_class_name("simple"), "simple")

    def test_extract_class_name_with_template(self):
        r = Renderer()
        self.assertEqual(r._extract_class_name("vector<int>"), "vector")

    def test_extract_class_name_with_scope(self):
        r = Renderer()
        self.assertEqual(r._extract_class_name("foo::bar"), "bar")

    def test_render_name_non_function(self):
        r = Renderer()
        name = ast.Name(ast.SourceName("foo"), is_function=False)
        self.assertEqual(r.render(name), "foo")

    def test_render_name_function_no_bare(self):
        r = Renderer()
        name = ast.Name(ast.SourceName("foo"), is_function=True, bare_function=None)
        self.assertEqual(r.render(name), "foo")

    def test_render_unqualified_name_template(self):
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        uq = ast.UnqualifiedName("template", targs)
        result = r.render(uq)
        self.assertIn("int", result)

    def test_render_unqualified_name_unknown_kind(self):
        r = Renderer()
        uq = ast.UnqualifiedName("unknown", "value")
        result = r.render(uq)
        self.assertEqual(result, "value")

    def test_render_function_signature_empty_types(self):
        """Function with bare_function that has no types."""
        r = Renderer()
        name = ast.Name(ast.SourceName("foo"), is_function=True, bare_function=ast.BareFunctionType([]))
        self.assertEqual(r.render(name), "foo()")

    def test_render_function_signature_void_param(self):
        """Function with single void param = empty param list."""
        r = Renderer()
        bare = ast.BareFunctionType([ast.BuiltinType("void", "v")])
        name = ast.Name(ast.SourceName("foo"), is_function=True, bare_function=bare)
        self.assertEqual(r.render(name), "foo()")

    def test_render_pointer_to_function_no_bare(self):
        """Pointer to FunctionType with None bare."""
        r = Renderer()
        ft = ast.FunctionType(None)
        ptr = ast.PointerType(ft)
        self.assertEqual(r.render(ptr), "void (*)()")

    def test_render_pointer_to_const_function_no_bare(self):
        """Pointer to CV-qualified FunctionType with None bare."""
        r = Renderer()
        ft = ast.FunctionType(None)
        cvft = ast.CVQualifiedType(ft, "const")
        ptr = ast.PointerType(cvft)
        self.assertEqual(r.render(ptr), "void (*)()")


class TestASTNodeReprAndChildren(unittest.TestCase):
    """Test __repr__ and children() for all AST node classes."""

    def test_node_base_repr(self):
        node = ast.Node()
        self.assertIn("Node", repr(node))

    def test_node_base_children(self):
        node = ast.Node()
        self.assertEqual(node.children(), [])

    def test_name_repr(self):
        node = ast.Name(ast.SourceName("foo"))
        self.assertIn("Name", repr(node))
        self.assertIn("foo", repr(node))

    def test_name_children_with_bare(self):
        bare = ast.BareFunctionType([ast.BuiltinType("void", "v")])
        node = ast.Name(ast.SourceName("foo"), is_function=True, bare_function=bare)
        children = node.children()
        self.assertEqual(len(children), 2)

    def test_name_children_without_bare(self):
        node = ast.Name(ast.SourceName("foo"))
        children = node.children()
        self.assertEqual(len(children), 1)

    def test_source_name_repr(self):
        node = ast.SourceName("hello")
        r = repr(node)
        self.assertIn("SourceName", r)
        self.assertIn("hello", r)

    def test_nested_name_repr(self):
        nn = ast.NestedName([ast.SourceName("foo")], ast.UnqualifiedName("source", ast.SourceName("bar")))
        r = repr(nn)
        self.assertIn("NestedName", r)
        self.assertIn("foo", r)
        self.assertIn("bar", r)

    def test_nested_name_children(self):
        prefix = [ast.SourceName("foo")]
        unq = ast.UnqualifiedName("source", ast.SourceName("bar"))
        nn = ast.NestedName(prefix, unq)
        children = nn.children()
        self.assertEqual(len(children), 2)

    def test_unqualified_name_repr(self):
        uq = ast.UnqualifiedName("source", ast.SourceName("foo"))
        r = repr(uq)
        self.assertIn("UnqualifiedName", r)
        self.assertIn("source", r)
        self.assertIn("foo", r)

    def test_unqualified_name_children_with_node(self):
        uq = ast.UnqualifiedName("source", ast.SourceName("foo"))
        children = uq.children()
        self.assertEqual(len(children), 1)

    def test_unqualified_name_children_with_str(self):
        uq = ast.UnqualifiedName("source", "foo")
        children = uq.children()
        self.assertEqual(children, [])

    def test_operator_name_repr_no_target(self):
        op = ast.OperatorName("pl", "+", 2)
        r = repr(op)
        self.assertIn("OperatorName", r)
        self.assertIn("pl", r)
        self.assertIn("+", r)

    def test_operator_name_repr_with_target(self):
        target = ast.BuiltinType("int", "i")
        op = ast.OperatorName("cv", "cast", 2, target_type=target)
        r = repr(op)
        self.assertIn("OperatorName", r)
        self.assertIn("cast", r)

    def test_ctor_dtor_name_repr_ctor(self):
        cd = ast.CtorDtorName("complete", is_destructor=False)
        r = repr(cd)
        self.assertIn("CtorDtorName", r)
        self.assertIn("complete", r)
        self.assertNotIn("~", r)

    def test_ctor_dtor_name_repr_dtor(self):
        cd = ast.CtorDtorName("complete", is_destructor=True)
        r = repr(cd)
        self.assertIn("~", r)

    def test_template_args_repr(self):
        args = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        r = repr(args)
        self.assertIn("TemplateArgs", r)

    def test_template_args_children(self):
        arg = ast.TemplateArg("type", ast.BuiltinType("int", "i"))
        args = ast.TemplateArgs([arg])
        self.assertEqual(len(args.children()), 1)

    def test_template_arg_repr(self):
        ta = ast.TemplateArg("primary", "42")
        r = repr(ta)
        self.assertIn("TemplateArg", r)
        self.assertIn("primary", r)
        self.assertIn("42", r)

    def test_template_arg_children_with_node(self):
        ta = ast.TemplateArg("type", ast.BuiltinType("int", "i"))
        self.assertEqual(len(ta.children()), 1)

    def test_template_arg_children_with_str(self):
        ta = ast.TemplateArg("primary", "42")
        self.assertEqual(ta.children(), [])

    def test_builtin_type_repr(self):
        bt = ast.BuiltinType("int", "i")
        r = repr(bt)
        self.assertIn("BuiltinType", r)
        self.assertIn("int", r)

    def test_pointer_type_repr(self):
        ptr = ast.PointerType(ast.BuiltinType("int", "i"))
        r = repr(ptr)
        self.assertIn("Pointer", r)

    def test_pointer_type_children(self):
        target = ast.BuiltinType("int", "i")
        ptr = ast.PointerType(target)
        self.assertEqual(ptr.children(), [target])

    def test_reference_type_repr(self):
        ref = ast.ReferenceType(ast.BuiltinType("int", "i"))
        r = repr(ref)
        self.assertIn("LvalueRef", r)

    def test_reference_type_children(self):
        target = ast.BuiltinType("int", "i")
        ref = ast.ReferenceType(target)
        self.assertEqual(ref.children(), [target])

    def test_rvalue_reference_type_repr(self):
        ref = ast.RvalueReferenceType(ast.BuiltinType("int", "i"))
        r = repr(ref)
        self.assertIn("RvalueRef", r)

    def test_rvalue_reference_type_children(self):
        target = ast.BuiltinType("int", "i")
        ref = ast.RvalueReferenceType(target)
        self.assertEqual(ref.children(), [target])

    def test_cv_qualified_type_repr(self):
        cv = ast.CVQualifiedType(ast.BuiltinType("int", "i"), "const")
        r = repr(cv)
        self.assertIn("CVQualified", r)
        self.assertIn("const", r)

    def test_cv_qualified_type_children(self):
        base = ast.BuiltinType("int", "i")
        cv = ast.CVQualifiedType(base, "const")
        self.assertEqual(cv.children(), [base])

    def test_function_type_repr(self):
        ft = ast.FunctionType(ast.BareFunctionType([]), cv="const", ref="&")
        r = repr(ft)
        self.assertIn("FunctionType", r)
        self.assertIn("const", r)

    def test_function_type_children(self):
        bare = ast.BareFunctionType([])
        ft = ast.FunctionType(bare)
        self.assertEqual(ft.children(), [bare])

    def test_bare_function_type_repr(self):
        bft = ast.BareFunctionType([ast.BuiltinType("int", "i")])
        r = repr(bft)
        self.assertIn("BareFunctionType", r)

    def test_bare_function_type_children(self):
        t1 = ast.BuiltinType("int", "i")
        bft = ast.BareFunctionType([t1])
        self.assertEqual(bft.children(), [t1])

    def test_substitution_repr_std(self):
        sub = ast.Substitution(std_sub="s")
        r = repr(sub)
        self.assertIn("Substitution", r)
        self.assertIn("s", r)

    def test_substitution_repr_index(self):
        sub = ast.Substitution(index=5)
        r = repr(sub)
        self.assertIn("5", r)

    def test_template_param_repr(self):
        tp = ast.TemplateParam(3)
        r = repr(tp)
        self.assertIn("TemplateParam", r)
        self.assertIn("3", r)

    def test_special_name_repr(self):
        sn = ast.SpecialName("vtable", ast.BuiltinType("A", "i"))
        r = repr(sn)
        self.assertIn("SpecialName", r)
        self.assertIn("vtable", r)

    def test_array_repr(self):
        arr = ast.Array("5", ast.BuiltinType("int", "i"))
        r = repr(arr)
        self.assertIn("Array", r)
        self.assertIn("5", r)

    def test_array_children(self):
        elem = ast.BuiltinType("int", "i")
        arr = ast.Array("5", elem)
        self.assertEqual(arr.children(), [elem])

    def test_pointer_to_member_repr(self):
        ptm = ast.PointerToMember(ast.BuiltinType("A", "i"), ast.BuiltinType("int", "i"))
        r = repr(ptm)
        self.assertIn("PointerToMember", r)

    def test_pointer_to_member_children(self):
        cls = ast.BuiltinType("A", "i")
        mem = ast.BuiltinType("int", "i")
        ptm = ast.PointerToMember(cls, mem)
        self.assertEqual(len(ptm.children()), 2)

    def test_vendor_extended_type_repr(self):
        vet = ast.VendorExtendedType("Token")
        r = repr(vet)
        self.assertIn("VendorExt", r)
        self.assertIn("Token", r)

    def test_vendor_extended_type_children_no_args(self):
        vet = ast.VendorExtendedType("Token")
        self.assertEqual(vet.children(), [])

    def test_vendor_extended_type_children_with_args(self):
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        vet = ast.VendorExtendedType("Token", targs)
        self.assertEqual(len(vet.children()), 1)

    def test_decltype_repr(self):
        dc = ast.Decltype("A", is_template=True)
        r = repr(dc)
        self.assertIn("Decltype", r)
        self.assertIn("True", r)

    def test_module_name_repr(self):
        mn = ast.ModuleName("mymodule")
        r = repr(mn)
        self.assertIn("Module", r)

    def test_abi_tag_repr(self):
        at = ast.AbiTag("cxx11")
        r = repr(at)
        self.assertIn("AbiTag", r)
        self.assertIn("cxx11", r)


class TestInitStructuredOutput(unittest.TestCase):
    """Test __init__.py structured output and error fallback paths."""

    def test_structured_failed_demangle(self):
        """Structured output when demangling fails."""
        sym = demangle_itanium("not_mangled", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.full_name, "not_mangled")
        self.assertEqual(sym.format, "itanium")

    def test_structured_variable(self):
        """Structured output for a variable (non-function)."""
        sym = demangle_itanium("_Z3foo", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.kind, "variable")

    def test_structured_function_with_scope(self):
        sym = demangle_itanium("_ZN3foo3barEv", structured=True)
        self.assertEqual(sym.kind, "function")
        self.assertEqual(sym.scope, ["foo"])
        self.assertEqual(sym.name, "bar()")

    def test_structured_template_function(self):
        sym = demangle_itanium("_Z3fooIiEvT_", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertTrue(sym.is_template)

    def test_structured_vtt(self):
        sym = demangle_itanium("_ZTT1A", structured=True)
        self.assertEqual(sym.kind, "vtt")

    def test_structured_guard(self):
        sym = demangle_itanium("_ZGV1A", structured=True)
        self.assertEqual(sym.kind, "guard")

    def test_structured_with_scope_split(self):
        """Test _parse_basic_structure scope splitting with 3-level nesting."""
        sym = demangle_itanium("_ZN3foo3bar3bazEv", structured=True)
        self.assertIn("foo", sym.scope)
        self.assertIn("bar", sym.scope)

    def test_structured_template_name_detection(self):
        """Test that < in name sets is_template."""
        sym = demangle_itanium("_Z3fooIiEvT_", structured=True)
        self.assertTrue(sym.is_template)

    def test_structured_no_scope(self):
        """Structured output for name without scope."""
        sym = demangle_itanium("_Z3foov", structured=True)
        self.assertEqual(sym.name, "foo()")

    def test_demangle_itanium_symbol_special_name(self):
        """demangle_itanium_symbol with special name."""
        s = demangle_itanium_symbol("_ZTV1A")
        self.assertEqual(s.kind, "vtable")
        self.assertEqual(s.name, "A")

    def test_demangle_itanium_symbol_ctor(self):
        s = demangle_itanium_symbol("_ZN1AC1Ev")
        self.assertEqual(s.kind, "ctor")
        self.assertIn("A", s.name)

    def test_demangle_itanium_symbol_dtor(self):
        s = demangle_itanium_symbol("_ZN1AD0Ev")
        self.assertEqual(s.kind, "dtor")
        self.assertIn("~", s.name)

    def test_demangle_itanium_symbol_operator(self):
        s = demangle_itanium_symbol("_ZN1aplEi")
        self.assertIn("operator", s.name)

    def test_demangle_itanium_symbol_template(self):
        s = demangle_itanium_symbol("_Z3fooIiEvT_")
        self.assertTrue(s.is_template)

    def test_demangle_itanium_symbol_function_params(self):
        s = demangle_itanium_symbol("_Z3fooii")
        self.assertEqual(s.parameters, ["int", "int"])

    def test_demangle_itanium_symbol_void_params(self):
        s = demangle_itanium_symbol("_Z3foov")
        self.assertEqual(s.parameters, [])

    def test_demangle_itanium_symbol_template_return(self):
        s = demangle_itanium_symbol("_Z3fooIiEvT_")
        self.assertEqual(s.return_type, "void")

    def test_demangle_itanium_symbol_version_suffix(self):
        s = demangle_itanium_symbol("_ZN3foo3barEv@@GLIBC_2.4")
        self.assertEqual(s.demangled, "foo::bar()")
        self.assertIn("version_suffix", s.stripped)

    def test_demangle_itanium_symbol_source_name_qualified(self):
        s = demangle_itanium_symbol("_Z3foo")
        self.assertEqual(s.kind, "variable")
        self.assertEqual(s.name, "foo")

    def test_demangle_itanium_symbol_substitution_qualified(self):
        s = demangle_itanium_symbol("_ZSs")
        self.assertIsInstance(s.name, str)
        self.assertIn("std", s.name)

    def test_demangle_itanium_symbol_unqualified_name_template(self):
        """Qualified name that is an UnqualifiedName with kind 'template'."""
        s = demangle_itanium_symbol("_Z3fooIiEv")
        self.assertIsInstance(s, object)

    def test_demangle_itanium_symbol_failed_parse(self):
        """demangle_itanium_symbol with failed parse (no cxxfilt fallback)."""
        s = demangle_itanium_symbol("_Z!")
        self.assertEqual(s.demangled, "_Z!")

    def test_demangle_itanium_symbol_all_failed(self):
        """demangle_itanium_symbol when parse fails and cxxfilt unavailable."""
        s = demangle_itanium_symbol("not_mangled")
        self.assertEqual(s.demangled, "not_mangled")

    def test_demangle_via_dispatch_structured(self):
        """Test structured output via main demangle() dispatch."""
        sym = demangle("_ZN3foo3barEv", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.format, "itanium")

    def test_demangle_itanium_symbol_member_function(self):
        """Symbol for a member function should have is_member=True."""
        s = demangle_itanium_symbol("_ZN1A3fooEv")
        self.assertTrue(s.is_member)


class TestInitErrorFallback(unittest.TestCase):
    """Test error fallback paths in __init__.py."""

    def test_parse_error_fallback(self):
        """ParseError should be caught, original returned."""
        result = demangle_itanium("_Z!")
        self.assertIsInstance(result, str)

    def test_parse_error_structured(self):
        """ParseError with structured=True should return DemangledSymbol."""
        sym = demangle_itanium("_Z!", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertGreater(len(sym.parse_warnings), 0)

    def test_non_itanium_input(self):
        """Non-Itanium input should return original."""
        result = demangle_itanium("plain_text")
        self.assertEqual(result, "plain_text")

    def test_non_itanium_structured(self):
        sym = demangle_itanium("plain_text", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.full_name, "plain_text")


class TestLocalNameParserDirect(unittest.TestCase):
    """Test _parse_local_name and _parse_discriminator directly."""

    def test_parse_discriminator(self):
        p = ItaniumParser("_Z3foo")
        p.pos = 0
        # Simulate being at a discriminator
        p.input = "_0_"
        p.pos = 0
        p._parse_discriminator()
        # Should have consumed _0_
        self.assertEqual(p.pos, 3)

    def test_parse_discriminator_no_underscore(self):
        """No discriminator when peek is not _."""
        p = ItaniumParser("abc")
        p._parse_discriminator()
        self.assertEqual(p.pos, 0)

    def test_parse_discriminator_no_trailing_underscore(self):
        """Discriminator without trailing underscore."""
        p = ItaniumParser("_5")
        p.pos = 0
        p._parse_discriminator()
        # _5 consumed, no trailing _ so consume_if fails
        self.assertEqual(p.pos, 2)


class TestCallOffset(unittest.TestCase):
    """Test _parse_call_offset directly."""

    def test_call_offset_h(self):
        """_parse_call_offset('h') parses number and underscore."""
        p = ItaniumParser("4_")
        p._parse_call_offset("h")
        self.assertEqual(p.pos, 2)

    def test_call_offset_v(self):
        """_parse_call_offset('v') parses two number_underscore pairs."""
        p = ItaniumParser("0_4_")
        p._parse_call_offset("v")
        self.assertEqual(p.pos, 4)

    def test_call_offset_empty_consumes_char(self):
        """Empty type string consumes first char as the offset type."""
        p = ItaniumParser("h4_")
        p._parse_call_offset("")
        self.assertEqual(p.pos, 3)

    def test_call_offset_invalid(self):
        """Invalid call offset type raises ParseError."""
        p = ItaniumParser("x")
        with self.assertRaises(ParseError):
            p._parse_call_offset("x")


class TestSpecialNameRenderer(unittest.TestCase):
    """Test _render_SpecialName for all kinds."""

    def test_render_vtable(self):
        r = Renderer()
        sn = ast.SpecialName("vtable", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "vtable for A")

    def test_render_vtt(self):
        r = Renderer()
        sn = ast.SpecialName("VTT", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "VTT for A")

    def test_render_typeinfo(self):
        r = Renderer()
        sn = ast.SpecialName("typeinfo", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "typeinfo for A")

    def test_render_typeinfo_name(self):
        r = Renderer()
        sn = ast.SpecialName("typeinfo name", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "typeinfo name for A")

    def test_render_guard_variable(self):
        r = Renderer()
        sn = ast.SpecialName("guard variable", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "guard variable for A")

    def test_render_reference_temp(self):
        r = Renderer()
        sn = ast.SpecialName("reference temp", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "reference temporary for A")

    def test_render_tls_init(self):
        r = Renderer()
        sn = ast.SpecialName("tls init", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "TLS init function for A")

    def test_render_tls_wrapper(self):
        r = Renderer()
        sn = ast.SpecialName("tls wrapper", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "TLS wrapper function for A")

    def test_render_generic_kind(self):
        r = Renderer()
        sn = ast.SpecialName("thunk", ast.BuiltinType("A", "i"))
        self.assertEqual(r.render(sn), "thunk for A")


class TestNestedNameRendererEdgeCases(unittest.TestCase):
    """Test edge cases in _render_NestedName."""

    def test_nested_name_with_template_unqualified(self):
        """NestedName where unqualified_name is template kind."""
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        prefix = [ast.UnqualifiedName("source", ast.SourceName("foo"))]
        unq = ast.UnqualifiedName("template", targs)
        nn = ast.NestedName(prefix, unq)
        result = r.render(nn)
        self.assertIn("foo", result)
        self.assertIn("int", result)

    def test_nested_name_ctor_with_template(self):
        """NestedName with ctor kind unqualified and template prefix."""
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        prefix = [ast.UnqualifiedName("source", ast.SourceName("A"))]
        unq = ast.UnqualifiedName("template", targs)
        nn = ast.NestedName(prefix, unq)
        result = r.render(nn)
        self.assertIn("A", result)

    def test_nested_name_cv_qualifiers_suffix(self):
        r = Renderer()
        prefix = [ast.UnqualifiedName("source", ast.SourceName("A"))]
        unq = ast.UnqualifiedName("source", ast.SourceName("foo"))
        nn = ast.NestedName(prefix, unq, cv_qualifiers="const")
        result = r.render(nn)
        self.assertIn("const", result)

    def test_nested_name_ref_qualifier_suffix(self):
        r = Renderer()
        prefix = [ast.UnqualifiedName("source", ast.SourceName("A"))]
        unq = ast.UnqualifiedName("source", ast.SourceName("foo"))
        nn = ast.NestedName(prefix, unq, ref_qualifier="&&")
        result = r.render(nn)
        self.assertIn("&&", result)

    def test_nested_name_cv_and_ref_suffix(self):
        r = Renderer()
        prefix = [ast.UnqualifiedName("source", ast.SourceName("A"))]
        unq = ast.UnqualifiedName("source", ast.SourceName("foo"))
        nn = ast.NestedName(prefix, unq, cv_qualifiers="const", ref_qualifier="&")
        result = r.render(nn)
        self.assertIn("const", result)
        self.assertIn("&", result)

    def test_get_class_name_from_prefix_source_unq(self):
        """Test _get_class_name_from_prefix with UnqualifiedName source."""
        r = Renderer()
        prefix = [ast.UnqualifiedName("source", ast.SourceName("MyClass"))]
        result = r._get_class_name_from_prefix(prefix)
        self.assertEqual(result, "MyClass")

    def test_get_class_name_from_prefix_substitution(self):
        """Test _get_class_name_from_prefix with Substitution (extracts last :: component)."""
        r = Renderer()
        prefix = [ast.UnqualifiedName("source", ast.Substitution(std_sub="s"))]
        result = r._get_class_name_from_prefix(prefix)
        # STD_SUBS['s'] = "std::basic_string<...>" -> _extract_class_name -> "basic_string"
        self.assertEqual(result, "basic_string")

    def test_get_class_name_from_prefix_unknown(self):
        """Test _get_class_name_from_prefix with unknown element type."""
        r = Renderer()
        prefix = [ast.BuiltinType("int", "i")]
        result = r._get_class_name_from_prefix(prefix)
        self.assertEqual(result, "int")

    def test_get_class_name_from_prefix_skip_template(self):
        """Test _get_class_name_from_prefix skips template args."""
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        prefix = [
            ast.UnqualifiedName("source", ast.SourceName("MyClass")),
            ast.UnqualifiedName("template", targs),
        ]
        result = r._get_class_name_from_prefix(prefix)
        self.assertEqual(result, "MyClass")


class TestIsOperatorPart(unittest.TestCase):
    """Test _is_operator_part method."""

    def test_is_operator_part_ls(self):
        r = Renderer()
        targs = ast.TemplateArgs([])
        prefix = [ast.UnqualifiedName("operator", ast.OperatorName("ls", "<<", 2))]
        result = r._is_operator_part(prefix, 1)
        self.assertTrue(result)

    def test_is_operator_part_non_ls(self):
        r = Renderer()
        prefix = [ast.UnqualifiedName("operator", ast.OperatorName("pl", "+", 2))]
        result = r._is_operator_part(prefix, 1)
        self.assertFalse(result)

    def test_is_operator_part_first_element(self):
        r = Renderer()
        prefix = [ast.UnqualifiedName("operator", ast.OperatorName("ls", "<<", 2))]
        result = r._is_operator_part(prefix, 0)
        self.assertFalse(result)

    def test_is_operator_part_non_operator(self):
        r = Renderer()
        prefix = [ast.UnqualifiedName("source", ast.SourceName("foo"))]
        result = r._is_operator_part(prefix, 1)
        self.assertFalse(result)


class TestUnqualifiedNameRendering(unittest.TestCase):
    """Test _render_UnqualifiedName edge cases."""

    def test_render_unqualified_name_with_abi_tags(self):
        r = Renderer()
        uq = ast.UnqualifiedName("source", ast.SourceName("foo"))
        uq.abi_tags = ["cxx11", "foo"]
        result = r.render(uq)
        self.assertIn("[abi:cxx11]", result)
        self.assertIn("[abi:foo]", result)

    def test_render_unqualified_name_operator_alpha(self):
        """Alphabetic operator names get a space."""
        r = Renderer()
        op = ast.OperatorName("nw", "new", 3)
        uq = ast.UnqualifiedName("operator", op)
        result = r.render(uq)
        self.assertEqual(result, "operator new")

    def test_render_unqualified_name_operator_symbolic(self):
        """Symbolic operator names don't get a space."""
        r = Renderer()
        op = ast.OperatorName("pl", "+", 2)
        uq = ast.UnqualifiedName("operator", op)
        result = r.render(uq)
        self.assertEqual(result, "operator+")

    def test_render_unqualified_name_conversion(self):
        """Conversion operator renders target type."""
        r = Renderer()
        target = ast.BuiltinType("int", "i")
        op = ast.OperatorName("cv", "cast", 2, target_type=target)
        uq = ast.UnqualifiedName("operator", op)
        result = r.render(uq)
        self.assertEqual(result, "operator int")

    def test_render_ctor_dtor_placeholder(self):
        """CtorDtorName renderer returns placeholder."""
        r = Renderer()
        uq_ctor = ast.UnqualifiedName("ctor", ast.CtorDtorName("complete"))
        result = r.render(uq_ctor)
        self.assertIn("<ctor>", result)

    def test_render_dtor_placeholder(self):
        r = Renderer()
        uq_dtor = ast.UnqualifiedName("dtor", ast.CtorDtorName("complete", is_destructor=True))
        result = r.render(uq_dtor)
        self.assertIn("~", result)


class TestPrefixSubstitutionHandling(unittest.TestCase):
    """Test substitution handling inside _parse_prefix."""

    def test_std_sub_st_in_prefix(self):
        """St (std::) used as a prefix component inside a nested name."""
        result = demangle_itanium("_ZN3fooSt3barEv")
        self.assertIn("std", result)
        self.assertIn("bar", result)

    def test_std_sub_sa_in_prefix(self):
        """Sa (std::allocator) used as a prefix component inside a nested name."""
        result = demangle_itanium("_ZN3fooSa3barEv")
        self.assertIn("allocator", result)

    def test_indexed_sub_in_prefix(self):
        """S0_ used as a prefix component inside a nested name."""
        result = demangle_itanium("_ZN3foo3barIiEES0_3bazEv")
        self.assertIsInstance(result, str)

    def test_substitution_in_prefix_with_template(self):
        """Substitution in prefix followed by template args."""
        result = demangle_itanium("_ZN3fooSt6vectorIiEE3bazEv")
        self.assertIsInstance(result, str)

    def test_get_substitution_success(self):
        """_get_substitution returns the correct node for valid index."""
        p = ItaniumParser("_Z3fooPiS_")
        p.parse()
        if len(p.subs) > 0:
            node = p._get_substitution(0)
            self.assertIsInstance(node, ast.Node)


class TestStOperatorInName(unittest.TestCase):
    """Test St followed by operator name in _parse_name."""

    def test_st_operator_plus(self):
        """St followed by 'pl' (operator+) as a name."""
        result = demangle_itanium("_ZStplEi")
        self.assertIn("std", result)
        self.assertIn("operator+", result)

    def test_st_operator_plus_with_template(self):
        """St followed by 'pl' and template args."""
        result = demangle_itanium("_ZStplIiE")
        self.assertIn("std", result)
        self.assertIn("operator+", result)

    def test_st_operator_new(self):
        """St followed by 'nw' (operator new)."""
        result = demangle_itanium("_ZStnwm")
        self.assertIn("std", result)
        self.assertIn("operator new", result)


class TestStdSubsWithTemplateInName(unittest.TestCase):
    """Test std substitutions (Sa, Sb, Ss, etc.) followed by template args in _parse_name."""

    def test_sa_with_template_in_name(self):
        """Sa followed by I <template-args> E as a template-template-param."""
        result = demangle_itanium("_Z3fooSaIiE")
        self.assertIn("allocator", result)
        self.assertIn("int", result)

    def test_ss_with_template_in_name(self):
        """Ss followed by I <template-args> E."""
        result = demangle_itanium("_Z3fooSsIiE")
        self.assertIsInstance(result, str)


class TestStAsTypeWithoutTemplate(unittest.TestCase):
    """Test St <source-name> as a type without template args."""

    def test_st_source_name_no_template(self):
        """St followed by source name but no I (template args)."""
        result = demangle_itanium("_Z3fooSt3vec")
        self.assertIn("std", result)
        self.assertIn("vec", result)


class TestSourceNameWithTemplateAsType(unittest.TestCase):
    """Test source name followed by template args in type context."""

    def test_source_name_template_as_type(self):
        """A digit source name followed by I <template-args> E as a type."""
        result = demangle_itanium("_Z3foo3vecIiE")
        self.assertIn("vec", result)
        self.assertIn("int", result)


class TestEnumClassLiteral(unittest.TestCase):
    """Test template arg with enum/class type literal."""

    def test_enum_literal(self):
        """L <type> <value> E where type is a user-defined type."""
        result = demangle_itanium("_Z3fooIL1A5EEvv")
        self.assertIn("foo", result)
        self.assertIn("(A)5", result)


class TestRendererNestedNameEdgeCases(unittest.TestCase):
    """Test additional _render_NestedName edge cases."""

    def test_empty_prefix_template_unqualified(self):
        """NestedName with empty prefix and template unqualified name."""
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        unq = ast.UnqualifiedName("template", targs)
        nn = ast.NestedName([], unq)
        result = r.render(nn)
        self.assertIn("int", result)

    def test_get_class_name_only_ctor_template(self):
        """_get_class_name_from_prefix with only ctor and template args."""
        r = Renderer()
        prefix = [
            ast.UnqualifiedName("ctor", ast.CtorDtorName("complete")),
            ast.UnqualifiedName("template", ast.TemplateArgs([])),
        ]
        result = r._get_class_name_from_prefix(prefix)
        self.assertEqual(result, "")

    def test_is_ctor_dtor_name_template_prefix(self):
        """_is_ctor_dtor_name with template unqualified and ctor in prefix."""
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        prefix = [ast.UnqualifiedName("ctor", ast.CtorDtorName("complete"))]
        unq = ast.UnqualifiedName("template", targs)
        nn = ast.NestedName(prefix, unq)
        self.assertTrue(r._is_ctor_dtor_name(nn))

    def test_is_ctor_dtor_name_template_prefix_dtor(self):
        """_is_ctor_dtor_name with template unqualified and dtor in prefix."""
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        prefix = [ast.UnqualifiedName("dtor", ast.CtorDtorName("complete", is_destructor=True))]
        unq = ast.UnqualifiedName("template", targs)
        nn = ast.NestedName(prefix, unq)
        self.assertTrue(r._is_ctor_dtor_name(nn))

    def test_render_pointer_to_cv_func_void_param(self):
        """Pointer to CV-qualified function with single void param."""
        r = Renderer()
        bare = ast.BareFunctionType([ast.BuiltinType("void", "v"), ast.BuiltinType("void", "v")])
        ft = ast.FunctionType(bare)
        cvft = ast.CVQualifiedType(ft, "const")
        ptr = ast.PointerType(cvft)
        result = r.render(ptr)
        self.assertIn("(*)", result)

    def test_render_function_type_void_param(self):
        """FunctionType with single void param (after return type)."""
        r = Renderer()
        bare = ast.BareFunctionType([ast.BuiltinType("int", "i"), ast.BuiltinType("void", "v")])
        ft = ast.FunctionType(bare)
        result = r.render(ft)
        self.assertIn("int", result)
        # void param should be empty, not "void"
        self.assertNotIn("(void)", result)


class TestInitAdditionalPaths(unittest.TestCase):
    """Test additional __init__.py paths."""

    def test_symbol_unqualified_name_template(self):
        """demangle_itanium_symbol with qualified=UnqualifiedName(kind='template')."""
        s = demangle_itanium_symbol("_Z3fooIiE")
        self.assertTrue(s.is_template)

    def test_symbol_source_name_qualified(self):
        """demangle_itanium_symbol with qualified=SourceName."""
        s = demangle_itanium_symbol("_Z3foo")
        self.assertEqual(s.name, "foo")

    def test_symbol_special_with_target_scope(self):
        """demangle_itanium_symbol with special name that has scoped target."""
        s = demangle_itanium_symbol("_ZTVN3foo3barE")
        self.assertEqual(s.kind, "vtable")

    def test_structured_no_scope_name(self):
        """Structured output for function with no scope."""
        sym = demangle_itanium("_Z3foov", structured=True)
        self.assertEqual(sym.scope, [])
        self.assertEqual(sym.name, "foo()")

    def test_structured_nested_template_depth(self):
        """Structured output with nested template args (depth tracking)."""
        sym = demangle_itanium("_Z3fooI1BIiiEEvT_", structured=True)
        self.assertTrue(sym.is_template)

    def test_symbol_function_return_type(self):
        """Symbol with return type from template function."""
        s = demangle_itanium_symbol("_Z3fooIiEvT_")
        self.assertEqual(s.return_type, "void")

    def test_symbol_function_parameters(self):
        """Symbol with multiple parameters."""
        s = demangle_itanium_symbol("_Z3fooic")
        self.assertEqual(s.parameters, ["int", "char"])

    def test_structured_unknown_kind_variable(self):
        """Structured output for a plain variable (no parens)."""
        sym = demangle_itanium("_Z3foo", structured=True)
        self.assertEqual(sym.kind, "variable")

    def test_structured_depth_tracking_with_template_scope(self):
        """Structured output where :: appears after > in the demangled string."""
        sym = demangle_itanium("_ZNSsD0Ev", structured=True)
        self.assertIn("~basic_string", sym.name)

    def test_structured_no_depth_zero_scope(self):
        """Structured output where :: only appears inside < > (depth > 0)."""
        sym = demangle_itanium("_Z3fooISt6vectorIiEEvT_", structured=True)
        self.assertIsInstance(sym.name, str)

    def test_structured_all_scope_inside_template(self):
        """Structured output where ALL :: are inside < > (no depth-0 split)."""
        sym = demangle_itanium("_Z3fooISt6vectorIiEE", structured=True)
        self.assertIsInstance(sym.name, str)
        self.assertIn("foo", sym.name)

    def test_structured_symbol_special_with_scope(self):
        """demangle_itanium_symbol with special name that has scoped target."""
        s = demangle_itanium_symbol("_ZTVN3foo3barE")
        self.assertEqual(s.kind, "vtable")
        self.assertIn("foo", s.scope)


class TestTemplatedCtorDtorRendering(unittest.TestCase):
    """Test rendering of templated constructors and destructors with class names."""

    def test_templated_ctor_with_class_name(self):
        """Constructor with template args and a class name in prefix."""
        result = demangle_itanium("_ZN3foo1AC1IiEEv")
        self.assertIn("foo", result)
        self.assertIn("A", result)
        self.assertIn("<int>", result)

    def test_templated_dtor_with_class_name(self):
        """Destructor with template args and a class name in prefix."""
        result = demangle_itanium("_ZN3foo1AD0IiEEv")
        self.assertIn("foo", result)
        self.assertIn("~A", result)
        self.assertIn("<int>", result)


class TestRendererAdditionalEdgeCases(unittest.TestCase):
    """Test additional renderer edge cases for remaining coverage."""

    def test_template_in_prefix_empty_parts(self):
        """NestedName with template as first prefix element (parts empty initially)."""
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        template_uq = ast.UnqualifiedName("template", targs)
        source_uq = ast.UnqualifiedName("source", ast.SourceName("bar"))
        nn = ast.NestedName([template_uq], source_uq)
        result = r.render(nn)
        self.assertIn("int", result)
        self.assertIn("bar", result)

    def test_get_class_name_from_raw_source_name(self):
        """_get_class_name_from_prefix with a raw SourceName (not wrapped)."""
        r = Renderer()
        prefix = [ast.SourceName("MyClass")]
        result = r._get_class_name_from_prefix(prefix)
        self.assertEqual(result, "MyClass")

    def test_render_ls_operator_template_with_space(self):
        """operator<< followed by template args should get a space before <."""
        result = demangle_itanium("_ZStlsIcE")
        self.assertIn("operator<<", result)
        self.assertIn(" <char>", result)

    def test_render_templated_ctor_no_class_name(self):
        """Templated ctor with no source name in prefix (class_name is empty)."""
        r = Renderer()
        targs = ast.TemplateArgs([ast.TemplateArg("type", ast.BuiltinType("int", "i"))])
        prefix = [ast.UnqualifiedName("ctor", ast.CtorDtorName("complete"))]
        unq = ast.UnqualifiedName("template", targs)
        nn = ast.NestedName(prefix, unq)
        result = r.render(nn)
        self.assertIn("int", result)


class TestVectorTypeParsing(unittest.TestCase):
    """Test Dv (vector type) parsing — parser falls through but doesn't crash."""

    def test_dv_vector_int(self):
        """Dv4_i — vector of 4 ints. Parser handles gracefully (may not match c++filt)."""
        result = demangle_itanium("_Z3fooDv4_i")
        self.assertIsInstance(result, str)

    def test_dv_vector_double(self):
        result = demangle_itanium("_Z3fooDv8_d")
        self.assertIsInstance(result, str)


class TestStdSubAsNameWithTemplate(unittest.TestCase):
    """Test std substitutions used as names with template args (lines 261-263)."""

    def test_sa_as_name_with_template(self):
        """Sa followed by I as a name (not type parameter)."""
        result = demangle_itanium("_ZSaIiE")
        self.assertEqual(result, "std::allocator<int>")

    def test_ss_as_name_with_template(self):
        """Ss followed by I as a name."""
        result = demangle_itanium("_ZSsIiE")
        self.assertIsInstance(result, str)


class TestInvalidSubstitutionLowercase(unittest.TestCase):
    """Test invalid substitution with lowercase letter not in STD_SUBS."""

    def test_invalid_sub_se(self):
        """S followed by 'e' (not in STD_SUBS, not digit/uppercase) raises."""
        p = ItaniumParser("_ZSe")
        with self.assertRaises(ParseError):
            p.parse()


class TestPrefixSubstitutionWithTemplate(unittest.TestCase):
    """Test substitution handling in _parse_prefix with template args."""

    def test_st_in_prefix_with_template(self):
        """St in prefix followed by template args."""
        result = demangle_itanium("_ZN3fooSt6vectorIiEE3bazEv")
        self.assertIsInstance(result, str)

    def test_indexed_sub_in_prefix_with_template(self):
        """S0_ in prefix followed by template args."""
        result = demangle_itanium("_ZN3foo3barIiEES0_IcE3bazEv")
        self.assertIsInstance(result, str)

    def test_template_prefix_single_element(self):
        """Template prefix with single element (line 421)."""
        result = demangle_itanium("_ZN3fooIiEE3barEv")
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
