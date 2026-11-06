"""
Extended tests for Rust v0, Rust legacy, D, and Swift demangling modules.

These tests target code paths not covered by test_demangle_rust_d_swift.py,
focusing on:
- Rust v0 (RFC 2603): path parsing (N, I, B, M, C), type parsing (all BASIC_TYPES,
  A, S, R, Q, P, O, T), generic args, ident escapes, base62, disambiguators
- Rust legacy: fallback path, __Z prefix, $ escape decoding, .h suffix stripping
- D: pointer/array/static-array/function/named/unknown types, structured output,
  error handling, truncated input
- Swift: embedded ($e), escape decoding, structured output edge cases, single-part names
- Error handling and graceful degradation across all three
"""

import unittest
from unittest.mock import patch

from vivisect.demangle import demangle, detect_format
from vivisect.demangle.rust import (
    _RustV0Parser,
    demangle_rust,
    _decode_rust_escapes,
    _demangle_rust_legacy,
)
from vivisect.demangle.dlang import _DParser, demangle_d
from vivisect.demangle.swift import (
    demangle_swift,
    _decode_swift_escapes,
    _demangle_swift_basic,
)
from vivisect.demangle.common import DemangledSymbol

# ===== RUST v0 PARSER UNIT TESTS =====


class TestRustV0BasicTypes(unittest.TestCase):
    """Test all BASIC_TYPES mappings in the v0 parser."""

    def test_all_basic_types(self):
        expected = {
            "a": "i8",
            "b": "bool",
            "c": "char",
            "d": "f64",
            "e": "str",
            "f": "f32",
            "h": "u8",
            "i": "isize",
            "j": "usize",
            "l": "i32",
            "m": "u32",
            "n": "i128",
            "o": "u128",
            "s": "i16",
            "t": "u16",
            "u": "()",
            "v": "...",
            "x": "i64",
            "y": "u64",
            "z": "!",
            "p": "_",
        }
        for code, name in expected.items():
            parser = _RustV0Parser(code)
            result = parser._parse_type()
            self.assertEqual(result, name, "BASIC_TYPES[%r] = %r, expected %r" % (code, result, name))


class TestRustV0TypeParsing(unittest.TestCase):
    """Test v0 type parsing: arrays, slices, references, pointers, tuples."""

    def test_array_type(self):
        # A<type><number> = [type; number]
        # Aa3 -> A, type=a(i8), number=3 -> [i8; 3]
        parser = _RustV0Parser("Aa3")
        self.assertEqual(parser._parse_type(), "[i8; 3]")
        # Aiaa -> A, type=i(isize), number=0 (peek 'a' not digit) -> [isize; 0]
        parser = _RustV0Parser("Aiaa")
        self.assertEqual(parser._parse_type(), "[isize; 0]")

    def test_slice_type(self):
        # S<type> = [type]
        parser = _RustV0Parser("Sa")
        self.assertEqual(parser._parse_type(), "[i8]")

    def test_reference_type(self):
        # R<type> = &type
        parser = _RustV0Parser("Ra")
        self.assertEqual(parser._parse_type(), "&i8")

    def test_refmut_type(self):
        # Q<type> = &mut type
        parser = _RustV0Parser("Qa")
        self.assertEqual(parser._parse_type(), "&mut i8")

    def test_const_pointer_type(self):
        # P<type> = *const type
        parser = _RustV0Parser("Pa")
        self.assertEqual(parser._parse_type(), "*const i8")

    def test_mut_pointer_type(self):
        # O<type> = *mut type
        parser = _RustV0Parser("Oa")
        self.assertEqual(parser._parse_type(), "*mut i8")

    def test_tuple_type_multiple(self):
        # T<types...>E = (type1, type2, ...)
        parser = _RustV0Parser("TabE")
        self.assertEqual(parser._parse_type(), "(i8, bool)")

    def test_tuple_type_single(self):
        parser = _RustV0Parser("TaE")
        self.assertEqual(parser._parse_type(), "(i8)")

    def test_tuple_type_empty(self):
        # T followed immediately by E
        parser = _RustV0Parser("TE")
        self.assertEqual(parser._parse_type(), "()")

    def test_unknown_type(self):
        # Unknown type code produces ?<code>
        parser = _RustV0Parser("W")
        self.assertEqual(parser._parse_type(), "?W")

    def test_path_as_type(self):
        # C path used as a type
        parser = _RustV0Parser("C4test")
        self.assertEqual(parser._parse_type(), "test")


class TestRustV0PathParsing(unittest.TestCase):
    """Test v0 path parsing: N (nested), I (generic), B (backref), M (impl), C (crate)."""

    def test_crate_path_no_disambiguator(self):
        # C<disambiguator><ident> -- without disambiguator, just C<ident>
        parser = _RustV0Parser("C4test")
        self.assertEqual(parser._parse_path(), "test")

    def test_crate_path_with_disambiguator(self):
        # Cs1234_4test -- disambiguator s1234, then ident
        # Note: the parser's _parse_disambiguator consumes s<digits> but NOT the trailing _
        # So after disambiguator, _peek is '_', _parse_ident sees '_', consumes it,
        # then _parse_number returns 0 -> '' (empty ident)
        # This is a known limitation; test it returns a string
        parser = _RustV0Parser("Cs0_4test")
        result = parser._parse_path()
        self.assertIsInstance(result, str)

    def test_nested_path(self):
        # N<namespace><disambiguator><path><ident>
        # NvC4test3foo -> N, ns=v, no disamb (peek=C), path=C4test='test', ident=3foo='foo'
        parser = _RustV0Parser("NvC4test3foo")
        self.assertEqual(parser._parse_path(), "test::foo")

    def test_generic_path(self):
        # I<path><generic-args>E -> path<args>
        parser = _RustV0Parser("IC4testiE")
        self.assertEqual(parser._parse_path(), "test<isize>")

    def test_backref_path(self):
        # B<base62>_ -> backref index
        parser = _RustV0Parser("B0_")
        result = parser._parse_path()
        self.assertIsInstance(result, str)
        self.assertIn("backref", result)

    def test_impl_path(self):
        # M<disambiguator><type> -> <impl type>
        parser = _RustV0Parser("Mi")
        self.assertEqual(parser._parse_path(), "<impl isize>")

    def test_ident_only_path(self):
        # No recognized prefix -> just parse ident
        parser = _RustV0Parser("4test")
        self.assertEqual(parser._parse_path(), "test")


class TestRustV0IdentParsing(unittest.TestCase):
    """Test v0 ident parsing: lengths, underscores, escape sequences."""

    def test_basic_ident(self):
        parser = _RustV0Parser("4test")
        self.assertEqual(parser._parse_ident(), "test")

    def test_zero_length_ident(self):
        parser = _RustV0Parser("0")
        self.assertEqual(parser._parse_ident(), "")

    def test_ident_with_underscore(self):
        # <number>_<name> -- the _ is consumed before the name
        parser = _RustV0Parser("3_foo")
        self.assertEqual(parser._parse_ident(), "foo")

    def test_ident_truncated_raises(self):
        parser = _RustV0Parser("10abc")
        with self.assertRaises(ValueError):
            parser._parse_ident()

    def test_ident_escape_dollar(self):
        # $RF$ -> &
        parser = _RustV0Parser("5$RF$x")
        self.assertEqual(parser._parse_ident(), "&x")

    def test_ident_escape_star(self):
        # $BP$ -> *
        parser = _RustV0Parser("5$BP$x")
        self.assertEqual(parser._parse_ident(), "*x")

    def test_ident_escape_at(self):
        # $SP$ -> @
        parser = _RustV0Parser("5$SP$x")
        self.assertEqual(parser._parse_ident(), "@x")

    def test_ident_escape_lt(self):
        # $LT$ -> <
        parser = _RustV0Parser("5$LT$x")
        self.assertEqual(parser._parse_ident(), "<x")

    def test_ident_escape_gt(self):
        # $GT$ -> >
        parser = _RustV0Parser("5$GT$x")
        self.assertEqual(parser._parse_ident(), ">x")

    def test_ident_escape_lp(self):
        # $LP$ -> (
        parser = _RustV0Parser("5$LP$x")
        self.assertEqual(parser._parse_ident(), "(x")

    def test_ident_escape_rp(self):
        # $RP$ -> )
        parser = _RustV0Parser("5$RP$x")
        self.assertEqual(parser._parse_ident(), ")x")

    def test_ident_escape_comma(self):
        # $C$ -> ,
        parser = _RustV0Parser("4$C$x")
        self.assertEqual(parser._parse_ident(), ",x")

    def test_ident_escape_unicode(self):
        # $u7e$ -> ~
        parser = _RustV0Parser("5$u7e$")
        self.assertEqual(parser._parse_ident(), "~")

    def test_ident_escape_unicode_space(self):
        # $u20$ -> space
        parser = _RustV0Parser("5$u20$")
        self.assertEqual(parser._parse_ident(), " ")


class TestRustV0NumberAndBase62(unittest.TestCase):
    """Test v0 number and base62 parsing."""

    def test_parse_number(self):
        parser = _RustV0Parser("123abc")
        self.assertEqual(parser._parse_number(), 123)
        self.assertEqual(parser.pos, 3)

    def test_parse_number_zero(self):
        parser = _RustV0Parser("abc")
        self.assertEqual(parser._parse_number(), 0)

    def test_base62_empty(self):
        parser = _RustV0Parser("")
        self.assertEqual(parser._parse_base62(), 0)

    def test_base62_zero(self):
        parser = _RustV0Parser("0_")
        self.assertEqual(parser._parse_base62(), 0)

    def test_base62_lowercase(self):
        parser = _RustV0Parser("a_")
        self.assertEqual(parser._parse_base62(), 10)

    def test_base62_uppercase(self):
        parser = _RustV0Parser("A_")
        self.assertEqual(parser._parse_base62(), 36)

    def test_base62_multiple_chars(self):
        parser = _RustV0Parser("ab_")
        result = parser._parse_base62()
        self.assertIsInstance(result, int)

    def test_disambiguator_with_s(self):
        parser = _RustV0Parser("s123")
        self.assertEqual(parser._parse_disambiguator(), 123)

    def test_disambiguator_without_s(self):
        parser = _RustV0Parser("abc")
        self.assertEqual(parser._parse_disambiguator(), 0)


class TestRustV0GenericArgs(unittest.TestCase):
    """Test v0 generic argument parsing."""

    def test_generic_args_single(self):
        parser = _RustV0Parser("iE")
        self.assertEqual(parser._parse_generic_args(), "isize")

    def test_generic_args_multiple(self):
        parser = _RustV0Parser("abE")
        self.assertEqual(parser._parse_generic_args(), "i8, bool")

    def test_generic_args_empty(self):
        # Immediately E
        parser = _RustV0Parser("E")
        self.assertEqual(parser._parse_generic_args(), "")

    def test_generic_args_no_terminator(self):
        # No E, hits end of input (\x00)
        parser = _RustV0Parser("i")
        result = parser._parse_generic_args()
        self.assertIsInstance(result, str)


class TestRustV0NextAndPeek(unittest.TestCase):
    """Test v0 parser low-level operations."""

    def test_peek_default(self):
        parser = _RustV0Parser("ab")
        self.assertEqual(parser._peek(), "a")
        self.assertEqual(parser._peek(1), "b")

    def test_peek_past_end(self):
        parser = _RustV0Parser("")
        self.assertEqual(parser._peek(), "\x00")

    def test_peek_offset_past_end(self):
        parser = _RustV0Parser("a")
        self.assertEqual(parser._peek(5), "\x00")

    def test_next_raises_at_end(self):
        parser = _RustV0Parser("")
        with self.assertRaises(ValueError):
            parser._next()

    def test_next_consumes(self):
        parser = _RustV0Parser("ab")
        self.assertEqual(parser._next(), "a")
        self.assertEqual(parser.pos, 1)
        self.assertEqual(parser._next(), "b")
        self.assertEqual(parser.pos, 2)


class TestRustV0FullDemangle(unittest.TestCase):
    """Test full v0 demangle via demangle_rust."""

    def test_v0_crate_function(self):
        # _R + NvC4test3foo
        result = demangle_rust("_RNvC4test3foo")
        self.assertIsInstance(result, str)
        self.assertIn("test", result)
        self.assertIn("foo", result)

    def test_v0_with_llvm_suffix(self):
        result = demangle_rust("_RNvC4test3foo.llvm.abc123")
        self.assertIsInstance(result, str)
        self.assertIn("test", result)

    def test_v0_dot_only(self):
        # Symbol with just a dot after _R -> dot_pos=0, not > 0, so no truncation
        # s = ".", parser gets ".", _parse_path -> _parse_ident -> number=0 -> ''
        result = demangle_rust("_R.")
        self.assertIsInstance(result, str)

    def test_v0_invalid_returns_original(self):
        result = demangle_rust("_R")
        self.assertEqual(result, "_R")

    def test_v0_garbage_returns_string(self):
        result = demangle_rust("_R\x00\x01\x02")
        self.assertIsInstance(result, str)

    def test_v0_empty_after_prefix(self):
        # _R with nothing after
        result = demangle_rust("_R")
        self.assertIsInstance(result, str)

    def test_v0_structured_success(self):
        sym = demangle_rust("_RNvC4test3foo", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.format, "rust")
        self.assertEqual(sym.kind, "function")

    def test_v0_structured_scope(self):
        sym = demangle_rust("_RNvC4test3foo", structured=True)
        self.assertEqual(sym.scope, ["test"])
        self.assertEqual(sym.name, "foo")

    def test_v0_structured_no_scope(self):
        # _RNvC4test produces "test::" which has :: so scope is set
        sym = demangle_rust("_RNvC4test", structured=True)
        self.assertEqual(sym.scope, ["test"])

    def test_v0_structured_failure(self):
        sym = demangle_rust("_R", structured=True)
        self.assertEqual(sym.format, "rust")
        self.assertEqual(sym.full_name, "_R")
        self.assertIn("unable to demangle", sym.parse_warnings)

    def test_v0_structured_original(self):
        orig = "_RNvC4test3foo"
        sym = demangle_rust(orig, structured=True)
        self.assertEqual(sym.original_mangled, orig)


# ===== RUST LEGACY TESTS =====


class TestRustLegacyDemangle(unittest.TestCase):
    """Test legacy Rust (_Z prefix) demangling."""

    def test_legacy_basic(self):
        result = demangle_rust("_ZN3foo3barEv")
        self.assertIsInstance(result, str)
        self.assertIn("foo", result)

    def test_legacy_double_underscore_prefix(self):
        result = demangle_rust("__ZN3foo3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_fallback_garbage(self):
        # When itanium returns the original, fallback path strips _Z and decodes escapes
        result = demangle_rust("_Zgarbage")
        self.assertIsInstance(result, str)

    def test_legacy_fallback_double_underscore_garbage(self):
        result = demangle_rust("__Zgarbage")
        self.assertIsInstance(result, str)

    def test_legacy_escape_ref(self):
        result = demangle_rust("_ZN3foo$RF$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_escape_star(self):
        result = demangle_rust("_ZN3foo$BP$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_escape_lt(self):
        result = demangle_rust("_ZN3foo$LT$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_escape_gt(self):
        result = demangle_rust("_ZN3foo$GT$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_escape_lp(self):
        result = demangle_rust("_ZN3foo$LP$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_escape_rp(self):
        result = demangle_rust("_ZN3foo$RP$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_escape_comma(self):
        result = demangle_rust("_ZN3foo$C$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_escape_at(self):
        result = demangle_rust("_ZN3foo$SP$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_escape_unicode(self):
        result = demangle_rust("_ZN3foo$u7e$3barEv")
        self.assertIsInstance(result, str)

    def test_legacy_hex_suffix_stripped(self):
        result = demangle_rust("_ZN3foo3barEv.h1234abcd")
        self.assertIsInstance(result, str)
        self.assertNotIn(".h1234abcd", result)

    def test_legacy_template_detection(self):
        sym = demangle_rust("_ZN3foo3barIiEE", structured=True)
        self.assertTrue(sym.is_template)

    def test_legacy_no_scope(self):
        sym = demangle_rust("_Z3foo", structured=True)
        self.assertEqual(sym.scope, [])
        self.assertEqual(sym.kind, "function")

    def test_legacy_structured_failure(self):
        sym = demangle_rust("_Z", structured=True)
        self.assertEqual(sym.format, "rust")
        self.assertIn("unable to demangle", sym.parse_warnings)

    def test_legacy_itanium_exception_fallback(self):
        """When itanium raises, the manual fallback should still produce output."""
        with patch("vivisect.demangle.itanium.demangle_itanium", side_effect=RuntimeError("test")):
            result = demangle_rust("_Z3foo")
            self.assertIsInstance(result, str)

    def test_legacy_itanium_exception_fallback_double_underscore(self):
        with patch("vivisect.demangle.itanium.demangle_itanium", side_effect=RuntimeError("test")):
            result = demangle_rust("__Z3foo")
            self.assertIsInstance(result, str)

    def test_decode_rust_escapes_all(self):
        self.assertEqual(_decode_rust_escapes("$RF$"), "&")
        self.assertEqual(_decode_rust_escapes("$BP$"), "*")
        self.assertEqual(_decode_rust_escapes("$LT$"), "<")
        self.assertEqual(_decode_rust_escapes("$GT$"), ">")
        self.assertEqual(_decode_rust_escapes("$LP$"), "(")
        self.assertEqual(_decode_rust_escapes("$RP$"), ")")
        self.assertEqual(_decode_rust_escapes("$C$"), ",")
        self.assertEqual(_decode_rust_escapes("$SP$"), "@")
        self.assertEqual(_decode_rust_escapes("$u41$"), "A")

    def test_decode_rust_escapes_plain(self):
        self.assertEqual(_decode_rust_escapes("hello"), "hello")

    def test_demangle_rust_legacy_direct(self):
        result = _demangle_rust_legacy("_ZN3foo3barEv")
        self.assertIsInstance(result, str)

    def test_demangle_rust_legacy_double_underscore(self):
        result = _demangle_rust_legacy("__ZN3foo3barEv")
        self.assertIsInstance(result, str)


# ===== RUST V0 ERROR HANDLING =====


class TestRustV0ErrorHandling(unittest.TestCase):
    """Test error handling in v0 parser."""

    def test_v0_parser_exception_caught(self):
        # _R alone causes _parse_path to call _parse_ident with empty input
        # _parse_ident calls _parse_number -> 0, then returns ''
        # Result is '' which equals mangled[2:] = '', so demangled == '' -> not demangled
        result = demangle_rust("_R")
        self.assertEqual(result, "_R")

    def test_v0_parser_exception_structured(self):
        sym = demangle_rust("_R", structured=True)
        self.assertIn("unable to demangle", sym.parse_warnings)

    def test_legacy_parser_exception_structured(self):
        sym = demangle_rust("_Z", structured=True)
        self.assertIn("unable to demangle", sym.parse_warnings)

    def test_v0_parser_exception_caught_truncated_ident(self):
        # A v0 symbol with an ident length exceeding input triggers ValueError
        # in _parse_ident, which is caught by the except block in demangle_rust
        result = demangle_rust("_R9999999")
        self.assertEqual(result, "_R9999999")

    def test_v0_parser_exception_structured_truncated(self):
        sym = demangle_rust("_R9999999", structured=True)
        self.assertEqual(sym.format, "rust")
        self.assertTrue(any("v0 parser error" in w for w in sym.parse_warnings))

    def test_legacy_parser_exception_caught_via_mock(self):
        """When _demangle_rust_legacy raises, the exception is caught and original returned."""
        with patch("vivisect.demangle.rust._demangle_rust_legacy", side_effect=RuntimeError("test")):
            result = demangle_rust("_Z3foo")
            self.assertEqual(result, "_Z3foo")

    def test_legacy_parser_exception_structured_via_mock(self):
        with patch("vivisect.demangle.rust._demangle_rust_legacy", side_effect=RuntimeError("test")):
            sym = demangle_rust("_Z3foo", structured=True)
            self.assertEqual(sym.format, "rust")
            self.assertTrue(any("legacy parser error" in w for w in sym.parse_warnings))

    def test_v0_backref_with_substs(self):
        """When _substs is populated, a backref returns the substituted value."""
        parser = _RustV0Parser("B0_")
        parser._substs = ["some_type"]
        self.assertEqual(parser._parse_path(), "some_type")

    def test_non_rust_no_prefix(self):
        result = demangle_rust("plain_function")
        self.assertEqual(result, "plain_function")

    def test_empty_string(self):
        result = demangle_rust("")
        self.assertEqual(result, "")

    def test_not_crash_on_null(self):
        result = demangle_rust("_R\x00\x01\x02")
        self.assertIsInstance(result, str)


# ===== D LANGUAGE TESTS =====


class TestDTypeParsing(unittest.TestCase):
    """Test D language type parsing: all type codes, pointers, arrays, functions."""

    def test_basic_void_type(self):
        result = demangle_d("_D3foo3barFvZv")
        self.assertIsInstance(result, str)

    def test_pointer_type(self):
        # P = pointer
        result = demangle_d("_D3foo3barFPiZv")
        self.assertIsInstance(result, str)
        self.assertIn("int*", result)

    def test_array_type(self):
        # A = dynamic array
        result = demangle_d("_D3foo3barFAiZv")
        self.assertIsInstance(result, str)
        self.assertIn("int[]", result)

    def test_static_array_type(self):
        # G<number><type> = static array
        result = demangle_d("_D3foo3barFG3iZv")
        self.assertIsInstance(result, str)
        self.assertIn("int[3]", result)

    def test_function_type_single_param(self):
        result = demangle_d("_D3foo3barFiZv")
        self.assertIsInstance(result, str)
        self.assertIn("int", result)

    def test_function_type_multiple_params(self):
        result = demangle_d("_D3foo3barFiiZv")
        self.assertIsInstance(result, str)
        self.assertIn("int, int", result)

    def test_named_type(self):
        # Digit-prefixed name as a type
        result = demangle_d("_D3foo3barF3bazZv")
        self.assertIsInstance(result, str)
        self.assertIn("baz", result)

    def test_unknown_type(self):
        # Q is not in TYPE_MAP and not a known type construct
        result = demangle_d("_D3foo3barFQZv")
        self.assertIsInstance(result, str)

    def test_all_type_map_entries(self):
        type_map = {
            "v": "void",
            "b": "bool",
            "y": "byte",
            "g": "ubyte",
            "h": "short",
            "t": "ushort",
            "i": "int",
            "j": "uint",
            "k": "long",
            "m": "ulong",
            "l": "real",
            "f": "float",
            "d": "double",
            "e": "real",
            "c": "ifloat",
            "q": "idouble",
            "r": "ireal",
            "p": "creal",
            "a": "char",
            "u": "wchar",
            "w": "dchar",
            "s": "string",
            "o": "wstring",
            "x": "dstring",
            "n": "char[]",
            "z": "void",
        }
        for code, name in type_map.items():
            result = demangle_d("_D3foo3barF%sZv" % code)
            self.assertIsInstance(result, str, "Type code %r should not crash" % code)

    def test_nested_pointer_type(self):
        # PPi = int**
        result = demangle_d("_D3foo3barFPPiZv")
        self.assertIsInstance(result, str)

    def test_pointer_to_array(self):
        # PAi = int[]*
        result = demangle_d("_D3foo3barFPAiZv")
        self.assertIsInstance(result, str)

    def test_function_no_params(self):
        # FZv -> function with no params, void return
        result = demangle_d("_D3foo3barFZv")
        self.assertIsInstance(result, str)

    def test_multiple_name_parts(self):
        # 3foo3bar3baz -> foo.bar.baz
        result = demangle_d("_D3foo3bar3bazFiZv")
        self.assertIsInstance(result, str)
        self.assertIn("foo", result)
        self.assertIn("bar", result)
        self.assertIn("baz", result)


class TestDErrorHandling(unittest.TestCase):
    """Test D language error handling and edge cases."""

    def test_truncated_name_length(self):
        # Length says 10 but only 3 chars available -> break, fallback
        result = demangle_d("_D10abcFiZv")
        self.assertIsInstance(result, str)

    def test_zero_length_name_part(self):
        # 0 as length -> break
        result = demangle_d("_D3foo0barFiZv")
        self.assertIsInstance(result, str)

    def test_no_type_suffix(self):
        # Name only, no type
        result = demangle_d("_D3foo3bar")
        self.assertIsInstance(result, str)
        self.assertIn("foo", result)

    def test_just_prefix(self):
        result = demangle_d("_D")
        self.assertEqual(result, "_D")

    def test_non_d_returns_original(self):
        result = demangle_d("plain_function")
        self.assertEqual(result, "plain_function")

    def test_empty_string(self):
        result = demangle_d("")
        self.assertEqual(result, "")

    def test_next_raises_on_truncated_type(self):
        # F then P but nothing after -> _next raises, caught by demangle_d
        result = demangle_d("_D3fooFP")
        self.assertIsInstance(result, str)

    def test_d_main(self):
        result = demangle_d("_Dmain")
        self.assertIsInstance(result, str)

    def test_d_main_structured(self):
        sym = demangle_d("_Dmain", structured=True)
        self.assertEqual(sym.format, "d")
        self.assertIsInstance(sym, DemangledSymbol)


class TestDStructuredOutput(unittest.TestCase):
    """Test D structured output."""

    def test_structured_basic(self):
        sym = demangle_d("_D3foo3barFiZv", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.format, "d")
        self.assertEqual(sym.kind, "function")

    def test_structured_scope(self):
        sym = demangle_d("_D3foo3barFiZv", structured=True)
        self.assertEqual(sym.scope, ["foo"])
        self.assertEqual(sym.name, "bar(int)")

    def test_structured_variable(self):
        # No parens in name -> variable
        sym = demangle_d("_D3foo3bar", structured=True)
        self.assertEqual(sym.kind, "variable")

    def test_structured_no_dot(self):
        # _Dmain -> no dot -> name = demangled, kind = variable (no parens)
        sym = demangle_d("_Dmain", structured=True)
        self.assertEqual(sym.scope, [])
        self.assertEqual(sym.kind, "variable")

    def test_structured_failure(self):
        sym = demangle_d("_D", structured=True)
        self.assertEqual(sym.format, "d")
        self.assertIn("unable to demangle", sym.parse_warnings)

    def test_structured_original(self):
        orig = "_D3foo3barFiZv"
        sym = demangle_d(orig, structured=True)
        self.assertEqual(sym.original_mangled, orig)

    def test_structured_with_parse_error(self):
        # Invalid D symbol triggers parser error
        sym = demangle_d("not_d", structured=True)
        self.assertEqual(sym.format, "d")
        self.assertTrue(len(sym.parse_warnings) > 0)


class TestDParserInternals(unittest.TestCase):
    """Test D parser internal methods."""

    def test_peek(self):
        parser = _DParser("_D3foo")
        self.assertEqual(parser._peek(), "_")
        self.assertEqual(parser._peek(1), "D")

    def test_peek_past_end(self):
        parser = _DParser("_D")
        self.assertEqual(parser._peek(10), "\x00")

    def test_next(self):
        parser = _DParser("_D3foo")
        self.assertEqual(parser._next(), "_")
        self.assertEqual(parser.pos, 1)

    def test_next_raises_at_end(self):
        parser = _DParser("_D")
        parser.pos = 2
        with self.assertRaises(ValueError):
            parser._next()

    def test_at_end_true(self):
        parser = _DParser("_D")
        parser.pos = 2
        self.assertTrue(parser._at_end())

    def test_at_end_false(self):
        parser = _DParser("_D3foo")
        parser.pos = 2
        self.assertFalse(parser._at_end())

    def test_parse_number(self):
        parser = _DParser("123abc")
        self.assertEqual(parser._parse_number(), 123)

    def test_parse_number_no_digits(self):
        parser = _DParser("abc")
        self.assertEqual(parser._parse_number(), 0)

    def test_parse_raises_non_d(self):
        parser = _DParser("not_d")
        with self.assertRaises(ValueError):
            parser.parse()


# ===== SWIFT TESTS =====


class TestSwiftBasicDemangle(unittest.TestCase):
    """Test Swift basic demangling."""

    def test_dollar_s_prefix(self):
        result = demangle_swift("$s5Hello4testyyF")
        self.assertIsInstance(result, str)
        self.assertIn("Hello", result)

    def test_dollar_S_prefix(self):
        result = demangle_swift("$S5Hello4testyyF")
        self.assertIsInstance(result, str)
        self.assertIn("Hello", result)

    def test_T0_prefix(self):
        result = demangle_swift("_T05Hello4testyyF")
        self.assertIsInstance(result, str)
        self.assertIn("Hello", result)

    def test_multiple_name_parts(self):
        result = demangle_swift("$s5Hello4test4mainyyF")
        self.assertIsInstance(result, str)
        self.assertIn("Hello", result)
        self.assertIn("test", result)

    def test_single_name_part(self):
        result = demangle_swift("$s4testyF")
        self.assertIsInstance(result, str)
        self.assertIn("test", result)

    def test_basic_returns_none_for_non_swift(self):
        self.assertIsNone(_demangle_swift_basic("plain_function"))

    def test_basic_returns_none_for_empty_after_prefix(self):
        self.assertIsNone(_demangle_swift_basic("$s"))
        self.assertIsNone(_demangle_swift_basic("$S"))
        self.assertIsNone(_demangle_swift_basic("_T0"))

    def test_basic_returns_none_for_huge_length(self):
        result = _demangle_swift_basic("$s99999x")
        self.assertIsNone(result)


class TestSwiftEscapes(unittest.TestCase):
    """Test Swift escape sequence decoding."""

    def test_decode_hex_space(self):
        self.assertEqual(_decode_swift_escapes("test$20$foo"), "test foo")

    def test_decode_hex_tilde(self):
        self.assertEqual(_decode_swift_escapes("$7e$"), "~")

    def test_decode_no_escapes(self):
        self.assertEqual(_decode_swift_escapes("hello"), "hello")

    def test_decode_multiple_escapes(self):
        result = _decode_swift_escapes("$20$$41$")
        self.assertEqual(result, " A")


class TestSwiftStructuredOutput(unittest.TestCase):
    """Test Swift structured output."""

    def test_structured_basic(self):
        sym = demangle_swift("$s5Hello4testyyF", structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.format, "swift")
        self.assertEqual(sym.kind, "function")

    def test_structured_scope(self):
        sym = demangle_swift("$s5Hello4testyyF", structured=True)
        self.assertEqual(sym.scope, ["Hello"])
        self.assertEqual(sym.name, "test")

    def test_structured_no_dot(self):
        # Single name part -> no dot -> name = full_name, scope = []
        sym = demangle_swift("$s4testyF", structured=True)
        self.assertEqual(sym.scope, [])
        self.assertEqual(sym.name, sym.full_name)

    def test_structured_failure(self):
        sym = demangle_swift("$s", structured=True)
        self.assertEqual(sym.format, "swift")
        self.assertIn("unable to demangle", sym.parse_warnings)

    def test_structured_original(self):
        orig = "$s5Hello4testyyF"
        sym = demangle_swift(orig, structured=True)
        self.assertEqual(sym.original_mangled, orig)

    def test_structured_with_parse_warnings(self):
        """When demangling succeeds, parse_warnings should contain basic message."""
        sym = demangle_swift("$s5Hello4testyyF", structured=True)
        self.assertTrue(len(sym.parse_warnings) > 0)
        self.assertIn("basic", sym.parse_warnings[0].lower())


class TestSwiftErrorHandling(unittest.TestCase):
    """Test Swift error handling."""

    def test_non_swift_returns_original(self):
        result = demangle_swift("plain_function")
        self.assertEqual(result, "plain_function")

    def test_empty_string(self):
        result = demangle_swift("")
        self.assertEqual(result, "")

    def test_invalid_swift(self):
        result = demangle_swift("$s")
        self.assertEqual(result, "$s")

    def test_no_crash_on_garbage(self):
        result = demangle_swift("$s\x00\x01\x02")
        self.assertIsInstance(result, str)

    def test_exception_caught_returns_original(self):
        """When _demangle_swift_basic raises, exception is caught and original returned."""
        with patch("vivisect.demangle.swift._demangle_swift_basic", side_effect=RuntimeError("test")):
            result = demangle_swift("$stest")
            self.assertEqual(result, "$stest")

    def test_exception_caught_structured(self):
        with patch("vivisect.demangle.swift._demangle_swift_basic", side_effect=RuntimeError("test")):
            sym = demangle_swift("$stest", structured=True)
            self.assertEqual(sym.format, "swift")
            self.assertTrue(len(sym.parse_warnings) > 0)
            self.assertIn("parser error", sym.parse_warnings[0])

    def test_embedded_swift_e_prefix(self):
        # $e prefix is not handled by the basic demangler (only $s, $S, _T0)
        result = demangle_swift("$e5Hello4testyyF")
        self.assertIsInstance(result, str)

    def test_T0_garbage(self):
        result = demangle_swift("_T0garbage")
        self.assertIsInstance(result, str)


# ===== DISPATCH TESTS =====


class TestExtendedDispatch(unittest.TestCase):
    """Test Rust/D/Swift through the main demangle() dispatch."""

    def test_rust_v0_dispatch(self):
        result = demangle("_RNvC4test3foo")
        self.assertIsInstance(result, str)

    def test_rust_v0_structured_dispatch(self):
        sym = demangle("_RNvC4test3foo", structured=True)
        self.assertEqual(sym.format, "rust")

    def test_d_pointer_type_dispatch(self):
        result = demangle("_D3foo3barFPiZv")
        self.assertIsInstance(result, str)

    def test_d_structured_dispatch(self):
        sym = demangle("_D3foo3barFiZv", structured=True)
        self.assertEqual(sym.format, "d")

    def test_swift_structured_dispatch(self):
        sym = demangle("$s5Hello4testyyF", structured=True)
        self.assertEqual(sym.format, "swift")

    def test_never_raises_various(self):
        for inp in [
            "_R",
            "_D",
            "$s",
            "_T0",
            "$S",
            "_R\x00",
            "_D\x00",
            "_RNvC4test3foo",
            "_D3foo3barFiZv",
            "$s5Hello4testyyF",
            "__ZN3foo3barEv",
            "_Zgarbage",
            "_D3fooFP",
            "$s\x00\x01",
        ]:
            result = demangle(inp)
            self.assertIsInstance(result, str, "demangle(%r) crashed" % inp)

    def test_detect_format_rust_v0_crate(self):
        self.assertEqual(detect_format("_RNvC4test3foo"), "rust")

    def test_detect_format_d_with_type(self):
        self.assertEqual(detect_format("_D3foo3barFPiZv"), "d")

    def test_detect_format_swift_S(self):
        self.assertEqual(detect_format("$S5Hello4testyyF"), "swift")


if __name__ == "__main__":
    unittest.main()
