"""
Tests for the MSVC C++ demangling module.

Tests cover:
- Simple functions (non-member)
- Member functions (virtual, static, public, private, protected)
- Constructors and destructors
- vtable symbols
- Variables (global and static)
- Primitive types (int, double, char, unsigned int, long, etc.)
- Pointer and reference types
- User-defined types (struct, class, enum, union)
- Namespace and nested class scope
- Operators (new, delete)
"""

import unittest

from vivisect.demangle import demangle, detect_format
from vivisect.demangle.msvc import demangle_msvc
from vivisect.demangle.common import DemangledSymbol


class TestMSVCDispatch(unittest.TestCase):
    """Test MSVC format detection and dispatch."""

    def test_detect_msvc(self):
        self.assertEqual(detect_format('?foo@@YAXH@Z'), 'msvc')

    def test_detect_vtable(self):
        self.assertEqual(detect_format('??_7MyClass@@6B@'), 'msvc')

    def test_detect_constructor(self):
        self.assertEqual(detect_format('??0MyClass@@QAE@X@Z'), 'msvc')

    def test_detect_operator(self):
        self.assertEqual(detect_format('??2@YAPAXI@Z'), 'msvc')

    def test_demangle_dispatch(self):
        result = demangle('?foo@@YAXH@Z')
        self.assertEqual(result, 'void __cdecl foo(int)')


class TestMSVCNonMemberFunctions(unittest.TestCase):
    """Test non-member (free) function demangling."""

    def test_simple_void_int(self):
        self.assertEqual(demangle_msvc('?foo@@YAXH@Z'),
                         'void __cdecl foo(int)')

    def test_int_return_int_param(self):
        self.assertEqual(demangle_msvc('?func@@YAHH@Z'),
                         'int __cdecl func(int)')

    def test_double_return_void(self):
        self.assertEqual(demangle_msvc('?func2@@YANX@Z'),
                         'double __cdecl func2(void)')

    def test_reference_param(self):
        self.assertEqual(demangle_msvc('?func3@@YAXABH@Z'),
                         'void __cdecl func3(int&)')

    def test_pointer_param(self):
        self.assertEqual(demangle_msvc('?func4@@YAXPAH@Z'),
                         'void __cdecl func4(int*)')

    def test_const_pointer_param(self):
        self.assertEqual(demangle_msvc('?pfunc@@YAXPBH@Z'),
                         'void __cdecl pfunc(const int*)')

    def test_multiple_params(self):
        self.assertEqual(demangle_msvc('?multi@@YAHHH@Z'),
                         'int __cdecl multi(int, int)')

    def test_char_param(self):
        self.assertEqual(demangle_msvc('?cfunc@@YAXD@Z'),
                         'void __cdecl cfunc(char)')

    def test_unsigned_int_param(self):
        self.assertEqual(demangle_msvc('?ufunc@@YAXI@Z'),
                         'void __cdecl ufunc(unsigned int)')

    def test_long_param(self):
        self.assertEqual(demangle_msvc('?lfunc@@YAXJ@Z'),
                         'void __cdecl lfunc(long)')


class TestMSVCMemberFunctions(unittest.TestCase):
    """Test member function demangling."""

    def test_public_virtual(self):
        self.assertEqual(demangle_msvc('?bar@MyClass@@UAEXH@Z'),
                         'public: virtual void __thiscall MyClass::bar(int)')

    def test_public_static(self):
        self.assertEqual(demangle_msvc('?baz@MyClass@@SGXH@Z'),
                         'public: static void __stdcall MyClass::baz(int)')

    def test_private_member(self):
        self.assertEqual(demangle_msvc('?priv@MyClass@@AAEXH@Z'),
                         'private: void __thiscall MyClass::priv(int)')

    def test_protected_member(self):
        self.assertEqual(demangle_msvc('?prot@MyClass@@IAEXH@Z'),
                         'protected: void __thiscall MyClass::prot(int)')


class TestMSVCSpecialNames(unittest.TestCase):
    """Test constructor, destructor, vtable, operator demangling."""

    def test_constructor(self):
        self.assertEqual(demangle_msvc('??0MyClass@@QAE@X@Z'),
                         'public: __thiscall MyClass::MyClass(void)')

    def test_destructor(self):
        self.assertEqual(demangle_msvc('??1MyClass@@UAE@X@Z'),
                         'public: virtual __thiscall MyClass::~MyClass(void)')

    def test_vtable(self):
        self.assertEqual(demangle_msvc('??_7MyClass@@6B@'),
                         "const MyClass::`vftable'")

    def test_operator_new(self):
        self.assertEqual(demangle_msvc('??2@YAPAXI@Z'),
                         'void* __cdecl operator new(unsigned int)')

    def test_operator_delete(self):
        self.assertEqual(demangle_msvc('??3@YAXPAX@Z'),
                         'void __cdecl operator delete(void*)')


class TestMSVCVariables(unittest.TestCase):
    """Test variable demangling."""

    def test_global_int(self):
        self.assertEqual(demangle_msvc('?myvar@@3HA'),
                         'int myvar')

    def test_static_member_int(self):
        self.assertEqual(demangle_msvc('?svar@MyClass@@2HA'),
                         'public: static int MyClass::svar')


class TestMSVCUserDefinedTypes(unittest.TestCase):
    """Test user-defined type demangling."""

    def test_struct_param(self):
        self.assertEqual(demangle_msvc('?sfunc@@YAXUMyStruct@@@Z'),
                         'void __cdecl sfunc(struct MyStruct)')

    def test_class_param(self):
        self.assertEqual(demangle_msvc('?cfunc2@@YAXVMyClass@@@Z'),
                         'void __cdecl cfunc2(class MyClass)')

    def test_enum_param(self):
        self.assertEqual(demangle_msvc('?efunc@@YAXW4MyEnum@@@Z'),
                         'void __cdecl efunc(enum MyEnum)')


class TestMSVCScope(unittest.TestCase):
    """Test namespace and nested class scope."""

    def test_namespace(self):
        self.assertEqual(demangle_msvc('?func@ns@@YAXH@Z'),
                         'void __cdecl ns::func(int)')

    def test_nested_class(self):
        self.assertEqual(demangle_msvc('?method@Inner@Outer@@UAEXH@Z'),
                         'public: virtual void __thiscall Outer::Inner::method(int)')


class TestMSVCStructuredOutput(unittest.TestCase):
    """Test structured DemangledSymbol output."""

    def test_structured_function(self):
        sym = demangle_msvc('?foo@@YAXH@Z', structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.format, 'msvc')
        self.assertEqual(sym.full_name, 'void __cdecl foo(int)')
        self.assertEqual(sym.original_mangled, '?foo@@YAXH@Z')

    def test_structured_member_function(self):
        sym = demangle_msvc('?bar@MyClass@@UAEXH@Z', structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.format, 'msvc')
        self.assertEqual(sym.full_name, 'public: virtual void __thiscall MyClass::bar(int)')

    def test_structured_constructor(self):
        sym = demangle_msvc('??0MyClass@@QAE@X@Z', structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.full_name, 'public: __thiscall MyClass::MyClass(void)')

    def test_structured_vtable(self):
        sym = demangle_msvc('??_7MyClass@@6B@', structured=True)
        self.assertIsInstance(sym, DemangledSymbol)
        self.assertEqual(sym.format, 'msvc')


class TestMSVCGracefulDegradation(unittest.TestCase):
    """Test graceful degradation for invalid or unsupported symbols."""

    def test_invalid_symbol_returns_original(self):
        result = demangle_msvc('?invalid@@@')
        # Should not crash — returns original or partial result
        self.assertIsInstance(result, str)

    def test_non_msvc_returns_original(self):
        result = demangle_msvc('plain_function_name')
        self.assertEqual(result, 'plain_function_name')

    def test_empty_string(self):
        result = demangle_msvc('')
        self.assertEqual(result, '')

    def test_hashed_object_returns_original(self):
        result = demangle_msvc('??@ABC123@')
        self.assertEqual(result, '??@ABC123@')


if __name__ == '__main__':
    unittest.main()