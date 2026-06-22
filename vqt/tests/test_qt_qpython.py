'''
Tests for vqt.qpython — VQPythonView widget and ScriptThread.

Covers the Python interactive console widget: construction, button
handlers, ScriptThread execution, and the _helpClicked documentation
viewer.
'''
import unittest

from PyQt6.QtWidgets import QPushButton, QTextEdit, QWidget
from PyQt6.QtCore import Qt

from vqt.tests.qt_testbase import VQtTestCase


class TestScriptThread(VQtTestCase):
    '''Tests for the ScriptThread execution engine.'''

    def test_executes_code(self):
        from vqt.qpython import ScriptThread
        local_context = {'value': 0}

        code = compile('value = 42', '<test>', 'exec')
        thread = ScriptThread(code, local_context)
        thread.run()
        self.assertEqual(local_context['value'], 42)

    def test_executes_function_def(self):
        from vqt.qpython import ScriptThread
        local_context = {}

        code = compile('def add(a, b): return a + b', '<test>', 'exec')
        thread = ScriptThread(code, local_context)
        thread.run()
        self.assertTrue(callable(local_context.get('add')))
        self.assertEqual(local_context['add'](3, 4), 7)

    def test_exception_does_not_propagate(self):
        '''ScriptThread should catch exceptions internally.'''
        from vqt.qpython import ScriptThread

        # Code that raises — ScriptThread catches in the run() method
        bad_code = compile('1 / 0', '<test>', 'exec')
        thread = ScriptThread(bad_code, {})

        # Should not raise
        try:
            thread.run()
        except Exception:
            self.fail('ScriptThread.run() propagated exception')

    def test_locals_initialized(self):
        from vqt.qpython import ScriptThread
        local_context = {'x': 10, 'y': 20}
        code = compile('z = x + y', '<test>', 'exec')
        thread = ScriptThread(code, local_context)
        thread.run()
        self.assertEqual(local_context['z'], 30)


class TestVQPythonView(VQtTestCase):
    '''Tests for the VQPythonView interactive widget.'''

    def test_create_default_locals(self):
        from vqt.qpython import VQPythonView
        view = VQPythonView()
        self.assertIsInstance(view._locals, dict)
        self.assertEqual(len(view._locals), 0)
        self.assertIsInstance(view._textWidget, QTextEdit)

    def test_create_with_locals(self):
        from vqt.qpython import VQPythonView
        my_locals = {'x': 42, 'name': 'test'}
        view = VQPythonView(locals=my_locals)
        self.assertIs(view._locals, my_locals)

    def test_run_button_exists(self):
        from vqt.qpython import VQPythonView
        view = VQPythonView()
        self.assertIsInstance(view._run_button, QPushButton)
        self.assertEqual(view._run_button.text(), 'Run')

    def test_help_button_exists(self):
        from vqt.qpython import VQPythonView
        view = VQPythonView()
        self.assertIsInstance(view._help_button, QPushButton)
        self.assertEqual(view._help_button.text(), '?')

    def test_window_title_set(self):
        from vqt.qpython import VQPythonView
        view = VQPythonView()
        self.assertEqual(view.windowTitle(), 'Python Interactive')

    def test_text_widget_read_write(self):
        from vqt.qpython import VQPythonView
        view = VQPythonView()
        view._textWidget.setPlainText('print("hello")')
        self.assertEqual(view._textWidget.toPlainText(), 'print("hello")')

    def test_help_clicked_creates_help_window(self):
        '''_helpClicked should create a help text window with local docs.'''
        from vqt.qpython import VQPythonView
        local_ctx = {
            'my_val': 42,
            'my_str': 'hello',
        }
        view = VQPythonView(locals=local_ctx)
        # Initial help_text should be None
        self.assertIsNone(view._help_text)

        # Trigger help
        view._helpClicked()
        self.qapp.processEvents()

        # Should have created the help text widget
        self.assertIsNotNone(view._help_text)
        self.assertIsInstance(view._help_text, QTextEdit)
        help_content = view._help_text.toPlainText()
        # Should contain the local names
        self.assertIn('my_val', help_content)
        self.assertIn('my_str', help_content)

        # Clean up
        view._help_text.close()

    def test_help_clicked_skips_modules(self):
        '''Module-type locals should be excluded from help output.'''
        import types
        from vqt.qpython import VQPythonView
        my_module = types.ModuleType('dummy_mod')
        local_ctx = {
            'visible_obj': 'hello',
            'hidden_mod': my_module,
        }
        view = VQPythonView(locals=local_ctx)
        view._helpClicked()
        help_content = view._help_text.toPlainText()
        self.assertIn('visible_obj', help_content)
        # Module should be filtered out
        self.assertNotIn('hidden_mod', help_content)
        view._help_text.close()

    def test_help_with_empty_locals(self):
        from vqt.qpython import VQPythonView
        view = VQPythonView(locals={})
        view._helpClicked()
        self.assertIsNotNone(view._help_text)
        help_content = view._help_text.toPlainText()
        # Should contain the header text
        self.assertIn('Objects/Functions', help_content)
        view._help_text.close()

    def test_help_text_is_read_only(self):
        from vqt.qpython import VQPythonView
        view = VQPythonView()
        view._helpClicked()
        self.assertTrue(view._help_text.isReadOnly())
        view._help_text.close()

    def test_ok_clicked_compiles_and_runs(self):
        '''_okClicked should compile code in _textWidget and run via ScriptThread.'''
        from vqt.qpython import VQPythonView
        local_ctx = {'result': None}
        view = VQPythonView(locals=local_ctx)
        view._textWidget.setPlainText('result = 99')
        view._okClicked()
        self.qapp.processEvents()
        # The ScriptThread runs in a background thread, so give it a moment
        import time
        time.sleep(0.1)
        self.qapp.processEvents()
        # result should have been set by the exec'd code
        self.assertEqual(local_ctx['result'], 99)

    def test_ok_clicked_invalid_code(self):
        '''Invalid Python should not crash _okClicked.'''
        from vqt.qpython import VQPythonView
        view = VQPythonView()
        view._textWidget.setPlainText('this is not valid python @@@')
        # Should not raise
        view._okClicked()
        self.qapp.processEvents()

    def test_ok_clicked_empty_code(self):
        '''Empty code should compile and run without error.'''
        from vqt.qpython import VQPythonView
        view = VQPythonView()
        view._textWidget.setPlainText('')
        view._okClicked()
        self.qapp.processEvents()

    def test_buttons_linked(self):
        '''Run and Help buttons should be connected to their slots.'''
        from vqt.qpython import VQPythonView
        view = VQPythonView()

        # Check that button signals are connected by checking the
        # number of receivers
        run_receivers = view._run_button.receivers(
            view._run_button.clicked
        )
        help_receivers = view._help_button.receivers(
            view._help_button.clicked
        )
        self.assertGreater(run_receivers, 0)
        self.assertGreater(help_receivers, 0)


if __name__ == '__main__':
    unittest.main()
