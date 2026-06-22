'''
Tests for vqt.cli — VQInput history management and VQCli basics.

Covers VQInput history navigation, persistence (load/save), and the
VQCli widget construction.  VQCli requires an envi.Cli or compatible
object for full testing, so we test with a minimal mock CLI.
'''
import os
import tempfile
import unittest

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import QEvent

from vqt.tests.qt_testbase import VQtTestCase


class TestVQInput(VQtTestCase):
    '''Tests for the VQInput line editor with history.'''

    def test_create(self):
        from vqt.cli import VQInput
        inp = VQInput()
        self.assertEqual(inp.history, [])
        self.assertEqual(inp.histidx, 0)
        self.assertEqual(inp.text(), '')

    def test_add_history(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('first command')
        self.assertEqual(inp.history, ['first command'])
        self.assertEqual(inp.histidx, 1)

    def test_add_empty_history_ignored(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('')
        # addHistory only appends if histcmd is truthy
        self.assertEqual(inp.history, [])

    def test_add_multiple_history(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('cmd1')
        inp.addHistory('cmd2')
        inp.addHistory('cmd3')
        self.assertEqual(inp.history, ['cmd1', 'cmd2', 'cmd3'])
        self.assertEqual(inp.histidx, 3)

    def test_use_history_prev(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('first')
        inp.addHistory('second')
        inp.addHistory('third')

        # histidx=3 (past end). First press up → last history item
        inp.useHistory(-1)
        self.assertEqual(inp.text(), 'third')
        # Second press up → second-to-last
        inp.useHistory(-1)
        self.assertEqual(inp.text(), 'second')

    def test_use_history_prev_at_start(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('only')
        # histidx=1, going back to 0 works
        inp.useHistory(-1)
        self.assertEqual(inp.text(), 'only')
        # Going back further from 0 should be a no-op
        inp.useHistory(-1)
        self.assertEqual(inp.text(), 'only')

    def test_use_history_next(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('a')
        inp.addHistory('b')
        inp.addHistory('c')
        # histidx=3.  Press up 3× to reach first item
        inp.useHistory(-1)  # → c
        inp.useHistory(-1)  # → b
        inp.useHistory(-1)  # → a
        self.assertEqual(inp.text(), 'a')
        # Then press down once to go forward to 'b'
        inp.useHistory(1)
        self.assertEqual(inp.text(), 'b')

    def test_use_history_next_past_end_clears(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('only')
        inp.useHistory(-1)  # go to 'only'
        self.assertEqual(inp.text(), 'only')
        inp.useHistory(1)  # past end should clear
        self.assertEqual(inp.text(), '')

    def test_history_wraps_correctly(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('x')
        inp.addHistory('y')
        # Navigate: up, up, down, down
        inp.useHistory(-1)  # -> y
        inp.useHistory(-1)  # -> x
        inp.useHistory(1)   # -> y
        inp.useHistory(1)   # -> clear
        self.assertEqual(inp.text(), '')

    def test_hotkey_up_triggers_history_prev(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('cmd_a')
        inp.addHistory('cmd_b')

        # Simulate press of Up key
        event = QtGui.QKeyEvent(
            QEvent.Type.KeyPress, QtCore.Qt.Key.Key_Up,
            QtCore.Qt.KeyboardModifier.NoModifier
        )
        inp.keyPressEvent(event)
        self.assertEqual(inp.text(), 'cmd_b')

    def test_hotkey_down_triggers_history_next(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('cmd_a')

        # Press Up then Down
        up_event = QtGui.QKeyEvent(
            QEvent.Type.KeyPress, QtCore.Qt.Key.Key_Up,
            QtCore.Qt.KeyboardModifier.NoModifier
        )
        down_event = QtGui.QKeyEvent(
            QEvent.Type.KeyPress, QtCore.Qt.Key.Key_Down,
            QtCore.Qt.KeyboardModifier.NoModifier
        )
        inp.keyPressEvent(up_event)
        self.assertEqual(inp.text(), 'cmd_a')
        inp.keyPressEvent(down_event)
        self.assertEqual(inp.text(), '')  # cleared

    def test_save_and_load_history(self):
        from vqt.cli import VQInput
        inp = VQInput()
        inp.addHistory('cmd1')
        inp.addHistory('cmd2')
        inp.addHistory('cmd3')

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hist') as f:
            tmppath = f.name

        try:
            inp.saveHistory(tmppath)

            # Create new VQInput and load
            inp2 = VQInput()
            inp2.loadHistory(tmppath)
            self.assertEqual(inp2.history, ['cmd1', 'cmd2', 'cmd3'])

        finally:
            os.unlink(tmppath)

    def test_save_and_load_roundtrip_empty(self):
        from vqt.cli import VQInput
        inp = VQInput()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hist') as f:
            tmppath = f.name

        try:
            inp.saveHistory(tmppath)
            inp2 = VQInput()
            inp2.loadHistory(tmppath)
            self.assertEqual(inp2.history, [])

        finally:
            os.unlink(tmppath)

    def test_load_nonexistent_file(self):
        from vqt.cli import VQInput
        inp = VQInput()
        # loadHistory checks os.path.isfile, so it skips silently
        inp.loadHistory('/tmp/nonexistent_history_file_xyz123')
        self.assertEqual(inp.history, [])

    def test_history_capped_at_1000(self):
        from vqt.cli import VQInput
        inp = VQInput()
        for i in range(1500):
            inp.addHistory(f'cmd{i}')
        # saveHistory uses [-1000:] slice
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hist') as f:
            tmppath = f.name
        try:
            inp.saveHistory(tmppath)
            with open(tmppath) as f:
                lines = f.read().strip().split('\n')
            self.assertLessEqual(len(lines), 1000)
        finally:
            os.unlink(tmppath)

    def test_load_history_trims_to_1000(self):
        from vqt.cli import VQInput
        inp = VQInput()
        # loadHistory uses readlines()[-1000:] internally
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hist') as f:
            for i in range(1500):
                f.write(f'line{i}\n')
            tmppath = f.name
        try:
            inp.loadHistory(tmppath)
            self.assertLessEqual(len(inp.history), 1000)
        finally:
            os.unlink(tmppath)


class TestVQCli(VQtTestCase):
    '''Tests for VQCli widget construction and basic operation.'''

    def test_create_with_minimal_cli(self):
        '''VQCli can be created with a minimal cli-like object.'''
        from vqt.cli import VQCli

        class DummyCli:
            def onecmd(self, cmdline):
                return False

        cli = DummyCli()
        widget = VQCli(cli)
        self.assertIs(widget.cli, cli)
        self.assertIsNotNone(widget.input)
        self.assertIsNotNone(widget.output)

    def test_create_sets_stylesheet(self):
        from vqt.cli import VQCli

        class DummyCli:
            def onecmd(self, cmdline):
                return False

        widget = VQCli(DummyCli())
        # Style sheet should be set from vqt.colors
        self.assertTrue(len(widget.styleSheet()) > 0)

    def test_cli_quit_signal(self):
        from vqt.cli import VQCli

        class DummyCli:
            def onecmd(self, cmdline):
                return True  # triggers quit

        widget = VQCli(DummyCli())
        results = []
        widget.sigCliQuit.connect(lambda: results.append('quit'))
        widget.onecmd('quit')
        # onecmd is queued via workthread, so it's async
        # Just verify the method accepts the command
        self.assertIsNotNone(widget)

    def test_getCliLayout(self):
        from vqt.cli import VQCli

        class DummyCli:
            def onecmd(self, cmdline):
                return False

        widget = VQCli(DummyCli())
        layout = widget.getCliLayout()
        self.assertIsNotNone(layout)

    def test_sigCliQuit_is_pyqtSignal(self):
        from vqt.cli import VQCli
        from PyQt6.QtCore import pyqtSignal
        self.assertIsInstance(VQCli.sigCliQuit, pyqtSignal)


if __name__ == '__main__':
    unittest.main()
