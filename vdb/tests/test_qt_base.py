'''
Tests for vdb.qt.base — VdbWidgetWindow base class.

Covers construction, attribute storage, key event delegation,
and inherited SaveableWidget / VQTraceNotifier behaviors.

Uses a background GUI queue drainer thread so tests that call
notify() (which is @idlethreadsync-decorated) complete properly
without the full vqt.main.startup().
'''
import threading
import unittest

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import QEvent

from vqt.tests.qt_testbase import VQtTestCase


def _start_guiq_worker():
    '''Start a daemon thread that drains guiq so idlethreadsync
    callbacks (e.g. VQTraceNotifier.notify) can complete.'''
    import vqt.main as vm

    sentinel = object()
    stop_event = threading.Event()

    def drain():
        while not stop_event.is_set():
            item = vm.guiq.get(timeout=0.2)
            if item is None:     # timeout, nothing available
                continue
            if item is sentinel: # shutdown signal
                break
            cb, args, kwargs = item
            try:
                cb(*args, **kwargs)
            except Exception:
                continue

    t = threading.Thread(target=drain, daemon=True)
    t.start()
    return stop_event, sentinel


class TestVdbWidgetWindow(VQtTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._guiq_stop, cls._guiq_sentinel = _start_guiq_worker()

    @classmethod
    def tearDownClass(cls):
        import vqt.main as vm
        # Put sentinel to stop the drainer
        vm.guiq.append(cls._guiq_sentinel)
        cls._guiq_stop.set()
        super().tearDownClass()

    def make_mocks(self):
        class MockGui:
            def keyPressEvent(self, event):
                self._last_key_event = event

        class MockDb:
            def __init__(self):
                self.gui = MockGui()

        class MockTrace:
            def __init__(self):
                self._notifiers = []
                self._attached = False
                self._running = False

            def registerNotifier(self, event, notifier):
                self._notifiers.append((event, notifier))

            def unregisterNotifier(self, notifier):
                self._notifiers = [(e, n) for e, n in self._notifiers
                                   if n is not notifier]

            def isAttached(self):
                return self._attached

            def isRunning(self):
                return self._running

            def shouldRunAgain(self):
                return False

        return MockDb(), MockTrace()

    def test_create(self):
        from vdb.qt.base import VdbWidgetWindow
        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        self.assertIs(widget.db, db)
        self.assertIs(widget.dbt, dbt)

    def test_has_saveable_widget_mixin(self):
        '''VdbWidgetWindow should inherit SaveableWidget methods.'''
        from vdb.qt.base import VdbWidgetWindow
        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        # SaveableWidget provides vqGetSaveState / vqSetSaveState
        # (default implementations return None — subclasses override)
        self.assertIsNone(widget.vqGetSaveState())
        self.assertIsNone(widget.vqSetSaveState({'dummy': 'data'}))

    def test_keyPressEvent_delegates_to_gui(self):
        from vdb.qt.base import VdbWidgetWindow
        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        event = QtGui.QKeyEvent(
            QEvent.Type.KeyPress, QtCore.Qt.Key.Key_F5,
            QtCore.Qt.KeyboardModifier.NoModifier
        )
        widget.keyPressEvent(event)
        self.assertIs(db.gui._last_key_event, event)

    def test_trace_notifier_inherited(self):
        from vdb.qt.base import VdbWidgetWindow
        from vtrace.const import NOTIFY_ALL
        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        self.assertEqual(len(dbt._notifiers), 1)
        event, notifier = dbt._notifiers[0]
        self.assertEqual(event, NOTIFY_ALL)
        self.assertIs(notifier, widget)

    def test_trace_notifier_registers_on_init(self):
        from vdb.qt.base import VdbWidgetWindow
        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        self.assertIs(widget.trace, dbt)

    def test_notify_skips_update_when_should_run_again(self):
        from vdb.qt.base import VdbWidgetWindow
        from vtrace.const import NOTIFY_BREAK

        db, dbt = self.make_mocks()
        dbt.shouldRunAgain = lambda: True

        widget = VdbWidgetWindow(db, dbt)
        # Need the guiq worker to process the idlethreadsync callback
        self.qapp.processEvents()
        widget.notify(NOTIFY_BREAK, dbt)
        self.qapp.processEvents()

    def test_notify_continue_disables(self):
        from vdb.qt.base import VdbWidgetWindow
        from vtrace.const import NOTIFY_CONTINUE

        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        widget.setEnabled(True)
        widget.notify(NOTIFY_CONTINUE, dbt)
        self.qapp.processEvents()
        self.assertFalse(widget.isEnabled())

    def test_notify_detach_disables(self):
        from vdb.qt.base import VdbWidgetWindow
        from vtrace.const import NOTIFY_DETACH

        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        widget.setEnabled(True)
        widget.notify(NOTIFY_DETACH, dbt)
        self.qapp.processEvents()
        self.assertFalse(widget.isEnabled())

    def test_notify_exit_disables(self):
        from vdb.qt.base import VdbWidgetWindow
        from vtrace.const import NOTIFY_EXIT

        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        widget.setEnabled(True)
        widget.notify(NOTIFY_EXIT, dbt)
        self.qapp.processEvents()
        self.assertFalse(widget.isEnabled())

    def test_notify_break_enables(self):
        from vdb.qt.base import VdbWidgetWindow
        from vtrace.const import NOTIFY_BREAK

        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        widget.setEnabled(False)
        widget.notify(NOTIFY_BREAK, dbt)
        self.qapp.processEvents()
        self.assertTrue(widget.isEnabled())

    def test_notify_signal_enables(self):
        from vdb.qt.base import VdbWidgetWindow
        from vtrace.const import NOTIFY_SIGNAL

        db, dbt = self.make_mocks()
        widget = VdbWidgetWindow(db, dbt)
        widget.setEnabled(False)
        widget.notify(NOTIFY_SIGNAL, dbt)
        self.qapp.processEvents()
        self.assertTrue(widget.isEnabled())

    def test_no_trace_passed(self):
        from vdb.qt.base import VdbWidgetWindow

        class MockDb:
            gui = None

        widget = VdbWidgetWindow(MockDb(), None)
        self.assertIsNone(widget.dbt)
        self.assertIsNone(widget.trace)


if __name__ == '__main__':
    unittest.main()
