'''
Tests for vqt.main — threading decorators, event system, VQApplication.

Covers idlethread, workthread, boredthread, idlethreadsync, iAmQtSafeThread,
isGuiStarted, eatevents, vqtevent, vqtconnect/vqtdisconnect, QEventThread,
VQApplication, getOpenFileName, getSaveFileName.

All tests use VQtTestCase from qt_testbase, which now creates a VQApplication
and seeds the vqt.main module globals (qapp, guiq, workerq) via
init_vqt_globals(). This means functions like eatevents, vqtconnect, and
idlethread-decorated calls work without a full startup().
'''
import unittest

from vqt.tests.qt_testbase import VQtTestCase
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication


# ── VQApplication / Event system tests ────────────────────────────

class Test_0VQApplicationRuntime(VQtTestCase):
    '''Name with _0 prefix to sort first alphabetically so VQApplication
    is set up before other VQtTestCase classes (unittest uses dir()
    which returns sorted names).'''

    def test_qapp_is_vqapplication(self):
        from vqt.main import VQApplication
        self.assertIsInstance(self.qapp, VQApplication)

    def test_vqapp_has_vqtchans(self):
        self.assertIsInstance(self.qapp.vqtchans, dict)
        self.assertEqual(len(self.qapp.vqtchans), 0)

    def test_vqapp_callFromQtLoop(self):
        results = []
        self.qapp.callFromQtLoop(
            lambda a, b: results.append(a + b), (3, 4), {})
        self.assertEqual(results, [7])

    def test_vqapp_guievents_signal(self):
        self.assertTrue(hasattr(self.qapp, 'guievents'))
        self.assertIsNotNone(self.qapp.guievents)


class Test_1EatEvents(VQtTestCase):

    def test_eatevents_does_not_crash(self):
        from vqt.main import eatevents
        eatevents()


class Test_2VQtEventSystem(VQtTestCase):

    def test_vqtconnect_without_event(self):
        from vqt.main import vqtconnect, vqtdisconnect
        results = []
        def cb(event, einfo): results.append((event, einfo))
        vqtconnect(cb)
        vqtdisconnect(cb)

    def test_vqtconnect_with_event_creates_channel(self):
        from vqt.main import vqtconnect, vqtdisconnect
        results = []
        def cb(event, einfo): results.append((event, einfo))
        vqtconnect(cb, event='test_event')
        self.assertIn('test_event', self.qapp.vqtchans)
        vqtdisconnect(cb, event='test_event')
        if 'test_event' in self.qapp.vqtchans:
            del self.qapp.vqtchans['test_event']

    def test_vqtconnect_event_channel_reuse(self):
        from vqt.main import vqtconnect, vqtdisconnect, QEventChannel
        chan = QEventChannel()
        self.qapp.vqtchans['preexisting'] = chan
        results = []
        def cb(event, einfo): results.append(event)
        vqtconnect(cb, event='preexisting')
        self.assertIs(self.qapp.vqtchans['preexisting'], chan)
        vqtdisconnect(cb, event='preexisting')
        del self.qapp.vqtchans['preexisting']

    def test_vqtdisconnect_non_connected_callback(self):
        from vqt.main import vqtdisconnect
        def cb(event, einfo): pass
        vqtdisconnect(cb, event='never_connected')

    def test_vqtevent_emits_to_global(self):
        from vqt.main import vqtevent
        results = []
        self.qapp.guievents.connect(
            lambda e, i: results.append((e, i)))
        vqtevent('my_event', {'key': 'val'})
        self.qapp.processEvents()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'my_event')


# ── Decorator / utility tests ─────────────────────────────────────

class TestBoredThread(VQtTestCase):

    def test_boredthread_wraps_name(self):
        from vqt.main import boredthread
        @boredthread
        def foo(): pass
        self.assertEqual(foo.__name__, 'foo')

    def test_boredthread_is_callable(self):
        from vqt.main import boredthread
        @boredthread
        def foo(): pass
        self.assertTrue(callable(foo))


class TestFireQtThread(VQtTestCase):

    def test_fireqtthread_creates_qthread(self):
        from vqt.main import fireqtthread, QFireThread
        @fireqtthread
        def my_func(x): return x * 2
        thread = my_func(10)
        self.assertIsInstance(thread, QFireThread)
        self.assertTrue(thread.isRunning())
        thread.wait(1000)
        self.assertFalse(thread.isRunning())


class TestGetOpenFileName(VQtTestCase):

    def test_getOpenFileName_wrapper(self):
        from vqt.main import getOpenFileName
        self.assertTrue(callable(getOpenFileName))


class TestGetSaveFileName(VQtTestCase):

    def test_getSaveFileName_wrapper(self):
        from vqt.main import getSaveFileName
        self.assertTrue(callable(getSaveFileName))


class TestIAmQtSafeThread(VQtTestCase):

    def test_not_qt_safe_by_default(self):
        from vqt.main import iAmQtSafeThread
        self.assertFalse(iAmQtSafeThread())

    def test_set_qt_safe(self):
        from threading import current_thread
        from vqt.main import iAmQtSafeThread
        current_thread().QtSafeThread = True
        self.assertTrue(iAmQtSafeThread())
        del current_thread().QtSafeThread


class TestIdleThread(VQtTestCase):

    def test_idlethread_wraps_name(self):
        from vqt.main import idlethread
        @idlethread
        def my_func(): pass
        self.assertEqual(my_func.__name__, 'my_func')

    def test_idlethread_is_callable(self):
        from vqt.main import idlethread
        @idlethread
        def my_func(): return 42
        self.assertTrue(callable(my_func))


class TestIdleThreadSync(VQtTestCase):

    def test_idlethreadsync_wraps(self):
        from vqt.main import idlethreadsync
        @idlethreadsync
        def compute(x, y): return x + y
        self.assertTrue(callable(compute))


class TestIsGuiStarted(VQtTestCase):

    def test_gui_started_with_app(self):
        from vqt.main import isGuiStarted
        self.assertTrue(isGuiStarted())


class TestQEventChannel(VQtTestCase):

    def test_create_channel(self):
        from vqt.main import QEventChannel
        chan = QEventChannel()
        self.assertTrue(hasattr(chan, 'guievents'))

    def test_channel_signal_emit(self):
        from vqt.main import QEventChannel
        chan = QEventChannel()
        results = []
        chan.guievents.connect(lambda e, i: results.append((e, i)))
        chan.guievents.emit('ch_event', 'info')
        self.qapp.processEvents()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], ('ch_event', 'info'))


class TestQFireThread(VQtTestCase):

    def test_qfirethread_executes(self):
        from vqt.main import QFireThread
        results = []
        def target(): results.append('done')
        thread = QFireThread(target, (), {})
        thread.start()
        thread.wait(1000)
        self.assertEqual(results, ['done'])


class TestWorkThread(VQtTestCase):

    def test_workthread_is_callable(self):
        from vqt.main import workthread
        @workthread
        def my_func(): pass
        self.assertTrue(callable(my_func))


if __name__ == '__main__':
    unittest.main()
