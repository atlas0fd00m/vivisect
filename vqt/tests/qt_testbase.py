'''
Base class for headless PyQt6 unit tests.

Sets QT_QPA_PLATFORM=offscreen and provides a shared QApplication
instance for all test cases.

Usage:
    QT_QPA_PLATFORM=offscreen python -m unittest discover -v

Or use run_gui_tests.sh which sets the env var for you.
'''
import os
import sys
import unittest

# Force offscreen rendering before any Qt imports
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

# QtWebEngineWidgets must be imported or AA_ShareOpenGLContexts set
# before QCoreApplication is created.  Set it early here so module
# imports that pull in QtWebEngine (e.g. envi.qt.memcanvas) work.
from PyQt6.QtCore import QCoreApplication, Qt
QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)

from PyQt6.QtWidgets import QApplication

# Singleton QApplication — PyQt6 requires exactly one per process
# We use VQApplication (a QApplication subclass with guievents signal
# and vqtchans dict) so runtime-dependent tests can access the full
# application object without requiring a vqt.main.startup() call.
_qapp = None

def get_qapp():
    global _qapp
    if _qapp is None:
        _qapp = QApplication.instance()
        if _qapp is None:
            from vqt.main import VQApplication
            _qapp = VQApplication(sys.argv)
    return _qapp

# Module-level globals found by vqt.main functions like eatevents,
# vqtconnect, idlethread, etc.  Set by init_vqt_globals() below.
# Avoids needing startup() which spawns background threads.
_globals_initialized = False

def init_vqt_globals():
    '''Seed the vqt.main module globals (qapp, guiq, workerq) so that
    functions referencing them (eatevents, idlethread, workthread,
    vqtconnect, vqtdisconnect, vqtevent) work in unit tests without
    a full vqt.main.startup() call.'''
    global _globals_initialized
    if _globals_initialized:
        return
    import vqt.main as vm
    import envi.threads as e_threads
    vm.qapp = QApplication.instance()
    vm.guiq = e_threads.EnviQueue()
    vm.workerq = e_threads.EnviQueue()
    _globals_initialized = True


class VQtTestCase(unittest.TestCase):
    '''
    Base test case that ensures a QApplication exists and pumps
    the event loop around each test.

    Sets up a VQApplication (QApplication subclass with event channel
    infrastructure) so tests can access vqtchans, guievents, and
    callFromQtLoop without requiring vqt.main.startup().

    Also seeds the vqt.main module-level globals (qapp, guiq, workerq)
    so functions decorated with @idlethread / @workthread can operate
    without a full runtime startup.
    '''

    @classmethod
    def setUpClass(cls):
        cls.qapp = get_qapp()
        init_vqt_globals()

    def setUp(self):
        self.qapp.processEvents()

    def tearDown(self):
        self.qapp.processEvents()
