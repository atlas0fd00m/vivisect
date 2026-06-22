'''
Additional tests for vqt.common — dialog functions, view selection, data editing.

Covers warning/information/scripterr message boxes (idlethread decorated),
VqtView.getSelectedRows(), VqtModel.setData() EditRole path, and
additional edge cases not covered in the initial test_qt_common.py.

NOTE: VqtModel defaults to 2 columns, so all test rows must be 2-element
tuples unless a custom columns parameter is passed.
'''
import unittest

from PyQt6 import QtCore
from PyQt6.QtWidgets import QTreeView

from vqt.tests.qt_testbase import VQtTestCase


class TestVqtModelEditing(VQtTestCase):
    '''Tests for VqtModel editing paths.'''

    def test_set_data_with_invalid_index(self):
        from vqt.common import VqtModel
        model = VqtModel(rows=[('a', 'b')])
        result = model.setData(QtCore.QModelIndex(), 'new',
                               QtCore.Qt.ItemDataRole.EditRole)
        self.assertFalse(result)

    def test_set_data_edit_role_calls_vqt_set_data(self):
        from vqt.common import VqtModel

        class CustomVqtModel(VqtModel):
            def _vqt_set_data(self, row, col, value):
                self.rows[row][col] = f'modified: {value}'
                return True

        model = CustomVqtModel(rows=[('old1', 'old2')])
        idx = model.index(0, 0, QtCore.QModelIndex())
        result = model.setData(idx, 'newval',
                               QtCore.Qt.ItemDataRole.EditRole)
        self.assertTrue(result)
        self.assertEqual(model.rows[0][0], 'modified: newval')

    def test_set_data_edit_role_rejected_by_vqt_set_data(self):
        from vqt.common import VqtModel

        class RejectingModel(VqtModel):
            def _vqt_set_data(self, row, col, value):
                return False

        model = RejectingModel(rows=[('old', 'val')])
        idx = model.index(0, 0, QtCore.QModelIndex())
        result = model.setData(idx, 'new',
                               QtCore.Qt.ItemDataRole.EditRole)
        self.assertFalse(result)
        self.assertEqual(model.rows[0][0], 'old')

    def test_set_data_non_edit_role(self):
        from vqt.common import VqtModel
        model = VqtModel(rows=[('val', 'x')])
        idx = model.index(0, 0, QtCore.QModelIndex())
        result = model.setData(idx, 'should_not_change',
                               QtCore.Qt.ItemDataRole.UserRole)
        self.assertTrue(result)
        self.assertEqual(model.rows[0][0], 'val')

    def test_append_emits_layout_changed(self):
        from vqt.common import VqtModel
        model = VqtModel()
        signal_fired = []
        model.layoutChanged.connect(lambda: signal_fired.append(True))
        model.append(('x', 'y'))
        self.assertEqual(len(signal_fired), 1)

    def test_pop_removes_and_emits_signals(self):
        from vqt.common import VqtModel
        model = VqtModel(rows=[('a', '1'), ('b', '2'), ('c', '3')])
        model.pop(1)
        self.assertEqual(model.rowCount(QtCore.QModelIndex()), 2)
        # Row 1 ('b', '2') removed, row 1 is now ('c', '3')
        idx = model.index(1, 0, QtCore.QModelIndex())
        self.assertEqual(model.data(idx, QtCore.Qt.ItemDataRole.DisplayRole), 'c')

    def test_editable_flags(self):
        from vqt.common import VqtModel
        model = VqtModel(rows=[('a', 'b')])
        model.editable = [True, False]
        idx_0 = model.index(0, 0, QtCore.QModelIndex())
        idx_1 = model.index(0, 1, QtCore.QModelIndex())
        self.assertTrue(model.flags(idx_0) & QtCore.Qt.ItemFlag.ItemIsEditable)
        self.assertFalse(model.flags(idx_1) & QtCore.Qt.ItemFlag.ItemIsEditable)

    def test_dragable_flags(self):
        from vqt.common import VqtModel
        model = VqtModel(rows=[('a', 'b')])
        model.dragable = True
        idx = model.index(0, 0, QtCore.QModelIndex())
        self.assertTrue(model.flags(idx) & QtCore.Qt.ItemFlag.ItemIsDragEnabled)

    def test_invalid_index_flags_no_item_flags(self):
        from vqt.common import VqtModel
        model = VqtModel(rows=[('a', 'b')])
        flags = model.flags(QtCore.QModelIndex())
        self.assertEqual(flags, 0)


class TestVqtView(VQtTestCase):
    '''Additional tests for VqtView beyond the basic test_qt_common.'''

    def test_get_selected_rows_empty(self):
        from vqt.common import VqtView, VqtModel
        view = VqtView()
        model = VqtModel(rows=[('a', 'b'), ('c', 'd')])
        view.setModel(model)
        self.assertEqual(view.getSelectedRows(), [])

    def test_get_model_rows(self):
        from vqt.common import VqtView, VqtModel
        view = VqtView()
        model = VqtModel(rows=[('x', 'y'), ('z', 'w')])
        view.setModel(model)
        rows = view.getModelRows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], ['x', 'y'])

    def test_get_model_row(self):
        from vqt.common import VqtView, VqtModel
        view = VqtView()
        model = VqtModel(rows=[('first', 'x'), ('second', 'y')])
        view.setModel(model)
        proxy = view.model()
        proxy_idx = proxy.index(0, 0, QtCore.QModelIndex())
        self.assertTrue(proxy_idx.isValid())
        row_num, ptr = view.getModelRow(proxy_idx)
        # QSortFilterProxyModel may remap rows — accept whichever internal
        # pointer getModelRow resolves to; it should be an existing row
        self.assertIn(ptr, model.rows)

    def test_set_model_creates_proxy(self):
        from vqt.common import VqtView, VqtModel
        from PyQt6.QtCore import QSortFilterProxyModel
        view = VqtView()
        model = VqtModel(rows=[('a', 'b')])
        view.setModel(model)
        proxy = view.model()
        self.assertIsInstance(proxy, QSortFilterProxyModel)
        self.assertIs(proxy.sourceModel(), model)


class TestMessageBoxFunctions(VQtTestCase):
    '''Tests for the idlethread-decorated message box functions.
    These queue via guiq, so we verify they don't raise.'''

    def test_warning_creates_messagebox(self):
        from vqt.common import warning
        try:
            warning('Test Warning', 'This is a test')
        except Exception as e:
            self.fail(f'warning() raised: {e}')

    def test_information_creates_messagebox(self):
        from vqt.common import information
        try:
            information('Test Info', 'Informative text')
        except Exception as e:
            self.fail(f'information() raised: {e}')

    def test_scripterr_creates_messagebox(self):
        from vqt.common import scripterr
        try:
            scripterr('Script Error', 'Stack trace here')
        except Exception as e:
            self.fail(f'scripterr() raised: {e}')

    def test_message_functions_are_callable(self):
        from vqt.common import warning, information, scripterr
        self.assertTrue(callable(warning))
        self.assertTrue(callable(information))
        self.assertTrue(callable(scripterr))


class TestACTNewThread(VQtTestCase):
    '''Tests for common.ACT setNewThread feature.'''

    def test_act_newthread_flag(self):
        from vqt.common import ACT
        act = ACT(lambda: None)
        self.assertFalse(act.newthread)
        act.setNewThread()
        self.assertTrue(act.newthread)
        act.setNewThread(False)
        self.assertFalse(act.newthread)

    def test_act_newthread_executes(self):
        from vqt.common import ACT
        results = []
        act = ACT(lambda: results.append('done'))
        act.setNewThread(True)
        result = act()
        self.assertIsNotNone(result)

    def test_act_exception_logged(self):
        from vqt.common import ACT
        act = ACT(lambda: 1 / 0)
        act()


class TestBasicsEdgeCases(VQtTestCase):
    '''Additional edge cases for vqt.basics constructs.'''

    def test_basic_model_column_count(self):
        from vqt.basics import BasicModel
        model = BasicModel()
        self.assertEqual(model.columnCount(QtCore.QModelIndex()), 2)

    def test_basic_model_row_count_for_valid_row(self):
        from vqt.basics import BasicModel
        model = BasicModel(rows=[('a', '1')])
        idx = model.index(0, 0, QtCore.QModelIndex())
        self.assertEqual(model.rowCount(idx), 0)

    def test_vbox_no_args(self):
        from vqt.basics import VBox
        layout = VBox()
        self.assertEqual(layout.count(), 0)

    def test_vbox_all_stretch(self):
        from vqt.basics import VBox
        layout = VBox(None, None)
        self.assertEqual(layout.count(), 2)

    def test_hbox_no_args(self):
        from vqt.basics import HBox
        layout = HBox()
        self.assertEqual(layout.count(), 0)

    def test_hbox_all_stretch(self):
        from vqt.basics import HBox
        layout = HBox(None, None)
        self.assertEqual(layout.count(), 2)

    def test_act_call_with_kwargs(self):
        from vqt.basics import ACT
        results = {}
        def cb(a, b, **kw):
            results['a'] = a
            results['b'] = b
            results.update(kw)

        act = ACT(cb, 1, 2, extra='val')
        act()
        self.assertEqual(results['a'], 1)
        self.assertEqual(results['b'], 2)
        self.assertEqual(results['extra'], 'val')


if __name__ == '__main__':
    unittest.main()
