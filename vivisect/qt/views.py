import vqt.tree as vq_tree
import vqt.basics as vq_basics
import vivisect.base as viv_base
import envi.qt.memory as e_q_memory
import vivisect.qt.ctxmenu as v_q_ctxmenu

from PyQt6 import QtCore
from PyQt6.QtCore import QSortFilterProxyModel, QRegularExpression
from PyQt6.QtGui import QActionGroup
from PyQt6.QtWidgets import QMenu, QWidget, QLineEdit, QToolButton, QWidgetAction

from vqt.main import vqtevent
from vqt.common import *
from vivisect.const import *

class VivNavModel(e_q_memory.EnviNavModel):
    pass


class VivFilterModel(QSortFilterProxyModel):
    """
    A QSortFilterProxyModel configured for real-time full-column filtering
    with transparent attribute delegation to the source model.
    """

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setDynamicSortFilter(True)
        self.setFilterKeyColumn(-1)  # filter across all columns

    def __getattr__(self, name):
        # Delegate attribute lookups to the source model so
        # vivAddRow / append / vqDelRow etc. pass through transparently.
        src = self.sourceModel()
        if src is None:
            raise AttributeError(name)
        return getattr(src, name)


class VQFilterWidget(QLineEdit):
    """Line-edit filter bar with case-sensitivity toggle and pattern-type selection."""

    filterChanged = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setClearButtonEnabled(True)
        self.setPlaceholderText("Filter...")

        self._caseSensitive = False
        self._patternType = "fixed"

        # ---- options menu ----
        menu = QMenu(self)

        caseAction = menu.addAction("Case Sensitive")
        caseAction.setCheckable(True)
        caseAction.toggled.connect(self._onCaseToggled)

        menu.addSeparator()

        patternGroup = QActionGroup(self)
        patternGroup.setExclusive(True)

        for label, ptype in [
            ("Fixed String", "fixed"),
            ("Regular Expression", "regex"),
            ("Wildcard", "wildcard"),
        ]:
            action = menu.addAction(label)
            action.setData(ptype)
            action.setCheckable(True)
            if ptype == "fixed":
                action.setChecked(True)
            patternGroup.addAction(action)

        patternGroup.triggered.connect(self._onPatternChanged)

        # ---- options button (hamburger style) ----
        optionsBtn = QToolButton(self)
        optionsBtn.setCursor(QtCore.Qt.CursorShape.ArrowCursor)
        optionsBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        optionsBtn.setStyleSheet("QToolButton { border: none; }")
        optionsBtn.setArrowType(QtCore.Qt.ArrowType.DownArrow)
        optionsBtn.setMenu(menu)
        optionsBtn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

        optionsAction = QWidgetAction(self)
        optionsAction.setDefaultWidget(optionsBtn)
        self.addAction(optionsAction, QLineEdit.ActionPosition.LeadingPosition)

        self.textChanged.connect(self.filterChanged)

    # -----------------------------------------------------------------
    def _onCaseToggled(self, checked):
        self._caseSensitive = checked
        self.filterChanged.emit()

    def _onPatternChanged(self, action):
        self._patternType = action.data()
        self.filterChanged.emit()

    def getCaseSensitivity(self):
        return (
            QtCore.Qt.CaseSensitivity.CaseSensitive
            if self._caseSensitive
            else QtCore.Qt.CaseSensitivity.CaseInsensitive
        )

    def getPatternType(self):
        return self._patternType


class VivFilterView(QWidget):
    """
    Container widget that wraps a VQVivTreeView subclass (the **Part**)
    together with a VQFilterWidget in a vertical layout.
    Subclasses set *view_type* to their Part class.
    """

    view_type = None

    def __init__(self, vw, vwqgui, *args, **kwargs):
        super().__init__()

        self.view = self.view_type(vw, vwqgui, *args, **kwargs)
        self.ffilt = VQFilterWidget(self)

        layout = vq_basics.VBox(self.view, self.ffilt)
        self.setLayout(layout)

        self.ffilt.filterChanged.connect(self._onFilterChanged)
        self.setWindowTitle(self.view.window_title)

    def _onFilterChanged(self):
        text = self.ffilt.text()
        if not text:
            self.view.filterModel.setFilterRegularExpression(QRegularExpression())
            return

        ptype = self.ffilt.getPatternType()
        cs = self.ffilt.getCaseSensitivity()

        if ptype == "wildcard":
            # * -> .*   ? -> .
            pattern = QRegularExpression.escape(text).replace(r"\*", ".*").replace(r"\?", ".")
            regex = QRegularExpression(pattern, cs)
        elif ptype == "regex":
            regex = QRegularExpression(text, cs)
        else:
            # Fixed string: escape for regex matching
            regex = QRegularExpression(QRegularExpression.escape(text), cs)

        self.view.filterModel.setFilterRegularExpression(regex)

    def __getattr__(self, name):
        return getattr(self.view, name)


class VQVivTreeView(vq_tree.VQTreeView, viv_base.VivEventCore):

    window_title = "VivTreeView"
    _viv_navcol = 0

    def __init__(self, vw=None, vwqgui=None, **kwargs):
        vq_tree.VQTreeView.__init__(self, parent=vwqgui, **kwargs)
        viv_base.VivEventCore.__init__(self, vw)

        self.vw = vw
        self.vwqgui = vwqgui
        self._viv_va_nodes = {}

        vwqgui.addEventCore(self)

        self.setWindowTitle(self.window_title)
        self.setSortingEnabled(True)
        self.setDragEnabled( True )

        self.doubleClicked.connect( self.doubleClickedSignal )

    def doubleClickedSignal(self, idx):
        if idx.isValid() and self._viv_navcol is not None:
            pnode = idx.internalPointer()
            expr = pnode.rowdata[self._viv_navcol]
            vqtevent('envi:nav:expr', ('viv', expr, None))
            return True

    def contextMenuEvent(self, event):
        menu = QMenu(parent=self)
        idxlist = self.selectedIndexes()
        if not idxlist:
            return

        idx = idxlist[0]
        if idx.isValid() and self._viv_navcol is not None:
            pnode = idx.internalPointer()
            expr = pnode.rowdata[self._viv_navcol]
            v_q_ctxmenu.buildContextMenu(self.vw, expr=expr, menu=menu)

        menu.exec(event.globalPos())

    def vivAddRow(self, va, *row):
        node = self.model().append(row)
        node.va = va
        self._viv_va_nodes[va] = node
        return node

    def vivDelRow(self, va):
        node = self._viv_va_nodes.pop(va, None)
        if node:
            self.model().vqDelRow(node)

    def vivSetData(self, va, col, val):
        '''
        Set a row/col in the data model.  This will quietly fail
        if we don't contain a row for the va (makes users not need
        to check...)

        Example: view.vivSetData(0x41414141, 2, 'Woot Function')

        NOTE: This is for use by the VWE_ event callback handlers!
        '''
        pnode = self._viv_va_nodes.get(va)
        if not pnode:
            return

        # When a proxy model is in use, access the source model directly
        # to avoid index-mapping issues (the proxy's setData expects proxy
        # indexes but we create source-model indexes here).
        model = self.model()
        src = getattr(model, 'sourceModel', None)
        if src is not None:
            model = src()

        idx = model.createIndex(pnode.row(), col, pnode)
        model.setData(idx, val, role=QtCore.Qt.ItemDataRole.DisplayRole)

    def vivGetData(self, va, col):
        pnode = self._viv_va_nodes.get(va)
        if not pnode:
            return None
        return pnode.rowdata[col]

class VQVivLocView(VQVivTreeView):

    loctypes = ()

    def __init__(self, vw, vwqgui):
        VQVivTreeView.__init__(self, vw, vwqgui)
        self.navModel = VivNavModel(self._viv_navcol, parent=self, columns=self.columns)
        self.filterModel = VivFilterModel()
        self.filterModel.setSourceModel(self.navModel)
        self.setModel(self.filterModel)
        self.vqLoad()
        self.vqSizeColumns()

    def vqLoad(self):

        for l in self.loctypes:
            for lva, lsize, ltype, linfo in self.vw.getLocations(l):
                self.vivAddLocation(lva, lsize, ltype, linfo)

    def VWE_DELLOCATION(self, vw, event, einfo):
        lva, lsize, ltype, linfo = einfo
        self.vivDelRow(lva)

    def VWE_ADDLOCATION(self, vw, event, einfo):
        lva, lsize, ltype, linfo = einfo
        if ltype in self.loctypes:
            self.vivAddLocation(lva, lsize, ltype, linfo)

    def vivAddLocation(self, lva, lsize, ltype, linfo):
        raise NotImplementedError("LocationViews must override vivAddLocation")

class VQVivStringsViewPart(VQVivLocView):

    columns = ('Address','String')
    loctypes = (LOC_STRING, LOC_UNI)
    window_title = 'Strings'

    def vivAddLocation(self, lva, lsize, ltype, linfo):
        s = self.vw.readMemory(lva, lsize)
        if ltype == LOC_UNI:
            s = s.decode('utf-16le', 'ignore')
        else:
            s = s.decode('utf-8', 'ignore')
        self.vivAddRow(lva, '0x%.8x' % lva, repr(s))

class VQVivImportsViewPart(VQVivLocView):

    columns = ('Address', 'Library', 'Function')
    loctypes = (LOC_IMPORT,)
    window_title = 'Imports'

    def vivAddLocation(self, lva, lsize, ltype, linfo):
        libname, funcname = linfo.split('.', 1)
        self.vivAddRow(lva, '0x%.8x' % lva, libname, funcname)

class VQVivStructsViewPart(VQVivLocView):
    columns = ('Address', 'Structure', 'Loc Name')
    loctypes = (LOC_STRUCT,)
    window_title = 'Structures'

    def vivAddLocation(self, lva, lsize, ltype, linfo):
        sym = self.vw.getSymByAddr(lva)
        self.vivAddRow(lva, '0x%.8x' % lva, linfo, str(sym))

class VQVivExportsViewPart(VQVivTreeView):

    window_title = 'Exports'
    columns = ('Address', 'File', 'Export')

    def __init__(self, vw, vwqgui):
        VQVivTreeView.__init__(self, vw, vwqgui)
        self.navModel = VivNavModel(self._viv_navcol, self, columns=self.columns)
        self.filterModel = VivFilterModel()
        self.filterModel.setSourceModel(self.navModel)
        self.setModel(self.filterModel)
        self.vqLoad()
        self.vqSizeColumns()

    def vqLoad(self):
        for va, etype, ename, fname in self.vw.getExports():
            self.vivAddExport(va, etype, ename, fname)

    def vivAddExport(self, va, etype, ename, fname):
        self.vivAddRow(va, '0x%.8x' % va, fname, ename)

    def VWE_ADDEXPORT(self, vw, event, einfo):
        va, etype, ename, fname = einfo
        self.vivAddExport(va, etype, ename, fname)

class VQVivSegmentsViewPart(VQVivTreeView):

    _viv_navcol = 2
    window_title = 'Segments'
    columns = ('Module','Section', 'Address', 'Size')

    def __init__(self, vw, vwqgui):
        VQVivTreeView.__init__(self, vw, vwqgui)
        self.navModel = VivNavModel(self._viv_navcol, self, columns=self.columns)
        self.filterModel = VivFilterModel()
        self.filterModel.setSourceModel(self.navModel)
        self.setModel(self.filterModel)
        self.vqLoad()
        self.vqSizeColumns()

    def vqLoad(self):
        for va, size, sname, fname in self.vw.getSegments():
            self.vivAddRow(va, fname, sname, '0x%.8x' % va, str(size))


class VQVivFunctionsViewPart(VQVivTreeView):

    _viv_navcol = 0
    window_title = 'Functions'
    columns = ('Name', 'Address', 'Size', 'Ref Count')

    def __init__(self, vw, vwqgui):
        VQVivTreeView.__init__(self, vw, vwqgui)
        self.navModel = VivNavModel(self._viv_navcol, self, columns=self.columns)
        self.filterModel = VivFilterModel()
        self.filterModel.setSourceModel(self.navModel)
        self.setModel(self.filterModel)
        self.vqLoad()
        self.vqSizeColumns()

    def vqLoad(self):
        for fva in self.vw.getFunctions():
            self.vivAddFunction(fva)

    def VWE_ADDFUNCTION(self, vw, event, einfo):
        fva, fmeta = einfo
        self.vivAddFunction(fva)

    def VWE_DELFUNCTION(self, vw, event, fva):
        self.vivDelRow(fva)

    def VWE_SETNAME(self, vw, event, einfo):
        va, name = einfo
        self.vivSetData(va, 0, name)

    def vivAddFunction(self, fva):
        size = self.vw.getFunctionMeta(fva, "Size", -1)
        funcname = self.vw.getName(fva)
        xcount = len(self.vw.getXrefsTo(fva))
        if fva in self._viv_va_nodes:
            self.vivSetData(fva, 0, funcname)
            self.vivSetData(fva, 1, '0x%.8x' % fva)
            self.vivSetData(fva, 2, size)
            self.vivSetData(fva, 3, xcount)
        else:
            self.vivAddRow(fva, funcname, '0x%.8x' % fva, size, xcount)

    def VWE_ADDXREF(self, vw, event, einfo):
        fromva, tova, rtype, rflag = einfo
        cnt = self.vivGetData(tova, 3)
        if cnt is None:
            return
        self.vivSetData(tova, 3, cnt + 1)

    def VWE_DELXREF(self, vw, event, einfo):
        fromva, tova, rtype, rflag = einfo
        cnt = self.vivGetData(tova, 3)
        if cnt is None:
            return
        self.vivSetData(tova, 3, cnt - 1)

    def VWE_SETFUNCMETA(self, vw, event, einfo):
        funcva, key, value = einfo
        if key == "Size":
            self.vivSetData(funcva, 2, value)

def reprAddress(vw, item):
    return "0x%x (%s)" % (item, vw.reprPointer(item))

def reprString(vw, item):
    return item

def reprIntLong(vw, item):
    if item > 1024:
        return hex(item)
    return item

def reprHextup(vw, item):
    return [hex(x) for x in item]

def reprSmart(vw, item):
    ptype = type(item)
    if ptype is int:
        if -1024 < item < 1024:
            return str(item)
        elif vw.isValidPointer(item):
            return vw.reprPointer(item)
        else:
            return hex(item)

    elif ptype in (list, tuple):
        return reprComplex(vw, item) # recurse

    elif ptype is dict:
        return '{%s}' % ','.join(["%s:%s" % (reprSmart(vw,k), reprSmart(vw,v)) for k,v in item.items()])

    else:
        return repr(item)

def reprComplex(vw, item):
    retval = []
    for part in item:
        retval.append(reprSmart(vw, part))

    return ', '.join(retval)


vaset_reprHandlers = {
    VASET_ADDRESS: reprAddress,
    VASET_STRING:  reprString,
    VASET_INTEGER: reprIntLong,
    VASET_HEXTUP:  reprHextup,
    VASET_COMPLEX: reprComplex,
}

class VQVivVaSetViewPart(VQVivTreeView):

    _viv_navcol = 0

    def __init__(self, vw, vwqgui, setname):
        self._va_setname = setname

        setdef = vw.getVaSetDef( setname )
        cols = [ cname for (cname,ctype) in setdef ]

        VQVivTreeView.__init__(self, vw, vwqgui)

        self.navModel = VivNavModel(self._viv_navcol, self, columns=cols)
        self.filterModel = VivFilterModel()
        self.filterModel.setSourceModel(self.navModel)
        self.setModel(self.filterModel)
        self.vqLoad()
        self.vqSizeColumns()
        self.setWindowTitle('Va Set: %s' % setname)

    def VWE_SETVASETROW(self, vw, event, einfo):
        setname, row = einfo
        if setname == self._va_setname:
            va = row[0]
            self.vivAddRow(va, *self.reprRow(row))

    def vqLoad(self):
        setdef = self.vw.getVaSetDef(self._va_setname)
        rows = self.vw.getVaSetRows(self._va_setname)
        for row in rows:
            va = row[0]
            self.vivAddRow(va, *self.reprRow(row))

    def reprRow(self, row):
        row = [item for item in row]
        setdef = self.vw.getVaSetDef(self._va_setname)

        row[0] = hex(row[0])
        for idx in range(1, len(row)):
            item = row[idx]
            itype = setdef[idx][1]

            handler = vaset_reprHandlers.get(itype)

            if handler is None:
                row[idx] = repr(row[idx])
            else:
                row[idx] = handler(self.vw, item)

        return row

class VQXrefViewPart(VQVivTreeView):

    _viv_navcol = 0

    def __init__(self, vw, vwqgui, xrefs=(), title='Xrefs'):

        self.window_title = title

        VQVivTreeView.__init__(self, vw, vwqgui)
        self.navModel = VivNavModel(self._viv_navcol, self, columns=('Xref From', 'Xref Type', 'Xref Flags', 'Func Name'))
        self.filterModel = VivFilterModel()
        self.filterModel.setSourceModel(self.navModel)
        self.setModel(self.filterModel)

        for fromva, tova, rtype, rflags in xrefs:
            fva = vw.getFunction(fromva)
            funcname = ''
            if fva is not None:
                funcname = vw.getName(fva)
            self.vivAddRow(fromva, '0x%.8x' % fromva, rtype, rflags, funcname)

        self.vqSizeColumns()

class VQVivNamesViewPart(VQVivTreeView):

    _viv_navcol = 0
    window_title = 'Workspace Names'
    columns = ('Address', 'Name')

    def __init__(self, vw, vwqgui):
        VQVivTreeView.__init__(self, vw, vwqgui)
        self.navModel = VivNavModel(self._viv_navcol, self, columns=self.columns)
        self.filterModel = VivFilterModel()
        self.filterModel.setSourceModel(self.navModel)
        self.setModel(self.filterModel)
        self.vqLoad()
        self.vqSizeColumns()

    def vqLoad(self):
        for name in self.vw.getNames():
            self.vivAddName(name)

    def VWE_SETNAME(self, vw, event, einfo):
        va, name = einfo
        #self.vivSetData(va, 1, name)
        self.vivAddName(einfo)

    def vivAddName(self, nifo):
        va, name = nifo
        if self.vivGetData(va, 0) is None:
            self.vivAddRow(va, '0x%.8x' % va, name)
        else:
            self.vivSetData(va, 1, name)


# =============================================================================
# Filtered view wrappers  (keep original class names for layout restoration)
# =============================================================================

class VQVivFunctionsView(VivFilterView):
    view_type = VQVivFunctionsViewPart


class VQVivNamesView(VivFilterView):
    view_type = VQVivNamesViewPart


class VQVivExportsView(VivFilterView):
    view_type = VQVivExportsViewPart


class VQVivVaSetView(VivFilterView):
    view_type = VQVivVaSetViewPart


class VQXrefView(VivFilterView):
    view_type = VQXrefViewPart


class VQVivStringsView(VivFilterView):
    view_type = VQVivStringsViewPart


class VQVivImportsView(VivFilterView):
    view_type = VQVivImportsViewPart


class VQVivStructsView(VivFilterView):
    view_type = VQVivStructsViewPart


class VQVivSegmentsView(VivFilterView):
    view_type = VQVivSegmentsViewPart
