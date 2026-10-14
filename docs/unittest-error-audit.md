# Python unittest output error audit

This document explains the error/warning messages emitted during a full unit
test run of Vivisect on master, their root causes, and how they were fixed so
that the messages no longer appear.

## How the tests are run

```
mkdir code && cd code
git clone https://github.com/vivisect/vivisect
git clone https://github.com/vivisect/vivtestfiles
cd vivisect
VIVTESTFILES=../vivtestfiles python3 -m unittest discover
```

The full suite consists of 595 tests (3 skipped).  The suite **passes**
(`OK (skipped=3)`), yet it emits several `ERROR:` log lines while analyzing the
vivo test binaries.  The messages below are not test failures — they are noisy
diagnostics leaked to the error level from analysis code paths that are
expected to encounter unusual binaries.

## 1. `ERROR:vivisect.analysis.elf.elfplt: analyzePLT(...): ... [elfplt.py:analyzePLT:303]`

**Count observed:** 11 error-log lines (plus ~9 `InvalidFile` tracebacks) during a full run.

**Message example:**
```
ERROR:vivisect.analysis.elf.elfplt: analyzePLT(0x4001648, 1776): [elfplt.py:analyzePLT:303]
Traceback ...
envi.exc.InvalidFile
```

### Root cause
`analyzePLT()` opens with:

```python
gotva, gotsize = getGOTByFilename(vw, vw.getFileByVa(ssva))
```

`vw.getFileByVa(ssva)` looks up the file that owns the segment containing
`ssva`.  For a memory-only analysis — or a workspace where the `.plt` section
is not backed by a file in the loader's file table — `getFileByVa()` returns
`None`.  `getGOTByFilename(vw, None)` then calls
`vw.getFileMeta(None, 'GOT')`, and `getFileMeta` raises
`envi.exc.InvalidFile` because `filemeta.get(None)` is `None`.

The exception is caught by the broad `except Exception` at the bottom of
`analyzePLT`, which re-emits it via `logger.exception(..., exc_info=1)`.  That
turns a benign "this PLT is not file-backed" situation into a full error-level
traceback.

### Fix
- Guard `getGOTByFilename()` against a `None` filename and return a synthetic
  `(None, None)` instead of raising.
- Guard `analyzePLT()` against a `None` `gotva` (no GOT location resolvable)
  and skip the pass at debug level rather than erroring.
- Only `getFileMeta` when the filename is truthy.

## 2. `analyzePLT(...): Unsupported Instruction: 0x08049212 hlt`

**Message example:**
```
ERROR:vivisect.analysis.elf.elfplt: analyzePLT(0x8049154, 840): Unsupported Instruction: 0x08049212 hlt [elfplt.py:analyzePLT:303]
Traceback ...
envi.exc.UnsupportedInstruction: Unsupported Instruction: 0x08049212 hlt
```

### Root cause
While linear-sweeping PLT entries, `analyzePLT` emulates each opcode with
`emu.executeOpcode(op)`.  Some executables contain opcodes the emulator cannot
execute — here an `hlt` instruction in an ET_DYN/ET_EXEC PLT.  The
`UnsupportedInstruction` exception propagates up to the broad `except` at line
303 and is logged as an error.  This aborts the entire PLT pass for that
section even though the rest of the entries were fine.

### Fix
- Catch `envi.exc.UnsupportedInstruction` separately inside the sweep loop,
  log it at debug level, and continue to the next opcode so the remainder of
  the PLT is still analyzed.

## 3. `brflags is BR_DEREF, but loctup is None.  Don't know what to do. skipping.`

**Count observed:** 4 occurrences.

**Message example:**
```
ERROR:vivisect.analysis.elf.elfplt: 0x206aeb6: opval=0x2182008: brflags is BR_DEREF, but loctup is None.  Don't know what to do. skipping.  taint:None ('None')[elfplt.py:analyzeFunction:376]
```

### Root cause
In `analyzeFunction()`, a PLT function's terminating branch is analyzed.  When
a branch has the `BR_DEREF` flag (the target is a pointer) but the referenced
address has **no location** in the workspace **and** no taint value could be
recovered, the code hits an explicitly-marked
`###### TODO: CHECK HERE FOR TAINT VALUE!` edge case.  It logs the condition
at `logger.error()` and `continue`s — i.e. the situation is already *handled*
by skipping, but the diagnostic level is too noisy (error).

### Fix
- Keep the skip behavior (it is correct: a deref with no location and no taint
  is simply not resolvable yet), but log it at **debug** level.  No crash or
  data corruption occurs; the message was incorrectly elevated to error.

## 4. `ERROR:vivisect.analysis.arm.thunk_reg: Error emulating function 0xb5e4`

**Count observed:** 2 occurrences.

### Root cause
`thunk_reg` (ARM PIE-address thunk analysis) spins up an emulator and calls
`emu.runFunction(fva)`.  For functions whose code cannot be faithfully
emulated (hand-written thunks, undefined instructions), `runFunction` raises.
The exception is logged via `logger.exception(...)` at error level, even
though the diagnostic data (`emumon.emuanom`) is already captured and analysis
correctly moves on.

### Fix
- Downgrade the `logger.exception` to `logger.warning`/debug carrying the
  anomaly text, since this is an expected non-fatal condition in thunk
  analysis.  A full exception traceback is not warranted for an expected
  emulation miss.

## Outcome

After the fixes above, a fresh full run (`VIVTESTFILES=../vivtestfiles
python3 -m unittest discover`) still passes all 595 tests
(`OK (skipped=3)`), and the genuine error messages are gone:

| Message | Before | After |
| --- | --- | --- |
| `ERROR:vivisect.analysis.elf.elfplt: analyzePLT(...)` (InvalidFile) | 11 | 0 |
| `analyzePLT(...): Unsupported Instruction: ... hlt` | 2 | 0 |
| `brflags is BR_DEREF, but loctup is None` (analyzeFunction) | 4 | 0 |
| `ERROR:vivisect.analysis.arm.thunk_reg: Error emulating function` | 2 | 0 |

## Notes on messages intentionally left as-is

- **`ERROR:vqt.menubuilder: ActionCall failed ... division by zero`** — this is
  the *intended* behavior of `vqt/tests/test_qt_menubuilder.py`, which
  deliberately registers a lambda that raises `ZeroDivisionError` to verify
  `ActionCall` exception handling.  These messages confirm the error-handling
  path works and must remain.
- **`WARNING:vtrace.breakpoints: Failed to resolve breakpoint address ...`** —
  benign "delayed resolution" message for `libc.*` symbols; the breakpoint is
  resolved on a later pass and the warning is expected.
- **`WARNING:vtrace.platforms.linux: Ignoring invalid thread event tid: None`** —
  normal race during thread attach; not an error.
