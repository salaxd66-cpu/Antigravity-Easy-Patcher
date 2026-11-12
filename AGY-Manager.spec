# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import re
import sys


root = Path(SPECPATH)
analysis = Analysis(
    [str(root / 'agy_manager.py')],
    datas=[(str(root / 'assets'), 'assets')],
)
if sys.platform == 'win32':
    # Qt links against Windows ICU. DLLs with the same names discovered on
    # the build machine's PATH may export a different set of symbols.
    icu = re.compile(r'icu(?:uc|in|dt)?\d*\.dll', re.IGNORECASE)
    analysis.binaries = [
        entry for entry in analysis.binaries if not icu.fullmatch(Path(entry[0]).name)
    ]

executable = EXE(
    PYZ(analysis.pure), analysis.scripts, [],
    exclude_binaries=True, name='AGY-Manager', console=False, upx=False,
)
distribution = COLLECT(
    executable, analysis.binaries, analysis.datas, name='AGY-Manager', upx=False,
)
