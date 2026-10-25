"""Ghost Data Still Exists package root.
Supports compatibility with standard library 'code' module when pdb/pytest is imported.
"""

import sys
import importlib.machinery
import importlib.util

# Ensure standard library 'code' attributes remain accessible for pdb/debugging
_stdlib_code = None
for _p in sys.path[1:]:
    try:
        _spec = importlib.machinery.PathFinder.find_spec("code", [_p])
        if _spec and _spec.origin and not _spec.origin.endswith("/code/__init__.py"):
            _mod = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            _stdlib_code = _mod
            break
    except Exception:
        continue

if _stdlib_code:
    InteractiveConsole = getattr(_stdlib_code, "InteractiveConsole", None)
    InteractiveInterpreter = getattr(_stdlib_code, "InteractiveInterpreter", None)
    compile_command = getattr(_stdlib_code, "compile_command", None)
    interact = getattr(_stdlib_code, "interact", None)
