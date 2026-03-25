"""Post-install cleanup: remove .py, .c, and .pyc for Cython-compiled modules.

Run after `pip install` in the conda build to ensure only .pyd binaries ship.
"""
import glob
import os
import sysconfig

pkg = os.path.join(sysconfig.get_path("purelib"), "netcapture")

# For every .pyd, delete the matching .py and .c in the same directory
for pyd in glob.glob(os.path.join(pkg, "**", "*.pyd"), recursive=True):
    stem = os.path.join(os.path.dirname(pyd), os.path.basename(pyd).split(".")[0])
    for ext in (".py", ".c"):
        path = stem + ext
        if os.path.exists(path):
            os.remove(path)
            print(f"  removed {os.path.relpath(path, pkg)}")

# Remove .pyc caches for those same modules
for pyc in glob.glob(os.path.join(pkg, "**", "__pycache__", "*.pyc"), recursive=True):
    # e.g. _router.cpython-312.pyc  →  module name = _router
    mod = os.path.basename(pyc).split(".")[0]
    parent = os.path.dirname(os.path.dirname(pyc))  # up from __pycache__
    if glob.glob(os.path.join(parent, mod + ".*.pyd")):
        os.remove(pyc)
        print(f"  removed {os.path.relpath(pyc, pkg)}")
