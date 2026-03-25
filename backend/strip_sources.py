"""Post-install cleanup: remove .py, .c, and .pyc for Cython-compiled modules.

Run after `pip install` in the conda build to ensure only native binaries ship.
Works on all platforms: .pyd (Windows), .so (Linux/macOS).
"""
import glob
import os
import sysconfig

pkg = os.path.join(sysconfig.get_path("purelib"), "netcapture")

# Native extension suffix is platform-dependent: .pyd on Windows, .so on Linux/macOS
ext_suffixes = ("*.pyd", "*.so")

# For every native extension, delete the matching .py and .c in the same directory
for suffix in ext_suffixes:
    for ext_file in glob.glob(os.path.join(pkg, "**", suffix), recursive=True):
        stem = os.path.join(os.path.dirname(ext_file), os.path.basename(ext_file).split(".")[0])
        for src_ext in (".py", ".c"):
            path = stem + src_ext
            if os.path.exists(path):
                os.remove(path)
                print(f"  removed {os.path.relpath(path, pkg)}")

# Remove .pyc caches for those same modules
for pyc in glob.glob(os.path.join(pkg, "**", "__pycache__", "*.pyc"), recursive=True):
    mod = os.path.basename(pyc).split(".")[0]
    parent = os.path.dirname(os.path.dirname(pyc))  # up from __pycache__
    has_native = any(
        glob.glob(os.path.join(parent, mod + pat))
        for pat in (".*.pyd", ".*.so")
    )
    if has_native:
        os.remove(pyc)
        print(f"  removed {os.path.relpath(pyc, pkg)}")
