"""
Cython-compiled build of netcapture.

When Cython is available (conda build), implementation modules are compiled to
native .pyd/.so extensions.  Without Cython (pip install -e .), falls back to
a normal pure-Python install for development.
"""

import os
import warnings

# Suppress setuptools' "Package X is absent from packages configuration" warnings.
# These fire during build-backend discovery before setup() runs, so our explicit
# packages list can't prevent them. The build works correctly regardless.
warnings.filterwarnings("ignore", message=r"Package '.*' is absent")

from setuptools import setup

# Modules that contain implementation logic — compiled to native extensions.
# Public API stubs (__init__.py, __main__.py) stay as readable Python.
_COMPILE = [
    "netcapture/_router.py",
    "netcapture/_manager.py",
    "netcapture/_filter.py",
    "netcapture/capture.py",
    "netcapture/capture_scapy.py",
    "netcapture/pcap_io.py",
    "netcapture/profiles.py",
    "netcapture/watchlists.py",
    "netcapture/interpreters/nc_frame.py",
]

try:
    from Cython.Build import cythonize
    from setuptools.extension import Extension

    extensions = []
    for path in _COMPILE:
        if os.path.exists(path):
            modname = path.replace(os.sep, "/").replace("/", ".").removesuffix(".py")
            extensions.append(Extension(modname, [path]))

    ext_modules = cythonize(
        extensions,
        compiler_directives={"language_level": "3"},
    )
except ImportError:
    ext_modules = []

setup(
    packages=["netcapture", "netcapture.interpreters"],
    package_data={"netcapture": ["static/**/*"]},
    ext_modules=ext_modules,
)
