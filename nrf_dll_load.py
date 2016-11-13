import logging
import sys
import ctypes
import os
import platform

logger  = logging.getLogger(__name__)


# TODO: Make sure we only run this code once.

# Load pc_ble_driver
SWIG_MODULE_NAME = "pc_ble_driver"
SHLIB_NAME = "pc_ble_driver_shared"

if getattr(sys, 'frozen', False):
    # we are running in a bundle
    this_dir = sys._MEIPASS
else:
    # we are running in a normal Python environment
    #this_dir, this_file = os.path.split(__file__)
    import pc_ble_driver_py
    this_dir = os.path.dirname(pc_ble_driver_py.__file__)

if sys.maxsize > 2**32:
    shlib_arch = 'x86_64'
else:
    shlib_arch = 'x86_32'

shlib_prefix = ""
if sys.platform.lower().startswith('win'):
    shlib_plat = 'win'
    shlib_postfix = ".dll"
elif sys.platform.lower().startswith('linux'):
    shlib_plat = 'linux'
    shlib_prefix = "lib"
    shlib_postfix = ".so"
elif sys.platform.startswith('dar'):
    shlib_plat = 'macos_osx'
    shlib_prefix = "lib"
    shlib_postfix = ".dylib"
    # OS X uses a single library for both archs
    shlib_arch = ""

shlib_file = '{}{}{}'.format(shlib_prefix, SHLIB_NAME, shlib_postfix)
shlib_dir = os.path.join(os.path.abspath(this_dir), 'lib', shlib_plat, shlib_arch)
shlib_path = os.path.join(shlib_dir, shlib_file)

if not os.path.exists(shlib_path):
    raise RuntimeError('Failed to locate the pc_ble_driver shared library: {}.'.format(shlib_path))

try:
    _shlib = ctypes.cdll.LoadLibrary(shlib_path)
except Exception as error:
    raise RuntimeError("Could not load shared library {} : '{}'.".format(shlib_path, error))

logger.info('Shared library folder: {}'.format(shlib_dir))

sys.path.append(shlib_dir)
import pc_ble_driver as driver
import pc_ble_driver_py.ble_driver_types as util
