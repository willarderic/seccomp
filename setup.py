from distutils.core import setup, Extension
from distutils import sysconfig

cfg_vars = sysconfig.get_config_vars()
for key, value in cfg_vars.items():
    if type(value) == str:
        cfg_vars[key] = value.replace('-Wstrict-prototypes', '')

cpp_args = ['-std=c++11']

#g++ -shared test.cpp /home/eric/Projects/research/HEAAN/HEAAN/lib/libHEAAN.a /usr/local/lib/libntl.so -o comparison.cpython-38-x86_64-linux-gnu.so  -fPIC -std=c++11 -O2 -I/home/eric/Projects/research/HEAAN/HEAAN/src -I/usr/include/python3.8 -I/home/eric/.local/lib/python3.8/site-packages/pybind11/include

# !!!!!!!!!!!!!
# !! NEED TO SET LD_LIBRARY_PATH=/usr/local/lib
# !! FOR IMPORTING TO WORK AFTER COMPILATION
# HAVE TO COMPILE NTL WITH -fPIC, or set SHARED=ON for the ./configure script

ext_modules = [
    Extension(
        'seccomp',
        ['seccomp.cpp'],
        include_dirs=['/usr/include/python3.8', '/home/eric/.local/lib/python3.8/site-packages/pybind11/include', './HEAAN/HEAAN/src'],
        language='c++',
        extra_compile_args=cpp_args,
        extra_objects=['./ntl/lib/libntl.so', './ntl/lib/libntl.so.44', './HEAAN/HEAAN/lib/libHEAAN.a'], # both lib need compiled with -fPIC
        extra_link_args=['-Wl,-rpath,$ORIGIN' ],
    ),
]

setup(
    name='seccomp',
    version='1.0.0',
    author='Eric', 
    author_email='emwwwc@umsystem.edu',
    description='Comparison of numbers using HEAAN',
    url='',
    license='MIT',
    ext_modules=ext_modules,
)