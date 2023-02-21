from distutils.core import setup, Extension
from distutils import sysconfig

cfg_vars = sysconfig.get_config_vars()
for key, value in cfg_vars.items():
    if type(value) == str:
        cfg_vars[key] = value.replace('-Wstrict-prototypes', '')

cpp_args = ['-std=c++11']

# !!!!!!!!!!!!!
# !! NEED TO SET LD_LIBRARY_PATH=/usr/local/lib
# !! FOR IMPORTING TO WORK AFTER COMPILATION

ext_modules = [
    Extension(
        'seccomp',
        ['seccomp.cpp'],
        include_dirs=['./ntl/include', './HEAAN/HEAAN/src'],
        language='c++',
        extra_compile_args=cpp_args,
        extra_objects=['/usr/local/lib/libntl.so.44', '/usr/local/lib/libntl.so', './HEAAN/HEAAN/lib/libHEAAN.a'], # both lib need compiled with -fPIC
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
