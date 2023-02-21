# Instructions
Tested on a fresh Ubuntu 18.04 installation.
```
emwwwc@ubuntu:~/Projects/seccomp$ cat /etc/os-release 
NAME="Ubuntu"
VERSION="18.04.6 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.6 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
```

Python version:
```
user@ubuntu:~/Projects/seccomp$ python3 --version
Python 3.6.9
```

Before installing all the libraries, we need to download everything we will need for it.
```
sudo apt install git
sudo apt install python3
git clone https://github.com/willarderic/seccomp.git
cd seccomp
sudo apt install python3-pip
sudo apt-get install python3-distutils
sudo apt-get install m4
pip3 install pytest
```
## Install pybind11
```
cd pybind11
mkdir build && cd build
cmake ..
make
sudo make install
```
## Install GMP
```
cd gmp-6.2.1
./configure SHARED=on
make
sudo make install
```
## Install NTL
```
cd ntl/src
./configure SHARED=on
make
sudo make install
```
IF THERE IS A VERSION MISMATCH BETWEEN `gmp.h` and `libgmp` just run `sudo ldconfig` in the `ntl/src` directory. [https://stackoverflow.com/questions/50046463/version-number-mismatch-inconsistency-between-gmp-h-and-libgmp](https://stackoverflow.com/questions/50046463/version-number-mismatch-inconsistency-between-gmp-h-and-libgmp)
## HEAAN
HEAAN should already be installed, but if for some reason `./HEAAN/HEAAN/lib/libHEAAN.a` does not exist, you can follow these steps.
```
cd ./HEAAN/HEAAN/lib/
make
```
Will produce `libHEAAN.a`.
## Afterwards
The dependencies will be installed under the directory `/usr/local/`. Run `python3 setup.py build` to build the library. The `.so` file that is created will be in `build/lib.linux*/` directory. Just `mv` it to the directory where it needs to be imported from. The library can then be included in python with `import seccomp`. You may need to set `export LD_LIBRARY_PATH=/usr/local/lib` to find `libntl.so.44`.
