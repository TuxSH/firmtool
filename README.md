# firmtool
A tool to parse, extract, and build 3DS firmware files.

Compatible with Python >= 3.2 and Python >= 2.7.

## Installation

On Windows, install Python >= 3.4 using the installer provided by the official Python website. Make sure that `pip` is in `PATH`.

On *ix, install the corresponding packages, they should be named `python`, `python-setuptools`, `python-pip` or similar. You may need to upgrade `pip`.

The preferred way to install and update firmtool is to run `pip install -U git+https://github.com/TuxSH/firmtool.git` directly (with the appropriate permissions), although `python setup.py install` should work as well.

`firmtool` depends on `pycryptodome` (either as `Crypto` or `Cryptodome`), old `pycrypto` will not work.

## Usage
Showing information about a firmware binary:
```
firmtool parse the.firm
```

Extracting a firmware binary, with decryption of the arm9bin and extraction of the k11 modules as well as Process9 (by default type `nand-retail` is assumed, if it's not the case use `-t`):
```
firmtool extract -m native.firm
```

Same as above plus using `ctrtool` and the shell to extract the code of each module
```bash
#!/bin/bash

firmtool extract -m native.firm
cd modules
for f in *.cxi
do
    ctrtool -p --exefs=exefs.bin $f

    if [ $f = "Process9.cxi" ]
    then
        ctrtool -t exefs --exefsdir=exefs exefs.bin > /dev/null
    else
        ctrtool -t exefs --exefsdir=exefs --decompresscode exefs.bin > /dev/null
    fi

    cp exefs/code.bin $(basename -s .cxi $f).bin
    rm -rf exefs
done
cd ..
```


Building a firmware binary (for example with two sections, an Arm9 and and Arm11 one, with the entrypoints at the start of the respective sections):

```bash
firmtool build test.firm -n 0x08006800 -e 0x1FF80000 -D arm9.bin arm11.bin -A 0x08006800 0x1FF80000 -C NDMA XDMA
```

Building a firmware binary from an arm9loaderhax.bin payload which doesn't use the Arm11, with a loader supporting the Arm11 entrypoint being 0:

```bash
firmtool build test.firm -n 0x23F00000 -e 0 -D arm9loaderhax.bin -A 0x23F00000 -C NDMA
```

You may also use ELF files, in this case the entrypoint for the given processor is deduced automatically, when applicable (using the first NDMA FIRM section for arm9, and the first XDMA FIRM section for arm11), as well as the addresses of such FIRM sections (using the first loadable ELF sections, and assuming contiguity).
