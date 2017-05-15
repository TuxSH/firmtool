# firmtool
A tool to parse, extract, and build 3DS firmware files.

Compatible with Python >= 3.2 and Python >= 2.7.
## Usage
Showing information about a firmware binary:
```
firmtool parse firm.bin
```

Basic extraction of a firmware binary:
```
firmtool extract firm.bin
```

Extracting a firmware binary, with decryption of the arm9bin and extraction of the k11 modules as well as Process9:
```
firmtool extract -m -s secret_sector.bin firm.bin
```

Same as above plus using `ctrtool` and the shell to extract the code of each module
```bash
#!/bin/bash

firmtool extract -m -s secret_sector.bin firm.bin
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


Building a firmware binary (for example with two sections, an ARM9 and and ARM11 one, with the entrypoints at the start of the respective sections):
```
firmtool build firmtest.bin -n 0x08006800 -e 0x1FF80000 -D arm9.bin arm11.bin -A 0x08006800 0x1FF80000 -C NDMA XDMA
```

You may also use ELF files, in this case the entrypoint for the given processor is deduced automatically, when applicable (using the first NDMA FIRM section for arm9, and the first XDMA FIRM section for arm11), as well as the addresses of such FIRM sections (using the first loadable ELF sections, and assuming contiguity).

## Installation

On Windows, install Python >= 3.4 using the installer provided by the official Python website. Make sure that `pip` is in `PATH` then run `pip install pycrypto`.

On *ix, install the corresponding packages, they should be named `python`, `python-setuptools`, `python-pip`, `python-crypto` or similar.

In either case, run `python setup.py install` with the correct permissions. 
