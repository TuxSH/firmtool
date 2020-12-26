#!/usr/bin/env python

__author__    = "TuxSH"
__copyright__ = "Copyright (c) 2017-2020 TuxSH"
__license__   = "BSD"
__version__   = "1.4"

"""
Parses, extracts, and builds 3DS firmware files
"""

from struct import pack, unpack, unpack_from
from binascii import hexlify, unhexlify

import argparse
import sys
import os

# Try to import PyCryptodome
try:
    import Crypto # type: ignore
except ImportError:
    import Cryptodome as Crypto # type: ignore

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# lenny
perfectSignatures = {
    "firm-nand-retail": (
        "B6724531C448657A2A2EE306457E350A10D544B42859B0E5B0BED27534CCCC2A"
        "4D47EDEA60A7DD99939950A6357B1E35DFC7FAC773B7E12E7C1481234AF141B3"
        "1CF08E9F62293AA6BAAE246C15095F8B78402A684D852C680549FA5B3F14D9E8"
        "38A2FB9C09A15ABB40DCA25E40A3DDC1F58E79CEC901974363A946E99B4346E8"
        "A372B6CD55A707E1EAB9BEC0200B5BA0B661236A8708D704517F43C6C38EE956"
        "0111E1405E5E8ED356C49C4FF6823D1219AFAEEB3DF3C36B62BBA88FC15BA864"
        "8F9333FD9FC092B8146C3D908F73155D48BE89D72612E18E4AA8EB9B7FD2A5F7"
        "328C4ECBFB0083833CBD5C983A25CEB8B941CC68EB017CE87F5D793ACA09ACF7"
    ),
    "ncsd-retail": (
        "6CF52F89F378120BFA4E1061D7361634D9A254A4F57AA5BD9F2C30934F0E68CB"
        "E6611D90D74CAAACB6A995565647333DC17092D320131089CCCD6331CB3A595D"
        "1BA299A32FF4D8E5DD1EB46A2A57935F6FE637322D3BC4F67CFED6C2254C089C"
        "62FA11D0824A844C79EE5A4F273D46C23BBBF0A2AF6ACADBE646F46B86D1289C"
        "7FF7E816CFDA4BC33DFF9D175AC69F72406C071B51F45A1ACB87F168C177CB9B"
        "E6C392F0341849AE5D510D26EEC1097BEBFB9D144A1647301BEAF9520D22C55A"
        "F46D49284CC7F9FBBA371A6D6E4C55F1E536D6237FFF54B3E9C11A20CFCCAC0C"
        "6B06F695766ACEB18BE33299A94CFCA7E258818652F7526B306B52E0AED04218"
    ),
    "firm-spi-retail": (
        "37E96B10BAF28C74A710EF35824C93F5FBB341CEE4FB446CE4D290ABFCEFACB0"
        "63A9B55B3E8A65511D900C5A6E9403AAB5943CEF3A1E882B77D2347942B9E9EB"
        "0D7566370F0CB7310C38CB4AC940D1A6BB476BCC2C487D1C532120F1D2A37DDB"
        "3E36F8A2945BD8B16FB354980384998ECC380CD5CF8530F1DAD2FD74BA35ACB9"
        "C9DA2C131CB295736AE7EFA0D268EE01872EF033058ABA07B5C684EAD60D76EA"
        "84A18D866307AAAAB764786E396F2F8B630E60E30E3F1CD8A67D02F0A88152DE"
        "7A9E0DD5E64AB7593A3701E4846B6F338D22FD455D45DF212C5577266AA8C367"
        "AE6E4CE89DF41691BF1F7FE58F2261F5D251DF36DE9F5AF1F368E650D576810B"
    ),
    "firm-nand-dev": (
        "88697CDCA9D1EA318256FCD9CED42964C1E98ABC6486B2F128EC02E71C5AE35D"
        "63D3BF1246134081AF68754787FCB922571D7F61A30DE4FCFA8293A9DA512396"
        "F1319A364968464CA9806E0A52567486754CDDD4C3A62BDCE255E0DEEC230129"
        "C1BAE1AE95D786865637C1E65FAE83EDF8E7B07D17C0AADA8F055B640D45AB0B"
        "AC76FF7B3439F5A4BFE8F7E0E103BCE995FAD913FB729D3D030B2644EC483964"
        "24E0563A1B3E6A1F680B39FC1461886FA7A60B6B56C5A846554AE648FC46E30E"
        "24678FAF1DC3CEB10C2A950F4FFA2083234ED8DCC3587A6D751A7E9AFA061569"
        "55084FF2725B698EB17454D9B02B6B76BE47ABBE206294366987A4CAB42CBD0B"
    ),
    "ncsd-dev": (
        "53CB0E4EB1A6FF84284BE0E7385AB4A686A8BBCBC16102479280E0583655D271"
        "3FE506FAEE74F8D10F1220441CC2FF5D6DDE99BE79C19B386CAF68D5EB8CED1A"
        "AB4D243C5F398680D31CD2E3C9DD5670F2A88D563B8F65F5B234FD2EBB3BE44A"
        "3B6C302722A2ADFB56AE3E1F6417BDEC1E5A86AABBAFBE9419ACA8FDCD45E2CD"
        "F1EB695F6EA87816122D7BE98EEF92C0814B16B215B31D8C813BB355CEA8138F"
        "B3BF2374246842CD91E1F9AAFF76878617CE02064777AEA0876A2C245C784341"
        "CDEE90D691745908A6FF9CE781166796F9F1238F884C84D6F1EEBB2E40B4BCA0"
        "0A7B1E913E0980D29FF6061D8AA944C663F2638127F7CCAB6FC71538471A5138"
    ),
    "firm-spi-dev": (
        "18722BC76DC3602E2C0171F3BCA12AB40EA6D112AEFBECF4BE7A2A58FF759058"
        "A93C95CDA9B3B676D09A4E4C9E842E5C68229A6A9D77FAC76445E78EB5B363F8"
        "C66B166BE65AFAE40A1485A364C2C13B855CEEDE3DFEACEC68DD6B8687DD6DF8"
        "B6D3213F72252E7C03C027EE6079F9C5E0290E5DB8CA0BBCF30FCAD72EB637A1"
        "70C4A2F41D96BF7D517A2F4F335930DC5E9792D78EDFB51DC79AD9D7A4E7F1ED"
        "4D5A5C621B6245A7F1652256011DC32C49B955304A423009E2B78072CEBC12B3"
        "85B72F926F19318D64075F09278FBA8448FD2484B82654A55D064542A8F5D9F9"
        "828CDA5E60D31A40CF8EF18D027310DA4F807988BC753C1EB3B3FC06207E84DE"
    ),
}

secretSectorKey1Key2 = {
    "retail": "07294438F8C97593AA0E4AB4AE84C1D8423F817A235258316E758E3A39432ED0",
    "dev"   : "A2F4003C7A951025DF4E9E74E30C9299FF77A09A9981E948EC51C9325D14EC25",
}

spiCryptoKey = {
    "retail": "07550C970C3DBD9EDDA9FB5D4C7FB713",
    "dev"   : "4DAD2124C2D32973100FBFBD1604C6F1",
}

def keyscrambler(keyX, keyY):
    #http://www.falatic.com/index.php/108/python-and-bitwise-rotation
    rol = lambda val, r_bits, max_bits: \
        (val << r_bits%max_bits) & (2**max_bits-1) | \
        ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
    return rol((rol(keyX, 2, 128) ^ keyY) + 0x1FF9E9AAC5FE0408024591DC5D52768A, 87, 128)

def exportP9(basePath, data):
    if not os.path.isdir(os.path.join(basePath, "modules")):
        os.mkdir(os.path.join(basePath, "modules"))

    pos = data.find(b"Process9") - 0x200

    if pos < 0: return
    size = unpack_from("<I", data, pos + 0x104)[0] * 0x200
    with open(os.path.join(basePath, "modules", "Process9.cxi"), "wb+") as f:
        f.write(data[pos : pos + size])

#
# Copyright (c) 2009 Forest Belton
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

def extractElf(elfFile):
    elfFile.seek(0)
    hdr = elfFile.read(52)

    if len(hdr) != 52:
        raise ValueError("failed to read firm header")

    ident, e_type, machine, version, entry, phoff, shoff, e_flags, ehsize, \
    phentsize, phnum, shentsize, shnum, shstrndx = unpack("<16s2H5I6H", hdr)

    if machine != 40:
        raise ValueError("machine type not Arm")

    if version != 1:
        raise ValueError("invalid ELF version")

    if ehsize != 52:
        raise ValueError("invalid ELF header size")

    if phnum == 0:
        raise ValueError("no program headers")

    elfFile.seek(phoff)
    addr, sz = 0, 0
    datalst = []
    for i in range(phnum):
        elfFile.seek(52 + (i * 32))
        phdr = elfFile.read(32)
        p_type, offset, vaddr, paddr, filesz, memsz, p_flags, p_align = unpack("<8I", phdr)
        if (i == 0 and p_type != 1) or filesz == 0: # not loadable or BSS
            continue

        # Use first found address and read contiguous sections
        if addr == 0:
            addr = paddr
        else:
            if paddr != addr + sz:
                continue

        elfFile.seek(offset)
        pdata = elfFile.read(filesz)
        if len(pdata) != filesz:
            raise ValueError("failed to read program header segment")
        datalst.append(pdata)
        datalst.append(b'\x00' * (memsz - filesz))

        sz += memsz

    return entry, addr, b''.join(datalst)

class FirmSectionHeader(object):
    def check(self):
        if self.copyMethod == 0 and (1 << 20) > self.size >= 0x800+0xA00 and self.address == 0x08006000:
            if self.sectionData[0x50 : 0x53] == b"K9L":
                self.guessedType = self.sectionData[0x50 : 0x54].decode("ascii")
            elif self.sectionData[0x50 : 0x54] == b"\xFF\xFF\xFF\xFF":
                self.guessedType = "K9L0"
        elif self.copyMethod == 0 and (1 << 20) > self.size >= 0xA00 and self.address == 0x08006800:
            self.guessedType = "Kernel9"
        elif self.copyMethod == 1 and self.size >= 0xA00:
            if self.sectionData[0x100 : 0x104] == b"NCCH":
                self.guessedType = "Kernel11 modules"

        hash = SHA256.new(self.sectionData).digest()
        self.hashIsValid = self.hash == hash

    def doNtrCrypto(self, encrypt = True):
        iv = pack("<4I", self.offset, self.address, self.size, self.size)
        key = unhexlify(spiCryptoKey.get(self.kind.split('-')[-1], "retail"))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(self.sectionData) if encrypt else cipher.decrypt(self.sectionData)

    def __init__(self, n, kind = "nand-retail", data = None):
        self.num = n
        hdrData = b'\x00'* 0x30 if data is None else data[0x40 + 0x30 * n : 0x40 + 0x30 * (n + 1)]
        self.offset, self.address, self.size, self.copyMethod, self.hash = unpack("<4I32s", hdrData)
        self.sectionData = b'' if self.size == 0 else data[self.offset : self.offset + self.size]
        self.guessedType = ''
        self.hashIsValid = True
        self.kind = kind
        if not (data is None):
            if self.kind in ("spi-retail", "spi-dev"):
                self.sectionData = self.doNtrCrypto(False)
            self.check()

    def setData(self, data):
        self.sectionData = data + b'\xFF' *  ((512 - (len(data) % 512)) % 512)
        self.size = len(self.sectionData)
        self.guessedType = ''
        self.hashIsValid = True

        self.hash = SHA256.new(self.sectionData).digest()

    def buildHeader(self):
        return pack("<4I32s", self.offset, self.address, self.size, self.copyMethod, self.hash)

    def export(self, basePath, extractModules = False, secretSector = None):
        if self.guessedType == "Kernel11 modules" and extractModules:
            pos = 0

            if not os.path.isdir(os.path.join(basePath, "modules")):
                os.mkdir(os.path.join(basePath, "modules"))
            while pos < self.size:
                size = unpack_from("<I", self.sectionData, pos + 0x104)[0] * 0x200
                name = self.sectionData[pos + 0x200: pos + 0x208].decode("ascii")
                nullBytePos = name.find('\x00')
                name = name if nullBytePos == -1 else name[:nullBytePos]
                name = "{0}.cxi".format(name)
                with open(os.path.join(basePath, "modules", name), "wb+") as f:
                    f.write(self.sectionData[pos : pos + size])
                pos += size

            with open(os.path.join(basePath, "section{0}.bin".format(self.num)), "wb+") as f:
                f.write(self.sectionData)

        elif self.guessedType.startswith("K9L") and secretSector is not None:
            # kek is in keyslot 0x11, as "normal key"
            encKeyX = self.sectionData[:0x10] if self.guessedType[3] == '0' else self.sectionData[0x60 : 0x70]
            kek = secretSector[:0x10] if self.guessedType[3] != '2' else secretSector[0x10 : 0x20]

            keyX = AES.new(kek, AES.MODE_ECB).decrypt(encKeyX)
            keyY = self.sectionData[0x10 : 0x20]
            key = unhexlify("{0:032X}".format(keyscrambler(int(hexlify(keyX), 16), int(hexlify(keyY), 16))))

            ctr = self.sectionData[0x20 : 0x30]
            sizeDec = self.sectionData[0x30 : 0x38].decode("ascii")
            size = int(sizeDec[:sizeDec.find('\x00')], 10)

            data = self.sectionData
            if 0x800 + size <= self.size:
                cipher = AES.new(key, AES.MODE_CTR, initial_value=ctr, nonce=b'')
                decData = cipher.decrypt(self.sectionData[0x800 : 0x800 + size])
                data = b''.join((self.sectionData[:0x800], decData, self.sectionData[0x800+size:]))
                if extractModules:
                    exportP9(basePath, data)

            with open(os.path.join(basePath, "section{0}.bin".format(self.num)), "wb+") as f:
                f.write(data)

        elif self.guessedType == "Kernel9":
            if extractModules:
                exportP9(basePath, self.sectionData)

            with open(os.path.join(basePath, "section{0}.bin".format(self.num)), "wb+") as f:
                f.write(self.sectionData)

        else:
            with open(os.path.join(basePath, "section{0}.bin".format(self.num)), "wb+") as f:
                f.write(self.sectionData)

    def __str__(self):
        types = ("NDMA", "XDMA", "memcpy")
        return """Copy type:\t{0}{1}
Offset:\t\t0x{2:08X}{3}
Address:\t0x{4:08X}
Size:\t\t0x{5:08X}
Hash:\t\t{6:032X}{7}""".format(types[self.copyMethod] if 0 <= self.copyMethod <= 2 else "invalid ({0})".format(self.copyMethod),
        "\nGuessed type:\t{0}".format(self.guessedType) if self.guessedType else "",
        self.offset, "" if self.offset >= 0x200 else "invalid", self.address, self.size, int(hexlify(self.hash), 16), " (invalid)" if not self.hashIsValid else "")


class Firm(object):
    def check(self):
        self.arm11EntrypointFound, self.arm9EntrypointFound = False, False
        for i in range(4):
            sec = self.sections[i]
            if sec.address <= self.arm11Entrypoint < sec.address + sec.size:
                self.arm11EntrypointFound = True
            if sec.address <= self.arm9Entrypoint < sec.address + sec.size:
                self.arm9EntrypointFound = True
            sec.check()

    def export(self, basePath, exportModules = False, secretSector = None):
        for i in range(4):
            if self.sections[i].size != 0:
                self.sections[i].export(basePath, exportModules, secretSector)

    def __init__(self, kind = "nand-retail", data = None):
        self.kind = kind
        if data is None:
            self.priority, self.arm11Entrypoint, self.arm9Entrypoint = 0, 0, 0
            self.sections = [FirmSectionHeader(i, kind) for i in range(4)]
            self.reserved, self.signature = b'\x00'* 0x30, b'\x00'* 0x100
        else:
            if data[:4] != b"FIRM":
                raise ValueError("Not a FIRM file")

            self.priority, self.arm11Entrypoint, self.arm9Entrypoint, self.reserved = unpack_from("<3I48s", data, 4)
            self.sections = [FirmSectionHeader(i, kind, data) for i in range(4)]
            self.signature = data[0x100 : 0x200]
            self.check()

    def setSectionData(self, n, data):
        self.sections[n].setData(data)

        off = 0x200
        for i in range(4):
            if self.sections[i].size != 0:
                self.sections[i].offset = off
                off += self.sections[i].size

    def build(self):
        hdr1 = pack("<3I48s", self.priority, self.arm11Entrypoint, self.arm9Entrypoint, self.reserved)
        hdr2 = b''.join(self.sections[i].buildHeader() for i in range(4))
        secs = b''.join((self.sections[i].doNtrCrypto() if self.kind in ("spi-retail", "spi-dev") else self.sections[i].sectionData) for i in range(4))
        return b''.join((b"FIRM", hdr1, hdr2, self.signature, secs))

    def __str__(self):
        hdr = """Priority:\t\t{0}

Arm9 entrypoint:\t0x{1:08X}{2}
Arm11 entrypoint:\t0x{3:08X}{4}

RSA-2048 signature:\t{5:0256X}

""".format(self.priority, self.arm9Entrypoint, " (invalid)" if not self.arm9EntrypointFound else "",
                   self.arm11Entrypoint, " (invalid)" if not (self.arm11Entrypoint == 0 or self.arm11EntrypointFound) else "", int(hexlify(self.signature), 16))

        #fmt_section = lambda n: "Section {0}:\n{1}".format(n), str(self.sections[n])))
        secs = '\n\n'.join("Section {0}:\n{1}".format(i, ''.join('\t' + l for l in str(self.sections[i]).splitlines(True)))
                for i in range(4) if self.sections[i].size != 0)
        return hdr+secs


def parseFirm(args):
    print(Firm(args.type if args.type else "nand-retail", args.infile.read()))

def extractFirm(args):
    keys = secretSectorKey1Key2.get(args.type.split('-')[-1], "retail") if args.secret_sector is None else args.secret_sector.read()
    firmObj = Firm(args.type if args.type else "nand-retail", args.infile.read())
    firmObj.export(args.outdir, args.export_modules, unhexlify(keys))

def buildFirm(args):
    if not (len(args.section_data) == len(args.section_copy_methods)):
        raise ValueError("number of sections not matching")
    elif len(args.section_addresses) > 4 or len(args.section_data) > 4 or len(args.section_copy_methods) > 4:
        raise ValueError("too many sections")

    if (not args.signature) and args.type:
        args.signature = args.type

    addrpos = 0

    firmObj = Firm(args.signature) if args.signature else Firm()

    firmObj.arm9Entrypoint = args.arm9_entrypoint
    firmObj.arm11Entrypoint = args.arm11_entrypoint

    arm11Flags = 0
    if args.suggest_screen_init:
        arm11Flags |= 1

    if args.suggest_skipping_bootrom_lockout:
        arm11Flags |= 2

    firmObj.reserved = unhexlify("{0:02x}".format(arm11Flags)) + firmObj.reserved[1:]

    for i in range(len(args.section_copy_methods)):
        magic = args.section_data[i].read(4)
        args.section_data[i].seek(0)

        if len(magic) == 4 and magic == b"\x7FELF":
            entry, firmObj.sections[i].address, data = extractElf(args.section_data[i])
            firmObj.sections[i].copyMethod = ("NDMA", "XDMA", "memcpy").index(args.section_copy_methods[i])
            firmObj.arm9Entrypoint = entry if firmObj.arm9Entrypoint == 0 and args.section_copy_methods[i] == "NDMA" else firmObj.arm9Entrypoint
            firmObj.arm11Entrypoint = entry if firmObj.arm11Entrypoint == 0 and args.section_copy_methods[i] == "XDMA" else firmObj.arm11Entrypoint
            firmObj.setSectionData(i, data)
        else:
            if addrpos >= len(args.section_addresses):
                raise argparse.ArgumentError("missing section addresses")
            firmObj.sections[i].address = args.section_addresses[addrpos]
            firmObj.sections[i].copyMethod = ("NDMA", "XDMA", "memcpy").index(args.section_copy_methods[i])
            firmObj.setSectionData(i, args.section_data[i].read())
            addrpos += 1

    firmObj.check()
    if not firmObj.arm9EntrypointFound:
        raise ValueError("invalid or missing Arm9 entrypoint")

    if not (firmObj.arm11Entrypoint == 0 or firmObj.arm11EntrypointFound):  # bootrom / FIRM won't boot firms with a NULL arm11 ep, though
        raise ValueError("invalid or missing Arm11 entrypoint")

    if args.signature:
        firmObj.signature = unhexlify(perfectSignatures["firm-" + args.signature])
    data = firmObj.build()
    args.outfile.write(data)
    if args.generate_hash:
        with open(args.outfile.name + ".sha", "wb+") as f:
            f.write(SHA256.new(data).digest())

def Uint32(s):
    N = 0
    try:
        N = int(s, base=0)
    except:
        raise argparse.ArgumentTypeError("invalid unsigned 32-bit integer")

    if not(0 <= int(N) < 2**32):
        raise argparse.ArgumentTypeError("invalid unsigned 32-bit integer")
    return N

def main(args=None):
    parser = argparse.ArgumentParser(prog="firmtool", description="Parses, extracts, and builds 3DS firmware files.")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)
    subparsers = parser.add_subparsers(help="sub-command help")

    parser_parse = subparsers.add_parser("parse")
    parser_parse.set_defaults(func=parseFirm)
    parser_parse.add_argument("infile", type=argparse.FileType("rb"))
    parser_parse.add_argument("-t", "--type", help="The kind of FIRM to assume (default: nand-retail)", choices=("nand-retail", "spi-retail", "nand-dev", "spi-dev"), default="nand-retail")

    parser_extract = subparsers.add_parser("extract")
    parser_extract.set_defaults(func=extractFirm)
    parser_extract.add_argument("infile", help="Input firmware file", type=argparse.FileType("rb"))
    parser_extract.add_argument("outdir", help="Output directory (current directory by default)", nargs='?', default='.')
    parser_extract.add_argument("-t", "--type", help="The kind of FIRM to assume (default: nand-retail)", choices=("nand-retail", "spi-retail", "nand-dev", "spi-dev"), default="nand-retail")
    parser_extract.add_argument("-m", "--export-modules", help="Export k11 modules and Process9 (when applicable and if possible)",
                                action="store_true")
    parser_extract.add_argument("-s", "--secret-sector", help="Path to decrypted secret sector, to decrypt the arm9 binary with (when applicable) (optional, keys are harcoded)",
                                type=argparse.FileType("rb"))

    parser_build = subparsers.add_parser("build")
    parser_build.set_defaults(func=buildFirm)
    parser_build.add_argument("outfile", help="Output firmware file", type=argparse.FileType("wb+"))
    parser_build.add_argument("-n", "--arm9-entrypoint", help="Arm9 entrypoint (deduced from the first ELF file having an entrypoint and corresponding to a NDMA-copied \
    section, otherwise required)", type=Uint32, default=0) # "nine"
    parser_build.add_argument("-e", "--arm11-entrypoint", help="Arm11 entrypoint (deduced from the first ELF file having and entrypoint and corresponding to a XDMA-copied \
    section, otherwise required)", type=Uint32, default=0) # "eleven"
    parser_build.add_argument("-D", "--section-data", help="Files containing the data of each section (required)", type=argparse.FileType("rb"), nargs='+', required=True)
    parser_build.add_argument("-A", "--section-addresses", help="Loading address of each section (inferred from the corresponding ELF file, otherwise required)",
    type=Uint32, nargs='+', default=[])
    parser_build.add_argument("-C", "--section-copy-methods", help="Copy method of each section (NDMA, XDMA, memcpy) (required)", choices=("NDMA", "XDMA", "memcpy"), nargs='+', required=True)
    parser_build.add_argument("-S", "--signature", "-t", "--type", help="The kind of the perfect signature to include (default: nand-retail)", choices=("nand-retail", "spi-retail", "nand-dev", "spi-dev"), default="nand-retail")
    parser_build.add_argument("-g", "--generate-hash", help="Generate a .sha file containing the SHA256 digest of the output file", action="store_true", default=False)
    parser_build.add_argument("-i", "--suggest-screen-init", help="Suggest that screen init should be done before launching the output file", action="store_true", default=False)
    parser_build.add_argument("-b", "--suggest-skipping-bootrom-lockout", help="Suggest skipping bootrom lockout", action="store_true", default=False)

    args = parser.parse_args()

    # http://bugs.python.org/issue16308 it's still not fixed, WTF are they doing ?!
    try:
        getattr(args, "func")
    except AttributeError:
        parser.print_help()
        sys.exit(0)

    args.func(args)

if __name__ == "__main__":
    main()
