"""NES disassembler."""

import argparse
import math
import os
import sys

INDENT_WIDTH = 8

# enumerate addressing modes
(
    AM_IMP,  # implied
    AM_AC,   # accumulator
    AM_IMM,  # immediate
    AM_Z,    # zeroPage
    AM_ZX,   # zeroPage,x
    AM_ZY,   # zeroPage,y
    AM_IX,   # (indirect,x)
    AM_IY,   # (indirect),y
    AM_R,    # relative
    AM_AB,   # absolute
    AM_ABX,  # absolute,x
    AM_ABY,  # absolute,y
    AM_I,    # (indirect)
) = range(13)

# addressing mode: (operand size, operand format)
ADDRESSING_MODES = {
    AM_IMP: (0, "{}"),
    AM_AC:  (0, "a{}"),
    AM_IMM: (1, "#{}"),
    AM_Z:   (1, "{}"),
    AM_ZX:  (1, "{},x"),
    AM_ZY:  (1, "{},y"),
    AM_IX:  (1, "({},x)"),
    AM_IY:  (1, "({}),y"),
    AM_R:   (1, "{}"),
    AM_AB:  (2, "{}"),
    AM_ABX: (2, "{},x"),
    AM_ABY: (2, "{},y"),
    AM_I:   (2, "({})"),
}

# opcode: (mnemonic, addressing mode)
OPCODES = {
    0x00: ("brk", AM_IMP),
    0x01: ("ora", AM_IX),
    0x05: ("ora", AM_Z),
    0x06: ("asl", AM_Z),
    0x08: ("php", AM_IMP),
    0x09: ("ora", AM_IMM),
    0x0a: ("asl", AM_AC),
    0x0d: ("ora", AM_AB),
    0x0e: ("asl", AM_AB),
    0x10: ("bpl", AM_R),
    0x11: ("ora", AM_IY),
    0x15: ("ora", AM_ZX),
    0x16: ("asl", AM_ZX),
    0x18: ("clc", AM_IMP),
    0x19: ("ora", AM_ABY),
    0x1d: ("ora", AM_ABX),
    0x1e: ("asl", AM_ABX),
    0x20: ("jsr", AM_AB),
    0x21: ("and", AM_IX),
    0x24: ("bit", AM_Z),
    0x25: ("and", AM_Z),
    0x26: ("rol", AM_Z),
    0x28: ("plp", AM_IMP),
    0x29: ("and", AM_IMM),
    0x2a: ("rol", AM_AC),
    0x2c: ("bit", AM_AB),
    0x2d: ("and", AM_AB),
    0x2e: ("rol", AM_AB),
    0x30: ("bmi", AM_R),
    0x31: ("and", AM_IY),
    0x35: ("and", AM_ZX),
    0x36: ("rol", AM_ZX),
    0x38: ("sec", AM_IMP),
    0x39: ("and", AM_ABY),
    0x3d: ("and", AM_ABX),
    0x3e: ("rol", AM_ABX),
    0x40: ("rti", AM_IMP),
    0x41: ("eor", AM_IX),
    0x45: ("eor", AM_Z),
    0x46: ("lsr", AM_Z),
    0x48: ("pha", AM_IMP),
    0x49: ("eor", AM_IMM),
    0x4a: ("lsr", AM_AC),
    0x4c: ("jmp", AM_AB),
    0x4d: ("eor", AM_AB),
    0x4e: ("lsr", AM_AB),
    0x50: ("bvc", AM_R),
    0x51: ("eor", AM_IY),
    0x55: ("eor", AM_ZX),
    0x56: ("lsr", AM_ZX),
    0x58: ("cli", AM_IMP),
    0x59: ("eor", AM_ABY),
    0x5d: ("eor", AM_ABX),
    0x5e: ("lsr", AM_ABX),
    0x60: ("rts", AM_IMP),
    0x61: ("adc", AM_IX),
    0x65: ("adc", AM_Z),
    0x66: ("ror", AM_Z),
    0x68: ("pla", AM_IMP),
    0x69: ("adc", AM_IMM),
    0x6a: ("ror", AM_AC),
    0x6c: ("jmp", AM_I),
    0x6d: ("adc", AM_AB),
    0x6e: ("ror", AM_AB),
    0x70: ("bvs", AM_R),
    0x71: ("adc", AM_IY),
    0x75: ("adc", AM_ZX),
    0x76: ("ror", AM_ZX),
    0x78: ("sei", AM_IMP),
    0x79: ("adc", AM_ABY),
    0x7d: ("adc", AM_ABX),
    0x7e: ("ror", AM_ABX),
    0x81: ("sta", AM_IX),
    0x84: ("sty", AM_Z),
    0x85: ("sta", AM_Z),
    0x86: ("stx", AM_Z),
    0x88: ("dey", AM_IMP),
    0x8a: ("txa", AM_IMP),
    0x8c: ("sty", AM_AB),
    0x8d: ("sta", AM_AB),
    0x8e: ("stx", AM_AB),
    0x90: ("bcc", AM_R),
    0x91: ("sta", AM_IY),
    0x94: ("sty", AM_ZX),
    0x95: ("sta", AM_ZX),
    0x96: ("stx", AM_ZY),
    0x98: ("tya", AM_IMP),
    0x99: ("sta", AM_ABY),
    0x9a: ("txs", AM_IMP),
    0x9d: ("sta", AM_ABX),
    0xa0: ("ldy", AM_IMM),
    0xa1: ("lda", AM_IX),
    0xa2: ("ldx", AM_IMM),
    0xa4: ("ldy", AM_Z),
    0xa5: ("lda", AM_Z),
    0xa6: ("ldx", AM_Z),
    0xa8: ("tay", AM_IMP),
    0xa9: ("lda", AM_IMM),
    0xaa: ("tax", AM_IMP),
    0xac: ("ldy", AM_AB),
    0xad: ("lda", AM_AB),
    0xae: ("ldx", AM_AB),
    0xb0: ("bcs", AM_R),
    0xb1: ("lda", AM_IY),
    0xb4: ("ldy", AM_ZX),
    0xb5: ("lda", AM_ZX),
    0xb6: ("ldx", AM_ZY),
    0xb8: ("clv", AM_IMP),
    0xb9: ("lda", AM_ABY),
    0xba: ("tsx", AM_IMP),
    0xbc: ("ldy", AM_ABX),
    0xbd: ("lda", AM_ABX),
    0xbe: ("ldx", AM_ABY),
    0xc0: ("cpy", AM_IMM),
    0xc1: ("cmp", AM_IX),
    0xc4: ("cpy", AM_Z),
    0xc5: ("cmp", AM_Z),
    0xc6: ("dec", AM_Z),
    0xc8: ("iny", AM_IMP),
    0xc9: ("cmp", AM_IMM),
    0xca: ("dex", AM_IMP),
    0xcc: ("cpy", AM_AB),
    0xcd: ("cmp", AM_AB),
    0xce: ("dec", AM_AB),
    0xd0: ("bne", AM_R),
    0xd1: ("cmp", AM_IY),
    0xd5: ("cmp", AM_ZX),
    0xd6: ("dec", AM_ZX),
    0xd8: ("cld", AM_IMP),
    0xd9: ("cmp", AM_ABY),
    0xdd: ("cmp", AM_ABX),
    0xde: ("dec", AM_ABX),
    0xe0: ("cpx", AM_IMM),
    0xe1: ("sbc", AM_IX),
    0xe4: ("cpx", AM_Z),
    0xe5: ("sbc", AM_Z),
    0xe6: ("inc", AM_Z),
    0xe8: ("inx", AM_IMP),
    0xe9: ("sbc", AM_IMM),
    0xea: ("nop", AM_IMP),
    0xec: ("cpx", AM_AB),
    0xed: ("sbc", AM_AB),
    0xee: ("inc", AM_AB),
    0xf0: ("beq", AM_R),
    0xf1: ("sbc", AM_IY),
    0xf5: ("sbc", AM_ZX),
    0xf6: ("inc", AM_ZX),
    0xf8: ("sed", AM_IMP),
    0xf9: ("sbc", AM_ABY),
    0xfd: ("sbc", AM_ABX),
    0xfe: ("inc", AM_ABX),
}

# NES memory-mapped registers
HARDWARE_REGISTERS = {
    0x2000: "ppu_ctrl",
    0x2001: "ppu_mask",
    0x2002: "ppu_status",
    0x2003: "oam_addr",
    0x2004: "oam_data",
    0x2005: "ppu_scroll",
    0x2006: "ppu_addr",
    0x2007: "ppu_data",
    0x4000: "sq1_vol",
    0x4001: "sq1_sweep",
    0x4002: "sq1_lo",
    0x4003: "sq1_hi",
    0x4004: "sq2_vol",
    0x4005: "sq2_sweep",
    0x4006: "sq2_lo",
    0x4007: "sq2_hi",
    0x4008: "tri_linear",
    0x400a: "tri_lo",
    0x400b: "tri_hi",
    0x400c: "noise_vol",
    0x400e: "noise_lo",
    0x400f: "noise_hi",
    0x4010: "dmc_freq",
    0x4011: "dmc_raw",
    0x4012: "dmc_start",
    0x4013: "dmc_len",
    0x4014: "oam_dma",
    0x4015: "snd_chn",
    0x4016: "joypad1",
    0x4017: "joypad2",
    # http://wiki.nesdev.com/w/index.php/CPU_Test_Mode
    0x4018: "apu_test1",
    0x4019: "apu_test2",
    0x401a: "apu_test3",
    0x401c: "cpu_timer1",
    0x401d: "cpu_timer2",
    0x401e: "cpu_timer3",
    0x401f: "cpu_timer4",
}

# enumerate CDL file chunk types
(
    CDL_UNACCESSED,  # not accessed
    CDL_CODE,        # accessed as code (and possibly also as data)
    CDL_DATA,        # accessed as data only
) = range(3)

# enumerate label access methods
(
    ACME_ARRAY,  # array: zeroPage,x / zeroPage,y / absolute,x / absolute,y
    ACME_SUB,    # subroutine: JSR
    ACME_CODE,   # other code: branch / JMP absolute
    ACME_DATA,   # data: none of the above
) = range(4)

def parse_arguments():
    """Parse command line arguments using argparse.
    return: arguments"""

    parser = argparse.ArgumentParser(description="An NES (6502) disassembler.")

    parser.add_argument(
        "--no-absolute-zp", action="store_true",
        help="Assume the game never accesses zero page using absolute addressing if the "
        "instruction also supports zero page addressing."
    )
    parser.add_argument(
        "--no-absolute-indexed-zp", action="store_true",
        help="Assume the game never accesses zero page using absolute indexed addressing if the "
        "instruction also supports the corresponding zero page indexed addressing mode."
    )
    parser.add_argument(
        "--no-opcodes", type=str, default="",
        help="Assume the game never uses these opcodes. Zero or more opcodes separated by commas. "
        "Each opcode is a hexadecimal integer (00 to ff). Examples: 00 = BRK, 01 = ORA "
        "(indirect,x)."
    )
    parser.add_argument(
        "--no-access", type=str, default="",
        help="Assume the game never accesses (reads/writes/executes) these addresses. Zero or more "
        "ranges separated by commas. Each range consists of two hexadecimal addresses (0000 to "
        "ffff) separated by a hyphen. Examples: 0800-1fff = mirrors of RAM, 2008-3fff = mirrors "
        "of PPU registers, 4020-5fff = beginning of cartridge space, 6000-7fff = PRG RAM."
    )
    parser.add_argument(
        "--no-write", type=str, default="",
        help="Assume the game never writes these addresses (via DEC/INC/ASL/LSR/ROL/ROR/STA/STX/"
        "STY). Same syntax as in --no-access. Example: 8000-ffff = PRG ROM."

    )
    parser.add_argument(
        "--no-execute", type=str, default="",
        help="Assume the game never executes these addresses (via JMP/JSR/branch). Same syntax as "
        "in --no-access. Examples: 0000-1fff = RAM, 2000-401f = memory-mapped registers."
    )
    parser.add_argument(
        "--cdl-file", type=str, default="",
        help="The FCEUX code/data log file (.cdl) to read."
    )
    parser.add_argument(
        "input_file",
        help="The PRG ROM file to read. Maximum size: 32 KiB. (.nes files are not supported.)"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        sys.exit("Input file not found.")

    if args.cdl_file and not os.path.isfile(args.cdl_file):
        sys.exit("CDL file not found.")

    return args

# -------------------------------------------------------------------------------------------------

def read_cdl_file(handle, PRGSize):
    """Read a FCEUX CDL file.
    PRGSize: int, yield: (range_of_PRG_addresses, chunk_type)"""

    if handle.seek(0, 2) < PRGSize:
        sys.exit("The CDL file must be at least as large as the PRG ROM file.")

    handle.seek(0)
    CDLData = handle.read(PRGSize)

    chunkStart = None  # start address of current chunk
    chunkType = CDL_UNACCESSED  # type of current chunk

    for (pos, byte) in enumerate(CDLData):
        if byte & 0b1:
            byteType = CDL_CODE
        elif byte & 0b10:
            byteType = CDL_DATA
        else:
            byteType = CDL_UNACCESSED

        if byteType != chunkType:
            if chunkType != CDL_UNACCESSED:
                # end current chunk
                yield (range(chunkStart, pos), chunkType)
                chunkType = CDL_UNACCESSED
            if byteType != CDL_UNACCESSED:
                # start new chunk
                chunkStart = pos
                chunkType = byteType

    if chunkType != CDL_UNACCESSED:
        # end last chunk
        yield (range(chunkStart, PRGSize), chunkType)

def decode_16bit_address(bytes_):
    """bytes_: 2 bytes, return: 16-bit unsigned int"""

    return bytes_[0] + bytes_[1] * 0x100

def decode_relative_address(base, offset):
    """base: 16-bit unsigned int, offset: 8-bit signed int,
    return: int (may over-/underflow 16-bit unsigned int)"""

    return base + 2 - (offset & 0x80) + (offset & 0x7f)

def get_origin(PRGSize):
    """Get origin CPU address for PRG ROM."""

    return 64 * 1024 - PRGSize

# -------------------------------------------------------------------------------------------------

def get_instruction_address_ranges(handle, CDLData, args):
    """Generate PRG address ranges of instructions from a PRG file.
    handle: file handle, CDLData: {address_range: chunk_type, ...}, args: from argparse,
    yield: one range per call"""

    def parse_opcode_list(arg):
        """Parse a command line argument containing hexadecimal integers.
        arg: str, yield: one int per call"""

        if arg == "":
            return None
        for n in arg.split(","):
            try:
                n = int(n, 16)
                if not 0 <= n <= 0xff:
                    raise ValueError
            except ValueError:
                sys.exit("Invalid opcode.")
            yield n

    def parse_address_ranges(arg):
        """Parse a command line argument containing ranges of hexadecimal addresses.
        arg: str, yield: one range() per call"""

        if arg == "":
            return None
        for range_ in arg.split(","):
            parts = range_.split("-")
            if len(parts) != 2:
                sys.exit("Invalid syntax in address range.")
            try:
                parts = tuple(int(part, 16) for part in parts)
                if not 0 <= parts[0] <= parts[1] <= 0xffff:
                    raise ValueError
            except ValueError:
                sys.exit("Invalid value in address range.")
            yield range(parts[0], parts[1] + 1)

    def is_valid_instruction(instrBytes, PRGAddr):
        """Are the bytes a valid combination of opcode + operand?
        instrBytes: 1...3 bytes (may be too short for the operand or contain unnecessary trailing
        bytes), PRGAddr: int, return: bool"""

        opcode = instrBytes[0]

        # invalid opcode?
        if opcode not in OPCODES or opcode in noOpcodes:
            return False

        (mnemonic, addrMode) = OPCODES[opcode]
        operandSize = ADDRESSING_MODES[addrMode][0]

        # not enough space in PRG ROM for opcode + operand?
        if PRGSize - PRGAddr < 1 + operandSize:
            return False

        # any byte of the instruction flagged as data only?
        if any(
            any(addr in rng for rng in CDLDataOnlyRanges)
            for addr in range(PRGAddr, PRGAddr + 1 + operandSize)
        ):
            return False

        # if operand is not an address, accept it
        if addrMode in (AM_IMP, AM_AC, AM_IMM):
            return True

        # decode address
        if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
            addr = instrBytes[1]
            if addrMode == AM_R:
                addr = decode_relative_address(PRGAddr, addr)
                if 0 <= addr < PRGSize:
                    addr += origin
                else:
                    return False  # target outside PRG ROM
        else:
            addr = decode_16bit_address(instrBytes[1:3])

        # uses absolute instead of zeroPage?
        if args.no_absolute_zp \
        and addrMode == AM_AB \
        and mnemonic not in ("jmp", "jsr") \
        and addr <= 0xff:
            return False

        # uses absolute indexed instead of corresponding zeroPage indexed?
        if args.no_absolute_indexed_zp \
        and (addrMode == AM_ABX or addrMode == AM_ABY and mnemonic == "ldx") \
        and addr <= 0xff:
            return False

        # accesses an excluded address?
        if any(addr in rng for rng in noAccess):
            return False

        # writes an excluded address?
        if mnemonic in ("asl", "dec", "inc", "lsr", "rol", "ror", "sta", "stx", "sty") \
        and addrMode in (AM_Z, AM_ZX, AM_ZY, AM_AB, AM_ABX, AM_ABY) \
        and any(addr in rng for rng in noWrite):
            return False

        # executes an excluded address?
        if (mnemonic in ("jmp", "jsr") and addrMode == AM_AB or addrMode == AM_R) \
        and any(addr in rng for rng in noExecute):
            return False

        return True

    CDLDataOnlyRanges = set(rng for rng in CDLData if CDLData[rng] == CDL_DATA)
    noOpcodes = set(parse_opcode_list(args.no_opcodes))
    noAccess = set(parse_address_ranges(args.no_access))
    noWrite = set(parse_address_ranges(args.no_write))
    noExecute = set(parse_address_ranges(args.no_execute))

    PRGSize = handle.seek(0, 2)
    origin = get_origin(PRGSize)

    handle.seek(0)
    PRGData = handle.read()

    codeStart = None  # start of current code chunk
    pos = 0  # position in PRG data

    # quite similar to main loops elsewhere
    while pos < PRGSize:
        # are the next 1...3 bytes a valid opcode and operand?
        if is_valid_instruction(PRGData[pos:pos+3], pos):
            # instruction
            if codeStart is None:
                # start new code chunk
                codeStart = pos
            addrMode = OPCODES[PRGData[pos]][1]
            pos += 1 + ADDRESSING_MODES[addrMode][0]
        else:
            # data
            if codeStart is not None:
                # end current code chunk
                yield range(codeStart, pos)
                codeStart = None
            pos += 1

    if codeStart is not None:
        # end last code chunk
        yield range(codeStart, PRGSize)

def get_label_stats(handle, instrAddrRanges, args):
    """Get addresses and statistics of labels from a PRG file.
    handle: file handle, instrAddrRanges: set of PRG address ranges, args: from argparse,
    return: {CPU address:
    [set of access methods, first referring CPU address, last referring CPU address], ...}"""

    def get_access_method(mnemonic, addrMode):
        # see enumeration
        if addrMode in (AM_ZX, AM_ZY, AM_ABX, AM_ABY):
            return ACME_ARRAY
        if mnemonic == "jsr":
            return ACME_SUB
        if addrMode == AM_R or mnemonic == "jmp" and addrMode == AM_AB:
            return ACME_CODE
        return ACME_DATA

    instrAddresses = set()  # PRG addresses of instructions
    labelStats = {}  # see function description

    PRGSize = handle.seek(0, 2)
    origin = get_origin(PRGSize)

    handle.seek(0)
    PRGData = handle.read()

    pos = 0  # position in PRG ROM

    # quite similar to main loops elsewhere, especially in disassemble()
    while pos < PRGSize:
        if any(pos in rng for rng in instrAddrRanges):
            # instruction
            instrAddresses.add(pos)

            opcode = PRGData[pos]
            (mnemonic, addrMode) = OPCODES[opcode]
            operandSize = ADDRESSING_MODES[addrMode][0]

            if addrMode not in (AM_IMP, AM_AC, AM_IMM):
                # operand is an address
                # decode operand
                if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
                    addr = PRGData[pos+1]
                    if addrMode == AM_R:
                        addr = decode_relative_address(origin + pos, addr)
                else:
                    addr = decode_16bit_address(PRGData[pos+1:pos+3])

                # remember access method, first reference and last reference
                accessMethod = get_access_method(mnemonic, addrMode)
                referrer = origin + pos
                if addr in labelStats:
                    labelStats[addr][0].add(accessMethod)
                    labelStats[addr][1] = min(labelStats[addr][1], referrer)
                    labelStats[addr][2] = max(labelStats[addr][2], referrer)
                else:
                    labelStats[addr] = [set((accessMethod,)), referrer, referrer]

            pos += 1 + operandSize
        else:
            # data
            pos += 1

    # only keep labels that refer to outside of PRG ROM, to instructions or to data
    return dict(
        (addr, labelStats[addr]) for addr in labelStats
        if addr <= 0x7fff or addr >= origin and (
            addr - origin in instrAddresses
            or not any(addr - origin in rng for rng in instrAddrRanges)
        )
    )

def get_label_names(handle, instrAddrRanges, args):
    """handle: PRG file handle, instrAddrRanges: set of ranges, args: from argparse,
    yield: (CPU_address, name)"""

    labelStats = get_label_stats(handle, instrAddrRanges, args)

    # RAM
    RAMLabels = set(addr for addr in labelStats if addr <= 0x1fff)
    # accessed at least once as an array
    addresses = sorted(addr for addr in RAMLabels if ACME_ARRAY in labelStats[addr][0])
    yield from ((addr, f"array{i+1}") for (i, addr) in enumerate(addresses))
    # never accessed as an array
    addresses = sorted(addr for addr in RAMLabels if ACME_ARRAY not in labelStats[addr][0])
    yield from ((addr, f"ram{i+1}") for (i, addr) in enumerate(addresses))
    del RAMLabels

    # between RAM and PRG ROM
    # hardware registers
    addresses = sorted(set(labelStats) & set(HARDWARE_REGISTERS))
    yield from ((addr, HARDWARE_REGISTERS[addr]) for addr in addresses)
    # 0x2000...0x7fff excluding HARDWARE_REGISTERS
    addresses = sorted(
        addr for addr in set(labelStats) - set(HARDWARE_REGISTERS) if 0x2000 <= addr <= 0x7fff
    )
    yield from ((addr, f"misc{i+1}") for (i, addr) in enumerate(addresses))

    # anonymous PRG ROM labels ("+" or "-")
    # addresses only referred to by branches or direct jumps
    prgCodeLabels = set(
        addr for addr in labelStats
        if addr >= 0x8000 and labelStats[addr][0] == set((ACME_CODE,))
    )
    # look for "+" labels, then "-" labels, then "+" labels again
    anonLabelsForwards = set()
    anonLabelsBackwards = set()
    for rnd in range(2):
        # "+" labels (within forward branch range from all references,
        # no labels except "-" labels in between)
        anonLabelsForwards.update(set(
            addr for addr in prgCodeLabels
            if labelStats[addr][1] + 2 + 127 >= addr
            and labelStats[addr][2] < addr
            and not any(
                labelStats[addr][1] < otherAddr < addr and otherAddr not in anonLabelsBackwards
                for otherAddr in labelStats
            )
        ))
        # break after one and a half rounds
        if rnd == 1:
            break
        # "-" labels (within backward branch range from all references,
        # no labels except "+" labels in between)
        anonLabelsBackwards.update(set(
            addr for addr in prgCodeLabels
            if labelStats[addr][1] >= addr
            and labelStats[addr][2] + 2 - 128 <= addr
            and not any(
                addr < otherAddr < labelStats[addr][2] and otherAddr not in anonLabelsForwards
                for otherAddr in labelStats
            )
        ))
    yield from ((addr, "+") for addr in anonLabelsForwards)
    yield from ((addr, "-") for addr in anonLabelsBackwards)
    del prgCodeLabels

    # named PRG ROM labels
    namedPRGLabels = set(addr for addr in set(labelStats) if addr >= 0x8000) \
    - anonLabelsForwards - anonLabelsBackwards
    del anonLabelsForwards, anonLabelsBackwards
    # subs
    addresses = sorted(
        addr for addr in namedPRGLabels
        if ACME_SUB in labelStats[addr][0]
    )
    yield from ((addr, f"sub{i+1}") for (i, addr) in enumerate(addresses))
    # other code
    addresses = sorted(
        addr for addr in namedPRGLabels
        if ACME_SUB not in labelStats[addr][0]
        and ACME_CODE in labelStats[addr][0]
    )
    yield from ((addr, f"code{i+1}") for (i, addr) in enumerate(addresses))
    # data (almost always arrays)
    addresses = sorted(
        addr for addr in namedPRGLabels
        if ACME_SUB not in labelStats[addr][0]
        and ACME_CODE not in labelStats[addr][0]
    )
    yield from ((addr, f"data{i+1}") for (i, addr) in enumerate(addresses))

def disassemble(handle, CDLData, args):
    """Disassemble a PRG file.
    handle: file handle, CDLData: {PRG_address_range: chunk_type, ...}, args: from argparse,
    return: None"""

    def print_CDL_stats():
        instrByteCnt = sum(len(rng) for rng in CDLData if CDLData[rng] == CDL_CODE)
        dataByteCnt = sum(len(rng) for rng in CDLData if CDLData[rng] == CDL_DATA)
        unaccByteCnt = PRGSize - instrByteCnt - dataByteCnt
        print(f"; CDL file - instruction bytes: {instrByteCnt}")
        print(f"; CDL file - data bytes: {dataByteCnt}")
        print(f"; CDL file - unaccessed bytes: {unaccByteCnt}")

    def format_literal(value, bits=8, base=16):
        """Format an asm6f integer literal.
        value: int, bits: 8/16, base: 2/10/16, return: str"""

        if bits == 16:
            assert 0 <= value <= 0xffff
            if base == 16:
                return f"${value:04x}"
        if bits == 8:
            assert 0 <= value <= 0xff
            if base == 16:
                return f"${value:02x}"
            if base == 10:
                return f"{value:d}"
            if base == 2:
                return f"%{value:08b}"
        assert False

    def generate_data_lines(data, addr):
        """Format lines with data bytes.
        data: bytes, addr: int, labels: dict, yield: str"""

        def format_data_line(label, bytes_, addr):
            return (
                format(label, f"{max(INDENT_WIDTH, len(label) + 1)}s")
                + format("hex " + " ".join(f"{byte:02x}" for byte in bytes_), "29s")
                + f"; {addr:04x}"
            )

        startOffset = 0  # current block
        prevLabel = ""

        for (offset, byte) in enumerate(data):
            label = labels.get(addr + offset, "")
            if label or offset - startOffset == 8:
                # a new block starts; print old one, if any
                if offset > startOffset:
                    yield format_data_line(
                        prevLabel, data[startOffset:offset], addr + startOffset
                    )
                    startOffset = offset
                prevLabel = label

        # print last block, if any
        if len(data) > startOffset:
            yield format_data_line(prevLabel, data[startOffset:], addr + startOffset)

    def format_operand_value(instrBytes, PRGAddr):
        """instrBytes: 1...3 bytes, return: str"""

        (mnemonic, addrMode) = OPCODES[instrBytes[0]]

        if addrMode in (AM_IMP, AM_AC):
            # none
            return ""
        if addrMode == AM_IMM:
            # immediate
            if mnemonic in ("and", "eor", "ora"):
                return format_literal(instrBytes[1], 8, 2)
            if mnemonic in ("cpx", "cpy", "ldx", "ldy"):
                return format_literal(instrBytes[1], 8, 10)
            return format_literal(instrBytes[1])
        if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY):
            # 8-bit address
            addr = instrBytes[1]
            return labels.get(addr, format_literal(addr))
        # relative or 16-bit
        if addrMode == AM_R:
            addr = instrBytes[1]
            addr = decode_relative_address(PRGAddr, addr)
        else:
            addr = decode_16bit_address(instrBytes[1:3])
        return labels.get(addr, format_literal(addr, 16))

    # ranges of PRG addresses
    instrAddrRanges = set(get_instruction_address_ranges(handle, CDLData, args))

    # {CPU_address: name, ...}
    labels = dict(get_label_names(handle, instrAddrRanges, args))

    PRGSize = handle.seek(0, 2)
    origin = get_origin(PRGSize)

    print(f"; Input file: {os.path.basename(handle.name)}")
    print(f"; Bytes: {PRGSize} (0x{PRGSize:04x})")
    instrByteCnt = sum(len(rng) for rng in instrAddrRanges)
    print(f"; Instruction bytes: {instrByteCnt}")
    print(f"; Data bytes: {PRGSize - instrByteCnt}")
    del instrByteCnt
    print(f"; Labels: {len(labels)}")
    print(";")
    print_CDL_stats()
    print()

    print("; === RAM labels ($0000...$01fff) ===")
    print()
    # zeroPage
    for addr in sorted(l for l in labels if l <= 0xff):
        print(f"{labels[addr]:15s} equ " + format_literal(addr))
    print()
    # other RAM labels
    for addr in sorted(l for l in labels if 0x0100 <= l <= 0x1fff):
        print(f"{labels[addr]:15s} equ " + format_literal(addr, 16))
    print()

    print("; === NES memory-mapped registers ===")
    print()
    for addr in sorted(HARDWARE_REGISTERS):
        print("{name:11s} equ {addr}".format(
            name=("" if addr in labels else ";") + HARDWARE_REGISTERS[addr],
            addr=format_literal(addr, 16)
        ))
    print()

    print("; === Misc labels ($2000...$7fff excluding NES memory-mapped registers) ===")
    print()
    for addr in sorted(l for l in set(labels) - set(HARDWARE_REGISTERS) if 0x2000 <= l <= 0x7fff):
        print(f"{labels[addr]:15s} equ " + format_literal(addr, 16))
    print()

    print(f"; === PRG ROM (CPU ${origin:04x}...${origin+PRGSize-1:04x}) ===")
    print()
    print(INDENT_WIDTH * " " + "org " + format_literal(origin, 16))
    print()

    handle.seek(0)
    PRGData = handle.read()

    pos = 0  # position in PRG data
    dataStart = None  # where current string of data bytes started

    # quite similar to main loops elsewhere, especially in get_label_stats()
    while pos < PRGSize:
        if any(pos in rng for rng in instrAddrRanges):
            # instruction

            # print previous data bytes, if any
            if dataStart is not None:
                print()
                for line in generate_data_lines(PRGData[dataStart:pos], origin + dataStart):
                    print(line)
                print()
                dataStart = None

            # get label, if any
            label = labels.get(origin + pos, "")

            opcode = PRGData[pos]
            (mnemonic, addrMode) = OPCODES[opcode]
            (operandSize, operandFormat) = ADDRESSING_MODES[addrMode]

            # get instruction (opcode + operand)
            instrBytes = PRGData[pos:pos+1+operandSize]

            # print instruction line
            operand = operandFormat.format(format_operand_value(instrBytes, origin + pos))
            instrBytesHex = " ".join(f"{byte:02x}" for byte in instrBytes)
            print(
                format(label, f"{max(INDENT_WIDTH, len(label) + 1)}s")
                + format(mnemonic + " " + operand, "29s")
                + f"; {origin+pos:04x}: {instrBytesHex}"
            )

            pos += 1 + operandSize
        else:
            # data

            # start a new data block if not already inside one
            if dataStart is None:
                dataStart = pos

            pos += 1

    # print last data bytes, if any
    if dataStart is not None:
        print()
        for line in generate_data_lines(PRGData[dataStart:], origin + dataStart):
            print(line)

    print()

# -------------------------------------------------------------------------------------------------

def main():
    """The main function."""

    args = parse_arguments()

    try:
        PRGSize = os.path.getsize(args.input_file)
    except OSError:
        sys.exit("Could not get PRG file size.")
    if PRGSize > 32 * 1024:
        sys.exit("The input file must be 32 KiB or less.")

    if args.cdl_file:
        with open(args.cdl_file, "rb") as handle:
            CDLData = dict(read_cdl_file(handle, PRGSize))
    else:
        CDLData = dict()

    with open(args.input_file, "rb") as handle:
        disassemble(handle, CDLData, args)

if __name__ == "__main__":
    main()

