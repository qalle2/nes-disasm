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
    AM_Z,    # zero page
    AM_ZX,   # zero page,x
    AM_ZY,   # zero page,y
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
        "--bank-size", type=int, choices=(256, 512, 1024, 2048, 4096, 8192, 16384, 32768),
        help="Size of PRG ROM banks in bytes. The input file size must be a multiple of this or "
        "equal to this. Default: the greatest common divisor of file size and 32768."
    )
    parser.add_argument(
        "--origin", type=int,
        help="The NES CPU address each PRG ROM bank starts from. Minimum: 32768. Default & "
        "maximum: 65536 minus --bank-size. Must be a multiple of 256."
    )
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
        "input_file",
        help="The PRG ROM file to read. Size: 256 bytes to 4 MiB (4,194,304 bytes) and a multiple "
        "of 256 bytes. (.nes files are not currently supported.)"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        sys.exit("Input file not found.")

    return args

# -------------------------------------------------------------------------------------------------

def get_file_size(handle):
    """Get and validate PRG file size."""

    fileSize = handle.seek(0, 2)
    if fileSize % 256 or not 256 <= fileSize <= 4 * 1024 * 1024:
        sys.exit("The input file size must be 256 bytes to 4 MiB and a multiple of 256 bytes.")
    return fileSize

def get_bank_size(fileSize, args):
    """Get and validate bank size."""

    bankSize = math.gcd(fileSize, 32 * 1024) if args.bank_size is None else args.bank_size
    if fileSize % bankSize:
        sys.exit("File size must a multiple of or equal to bank size.")
    return bankSize

def get_origin(bankSize, args):
    """Get and validate origin."""

    origin = 64 * 1024 - bankSize if args.origin is None else args.origin
    if origin % 256:
        sys.exit("Origin must be a multiple of 256.")
    if not 32 * 1024 <= origin <= 64 * 1024 - bankSize:
        sys.exit("Origin must not be less than 32768 or greater than 65536 minus bank size.")
    return origin

def decode_16bit_address(bytes_):
    """bytes_: 2 bytes, return: 16-bit unsigned int"""

    return bytes_[0] + bytes_[1] * 0x100

def decode_relative_address(base, offset):
    """base: 16-bit unsigned int, offset: 8-bit signed int,
    return: int (may over-/underflow 16-bit unsigned int)"""

    return base + 2 - (offset & 0x80) + (offset & 0x7f)

# -------------------------------------------------------------------------------------------------

def get_instruction_addresses(handle, args):
    """Generate PRG addresses of instructions (where they *are*) from a PRG file.
    handle: file handle, args: from argparse, yield: one int per call"""

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

    def is_valid_instruction(instrBytes, origin, offset, bankSize):
        """Are the bytes a valid combination of opcode + operand?
        instrBytes: 1...3 bytes (may be too short for the operand or contain unnecessary trailing
        bytes), origin: int, offset: int, bankSize: int, return: bool"""

        opcode = instrBytes[0]

        # invalid opcode?
        if opcode not in OPCODES or opcode in noOpcodes:
            return False

        (mnemonic, addrMode) = OPCODES[opcode]

        # not enough space in bank for opcode + operand?
        if bankSize - offset < 1 + ADDRESSING_MODES[addrMode][0]:
            return False

        # if operand is not an address, accept it
        if addrMode in (AM_IMP, AM_AC, AM_IMM):
            return True

        # decode address
        if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
            addr = instrBytes[1]
            if addrMode == AM_R:
                addr = decode_relative_address(offset, addr)
                if 0 <= addr < bankSize:
                    addr += origin
                else:
                    return False  # target in different bank
        else:
            addr = decode_16bit_address(instrBytes[1:3])

        # uses absolute instead of zero page?
        if args.no_absolute_zp \
        and addrMode == AM_AB \
        and mnemonic not in ("jmp", "jsr") \
        and addr <= 0xff:
            return False

        # uses absolute indexed instead of corresponding zero page indexed?
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

    noOpcodes = set(parse_opcode_list(args.no_opcodes))
    noAccess = set(parse_address_ranges(args.no_access))
    noWrite = set(parse_address_ranges(args.no_write))
    noExecute = set(parse_address_ranges(args.no_execute))

    fileSize = get_file_size(handle)
    bankSize = get_bank_size(fileSize, args)
    origin = get_origin(bankSize, args)

    # quite similar to main loops elsewhere
    for (bankIndex, bankAddr) in enumerate(range(0, fileSize, bankSize)):
        handle.seek(bankAddr)
        bankContents = handle.read(bankSize)
        offset = 0  # within bank

        while offset < bankSize:
            # are the next 1...3 bytes a valid opcode and operand?
            if is_valid_instruction(
                bankContents[offset:offset+3], origin, offset, bankSize
            ):
                yield bankAddr + offset
                addrMode = OPCODES[bankContents[offset]][1]
                offset += 1 + ADDRESSING_MODES[addrMode][0]
            else:
                # data
                offset += 1

def get_label_stats(handle, instrAddresses, args):
    """Get addresses and statistics of labels from a PRG file.
    handle: file handle, instrAddresses: set, args: from argparse,
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

    validPRGLabels = set()  # valid addresses for PRG ROM labels (0x8000...0xffff)
    labelStats = {}  # see function description

    fileSize = get_file_size(handle)
    bankSize = get_bank_size(fileSize, args)
    if bankSize < fileSize:
        print("Warning: game uses bankswitching; PRG ROM labels disabled.", file=sys.stderr)
    origin = get_origin(bankSize, args)

    # quite similar to main loops elsewhere, especially in disassemble()
    for (bankIndex, bankAddr) in enumerate(range(0, fileSize, bankSize)):
        handle.seek(bankAddr)
        bankContents = handle.read(bankSize)

        offset = 0  # within bank

        while offset < bankSize:
            validPRGLabels.add(origin + offset)

            if bankAddr + offset in instrAddresses:
                # instruction
                opcode = bankContents[offset]
                (mnemonic, addrMode) = OPCODES[opcode]
                operandSize = ADDRESSING_MODES[addrMode][0]

                if addrMode not in (AM_IMP, AM_AC, AM_IMM):
                    # operand is an address
                    # decode operand
                    if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
                        addr = bankContents[offset+1]
                        if addrMode == AM_R:
                            addr = decode_relative_address(origin + offset, addr)
                    else:
                        addr = decode_16bit_address(bankContents[offset+1:offset+3])

                    # remember access method, first reference and last reference
                    accessMethod = get_access_method(mnemonic, addrMode)
                    referrer = origin + offset
                    if addr in labelStats:
                        labelStats[addr][0].add(accessMethod)
                        labelStats[addr][1] = min(labelStats[addr][1], referrer)
                        labelStats[addr][2] = max(labelStats[addr][2], referrer)
                    else:
                        labelStats[addr] = [set((accessMethod,)), referrer, referrer]

                offset += 1 + operandSize
            else:
                # data
                offset += 1

    # delete invalid PRG ROM labels, or all if game uses bankswitching
    if bankSize < fileSize:
        validPRGLabels.clear()
    return dict(
        (addr, labelStats[addr]) for addr in labelStats if addr <= 0x7fff or addr in validPRGLabels
    )

def create_label_names(labelStats):
    """labelStats: {CPU address:
    [set of access methods, first referring CPU address, last referring CPU address], ...}
    return: {CPU address: name, ...}"""

    labelNames = {}

    # RAM
    RAMLabels = set(addr for addr in labelStats if addr <= 0x1fff)
    # accessed at least once as an array
    addresses = sorted(addr for addr in RAMLabels if ACME_ARRAY in labelStats[addr][0])
    labelNames.update((addr, f"array{i+1}") for (i, addr) in enumerate(addresses))
    # never accessed as an array
    addresses = sorted(addr for addr in RAMLabels if ACME_ARRAY not in labelStats[addr][0])
    labelNames.update((addr, f"ram{i+1}") for (i, addr) in enumerate(addresses))
    del RAMLabels

    # between RAM and PRG ROM
    # hardware registers
    addresses = sorted(set(labelStats) & set(HARDWARE_REGISTERS))
    labelNames.update((addr, HARDWARE_REGISTERS[addr]) for addr in addresses)
    # 0x2000...0x7fff excluding HARDWARE_REGISTERS
    addresses = sorted(
        addr for addr in set(labelStats) - set(HARDWARE_REGISTERS) if 0x2000 <= addr <= 0x7fff
    )
    labelNames.update((addr, f"misc{i+1}") for (i, addr) in enumerate(addresses))

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
    labelNames.update(dict.fromkeys(anonLabelsForwards, "+"))
    labelNames.update(dict.fromkeys(anonLabelsBackwards, "-"))
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
    labelNames.update((addr, f"sub{i+1}") for (i, addr) in enumerate(addresses))
    # other code
    addresses = sorted(
        addr for addr in namedPRGLabels
        if ACME_SUB not in labelStats[addr][0]
        and ACME_CODE in labelStats[addr][0]
    )
    labelNames.update((addr, f"code{i+1}") for (i, addr) in enumerate(addresses))
    # data (almost always arrays)
    addresses = sorted(
        addr for addr in namedPRGLabels
        if ACME_SUB not in labelStats[addr][0]
        and ACME_CODE not in labelStats[addr][0]
    )
    labelNames.update((addr, f"data{i+1}") for (i, addr) in enumerate(addresses))

    return labelNames

def disassemble(handle, instrAddresses, labels, args):
    """Disassemble a PRG file.
    handle: file handle, instrAddresses: set, labels: dict, args: from argparse, return: None"""

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

    def format_asm6_line(label, instruction, operand, comment=""):
        """Format an asm6f line.
        label: str (without trailing colon), instruction: str,
        comment: str (without leading semicolon), return: str"""

        labelFormat = str(INDENT_WIDTH) + "s" if instruction or operand else "s"
        operandSeparator = " " if instruction and operand else ""
        instrFormat = "29s" if (instruction or operand) and comment else "s"

        return "".join((
            format(label, labelFormat),
            format(instruction + operandSeparator + operand, instrFormat),
            "; " if comment else "",
            comment
        ))

    def print_label_counts():
        """Print number of labels by type."""

        cnt = len(labels)
        print(format_asm6_line("", "", "", f"Labels - total        : {cnt}"))
        cnt = len(set(l for l in labels if l <= 0x1fff))
        print(format_asm6_line("", "", "", f"Labels - RAM          : {cnt}"))
        cnt = len(set(l for l in labels if l >= 0x8000))
        print(format_asm6_line("", "", "", f"Labels - PRG ROM      : {cnt}"))
        cnt = len(set(l for l in labels if labels[l] == "+"))
        print(format_asm6_line("", "", "", f'Labels - PRG ROM - "+": {cnt}'))
        cnt = len(set(l for l in labels if labels[l] == "-"))
        print(format_asm6_line("", "", "", f'Labels - PRG ROM - "-": {cnt}'))

    def generate_data_lines(data, addr):
        """Format lines with data bytes.
        data: bytes, addr: int, labels: dict, yield: str"""

        def format_data_line(label, bytes_, addr):
            return format_asm6_line(
                label, "hex", " ".join(f"{byte:02x}" for byte in bytes_), f"{addr:04x}"
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

    def format_operand_value(instrBytes):
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
            addr = decode_relative_address(origin + offset, addr)
        else:
            addr = decode_16bit_address(instrBytes[1:3])
        return labels.get(addr, format_literal(addr, 16))

    fileSize = get_file_size(handle)
    bankSize = get_bank_size(fileSize, args)
    origin = get_origin(bankSize, args)

    print(format_asm6_line("", "", "", f"Input file: {os.path.basename(handle.name)}"))
    print(format_asm6_line("", "", "", f"PRG ROM size: {fileSize} (0x{fileSize:04x})"))
    print(format_asm6_line("", "", "", f"Bank size: {bankSize} (0x{bankSize:04x})"))
    print(format_asm6_line("", "", "", f"Number of banks: {fileSize//bankSize}"))
    print(format_asm6_line(
        "", "", "", f"Bank CPU address: 0x{origin:04x}...0x{origin+bankSize-1:04x}"
    ))
    print(format_asm6_line("", "", "", f"Number of instructions: {len(instrAddresses)}"))
    print_label_counts()
    print()

    print(format_asm6_line("", "", "", "=== RAM labels ($0000...$01fff) ==="))
    print()
    # zero page
    for addr in sorted(l for l in labels if l <= 0xff):
        print(f"{labels[addr]:15s} equ " + format_literal(addr))
    print()
    # other RAM labels
    for addr in sorted(l for l in labels if 0x0100 <= l <= 0x1fff):
        print(f"{labels[addr]:15s} equ " + format_literal(addr, 16))
    print()

    # TODO: create a function for formatting EQU lines

    print(format_asm6_line("", "", "", "=== NES memory-mapped registers ==="))
    print()
    for addr in sorted(HARDWARE_REGISTERS):
        print("{name:11s} equ {addr}".format(
            name=("" if addr in labels else ";") + HARDWARE_REGISTERS[addr],
            addr=format_literal(addr, 16)
        ))
    print()

    print(format_asm6_line(
        "", "", "", "=== Misc labels ($2000...$7fff excluding NES memory-mapped registers) ==="
    ))
    print()
    for addr in sorted(l for l in set(labels) - set(HARDWARE_REGISTERS) if 0x2000 <= l <= 0x7fff):
        print(f"{labels[addr]:15s} equ " + format_literal(addr, 16))
    print()

    # quite similar to main loops elsewhere, especially in get_label_stats()
    for (bankIndex, bankAddr) in enumerate(range(0, fileSize, bankSize)):
        print(format_asm6_line(
            "", "", "",
            f"; === Bank {bankIndex} (PRG ROM 0x{bankAddr:04x}...0x{bankAddr+bankSize-1:04x}) ==="
        ))
        print()
        print(format_asm6_line("", "base", format_literal(origin, 16)))
        print()

        handle.seek(bankAddr)
        bankContents = handle.read(bankSize)

        offset = 0  # within bank
        dataStart = None  # where current string of data bytes started (offsett within bank)

        while offset < bankSize:
            if bankAddr + offset in instrAddresses:
                # instruction

                # print previous data bytes, if any
                if dataStart is not None:
                    for line in generate_data_lines(
                        bankContents[dataStart:offset], origin + dataStart
                    ):
                        print(line)
                    print()
                    dataStart = None

                # get label, if any
                label = labels.get(origin + offset, "")

                opcode = bankContents[offset]
                (mnemonic, addrMode) = OPCODES[opcode]
                (operandSize, operandFormat) = ADDRESSING_MODES[addrMode]

                # get instruction (opcode + operand)
                instrBytes = bankContents[offset:offset+1+operandSize]

                # print instruction line
                operand = operandFormat.format(format_operand_value(instrBytes))
                instrBytesHex = " ".join(f"{byte:02x}" for byte in instrBytes)
                print(format_asm6_line(
                    label, mnemonic, operand, f"{origin+offset:04x}: {instrBytesHex}"
                ))

                # print an empty line after an unconditional control flow instruction
                if mnemonic in ("jmp", "rti", "rts"):
                    print(format_asm6_line("", "", "", ""))

                offset += 1 + operandSize
            else:
                # data

                # start a new data block if not already inside one
                if dataStart is None:
                    dataStart = offset

                offset += 1

        # print last data bytes, if any
        if dataStart is not None:
            for line in generate_data_lines(bankContents[dataStart:offset], origin + dataStart):
                print(line)

        print()

# -------------------------------------------------------------------------------------------------

def main():
    """The main function."""

    args = parse_arguments()

    with open(args.input_file, "rb") as handle:
        instrAddresses = set(get_instruction_addresses(handle, args))
        labelStats = get_label_stats(handle, instrAddresses, args)
        labels = create_label_names(labelStats)
        disassemble(handle, instrAddresses, labels, args)

if __name__ == "__main__":
    main()

