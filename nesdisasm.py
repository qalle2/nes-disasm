"""NES disassembler."""

import argparse
import math
import os
import sys

# addressing modes
ADDR_MODES = {
    "imp": {"operandSize": 0, "prefix": "",  "suffix": ""},     # implied
    "ac":  {"operandSize": 0, "prefix": "a", "suffix": ""},     # accumulator
    "imm": {"operandSize": 1, "prefix": "#", "suffix": ""},     # immediate
    "zp":  {"operandSize": 1, "prefix": "",  "suffix": ""},     # zero page
    "zpx": {"operandSize": 1, "prefix": "",  "suffix": ",x"},   # zero page,x
    "zpy": {"operandSize": 1, "prefix": "",  "suffix": ",y"},   # zero page,y
    "idx": {"operandSize": 1, "prefix": "(", "suffix": ",x)"},  # (indirect,x)
    "idy": {"operandSize": 1, "prefix": "(", "suffix": "),y"},  # (indirect),y
    "re":  {"operandSize": 1, "prefix": "",  "suffix": ""},     # relative
    "ab":  {"operandSize": 2, "prefix": "",  "suffix": ""},     # absolute
    "abx": {"operandSize": 2, "prefix": "",  "suffix": ",x"},   # absolute,x
    "aby": {"operandSize": 2, "prefix": "",  "suffix": ",y"},   # absolute,y
    "id":  {"operandSize": 2, "prefix": "(", "suffix": ")"},    # indirect
}

# addressing modes: as above
INSTRUCTIONS = {
    0x00: {"mnemonic": "brk", "addrMode": "imp"},
    0x01: {"mnemonic": "ora", "addrMode": "idx"},
    0x05: {"mnemonic": "ora", "addrMode": "zp"},
    0x06: {"mnemonic": "asl", "addrMode": "zp"},
    0x08: {"mnemonic": "php", "addrMode": "imp"},
    0x09: {"mnemonic": "ora", "addrMode": "imm"},
    0x0a: {"mnemonic": "asl", "addrMode": "ac"},
    0x0d: {"mnemonic": "ora", "addrMode": "ab"},
    0x0e: {"mnemonic": "asl", "addrMode": "ab"},
    0x10: {"mnemonic": "bpl", "addrMode": "re"},
    0x11: {"mnemonic": "ora", "addrMode": "idy"},
    0x15: {"mnemonic": "ora", "addrMode": "zpx"},
    0x16: {"mnemonic": "asl", "addrMode": "zpx"},
    0x18: {"mnemonic": "clc", "addrMode": "imp"},
    0x19: {"mnemonic": "ora", "addrMode": "aby"},
    0x1d: {"mnemonic": "ora", "addrMode": "abx"},
    0x1e: {"mnemonic": "asl", "addrMode": "abx"},
    0x20: {"mnemonic": "jsr", "addrMode": "ab"},
    0x21: {"mnemonic": "and", "addrMode": "idx"},
    0x24: {"mnemonic": "bit", "addrMode": "zp"},
    0x25: {"mnemonic": "and", "addrMode": "zp"},
    0x26: {"mnemonic": "rol", "addrMode": "zp"},
    0x28: {"mnemonic": "plp", "addrMode": "imp"},
    0x29: {"mnemonic": "and", "addrMode": "imm"},
    0x2a: {"mnemonic": "rol", "addrMode": "ac"},
    0x2c: {"mnemonic": "bit", "addrMode": "ab"},
    0x2d: {"mnemonic": "and", "addrMode": "ab"},
    0x2e: {"mnemonic": "rol", "addrMode": "ab"},
    0x30: {"mnemonic": "bmi", "addrMode": "re"},
    0x31: {"mnemonic": "and", "addrMode": "idy"},
    0x35: {"mnemonic": "and", "addrMode": "zpx"},
    0x36: {"mnemonic": "rol", "addrMode": "zpx"},
    0x38: {"mnemonic": "sec", "addrMode": "imp"},
    0x39: {"mnemonic": "and", "addrMode": "aby"},
    0x3d: {"mnemonic": "and", "addrMode": "abx"},
    0x3e: {"mnemonic": "rol", "addrMode": "abx"},
    0x40: {"mnemonic": "rti", "addrMode": "imp"},
    0x41: {"mnemonic": "eor", "addrMode": "idx"},
    0x45: {"mnemonic": "eor", "addrMode": "zp"},
    0x46: {"mnemonic": "lsr", "addrMode": "zp"},
    0x48: {"mnemonic": "pha", "addrMode": "imp"},
    0x49: {"mnemonic": "eor", "addrMode": "imm"},
    0x4a: {"mnemonic": "lsr", "addrMode": "ac"},
    0x4c: {"mnemonic": "jmp", "addrMode": "ab"},
    0x4d: {"mnemonic": "eor", "addrMode": "ab"},
    0x4e: {"mnemonic": "lsr", "addrMode": "ab"},
    0x50: {"mnemonic": "bvc", "addrMode": "re"},
    0x51: {"mnemonic": "eor", "addrMode": "idy"},
    0x55: {"mnemonic": "eor", "addrMode": "zpx"},
    0x56: {"mnemonic": "lsr", "addrMode": "zpx"},
    0x58: {"mnemonic": "cli", "addrMode": "imp"},
    0x59: {"mnemonic": "eor", "addrMode": "aby"},
    0x5d: {"mnemonic": "eor", "addrMode": "abx"},
    0x5e: {"mnemonic": "lsr", "addrMode": "abx"},
    0x60: {"mnemonic": "rts", "addrMode": "imp"},
    0x61: {"mnemonic": "adc", "addrMode": "idx"},
    0x65: {"mnemonic": "adc", "addrMode": "zp"},
    0x66: {"mnemonic": "ror", "addrMode": "zp"},
    0x68: {"mnemonic": "pla", "addrMode": "imp"},
    0x69: {"mnemonic": "adc", "addrMode": "imm"},
    0x6a: {"mnemonic": "ror", "addrMode": "ac"},
    0x6c: {"mnemonic": "jmp", "addrMode": "id"},
    0x6d: {"mnemonic": "adc", "addrMode": "ab"},
    0x6e: {"mnemonic": "ror", "addrMode": "ab"},
    0x70: {"mnemonic": "bvs", "addrMode": "re"},
    0x71: {"mnemonic": "adc", "addrMode": "idy"},
    0x75: {"mnemonic": "adc", "addrMode": "zpx"},
    0x76: {"mnemonic": "ror", "addrMode": "zpx"},
    0x78: {"mnemonic": "sei", "addrMode": "imp"},
    0x79: {"mnemonic": "adc", "addrMode": "aby"},
    0x7d: {"mnemonic": "adc", "addrMode": "abx"},
    0x7e: {"mnemonic": "ror", "addrMode": "abx"},
    0x81: {"mnemonic": "sta", "addrMode": "idx"},
    0x84: {"mnemonic": "sty", "addrMode": "zp"},
    0x85: {"mnemonic": "sta", "addrMode": "zp"},
    0x86: {"mnemonic": "stx", "addrMode": "zp"},
    0x88: {"mnemonic": "dey", "addrMode": "imp"},
    0x8a: {"mnemonic": "txa", "addrMode": "imp"},
    0x8c: {"mnemonic": "sty", "addrMode": "ab"},
    0x8d: {"mnemonic": "sta", "addrMode": "ab"},
    0x8e: {"mnemonic": "stx", "addrMode": "ab"},
    0x90: {"mnemonic": "bcc", "addrMode": "re"},
    0x91: {"mnemonic": "sta", "addrMode": "idy"},
    0x94: {"mnemonic": "sty", "addrMode": "zpx"},
    0x95: {"mnemonic": "sta", "addrMode": "zpx"},
    0x96: {"mnemonic": "stx", "addrMode": "zpy"},
    0x98: {"mnemonic": "tya", "addrMode": "imp"},
    0x99: {"mnemonic": "sta", "addrMode": "aby"},
    0x9a: {"mnemonic": "txs", "addrMode": "imp"},
    0x9d: {"mnemonic": "sta", "addrMode": "abx"},
    0xa0: {"mnemonic": "ldy", "addrMode": "imm"},
    0xa1: {"mnemonic": "lda", "addrMode": "idx"},
    0xa2: {"mnemonic": "ldx", "addrMode": "imm"},
    0xa4: {"mnemonic": "ldy", "addrMode": "zp"},
    0xa5: {"mnemonic": "lda", "addrMode": "zp"},
    0xa6: {"mnemonic": "ldx", "addrMode": "zp"},
    0xa8: {"mnemonic": "tay", "addrMode": "imp"},
    0xa9: {"mnemonic": "lda", "addrMode": "imm"},
    0xaa: {"mnemonic": "tax", "addrMode": "imp"},
    0xac: {"mnemonic": "ldy", "addrMode": "ab"},
    0xad: {"mnemonic": "lda", "addrMode": "ab"},
    0xae: {"mnemonic": "ldx", "addrMode": "ab"},
    0xb0: {"mnemonic": "bcs", "addrMode": "re"},
    0xb1: {"mnemonic": "lda", "addrMode": "idy"},
    0xb4: {"mnemonic": "ldy", "addrMode": "zpx"},
    0xb5: {"mnemonic": "lda", "addrMode": "zpx"},
    0xb6: {"mnemonic": "ldx", "addrMode": "zpy"},
    0xb8: {"mnemonic": "clv", "addrMode": "imp"},
    0xb9: {"mnemonic": "lda", "addrMode": "aby"},
    0xba: {"mnemonic": "tsx", "addrMode": "imp"},
    0xbc: {"mnemonic": "ldy", "addrMode": "abx"},
    0xbd: {"mnemonic": "lda", "addrMode": "abx"},
    0xbe: {"mnemonic": "ldx", "addrMode": "aby"},
    0xc0: {"mnemonic": "cpy", "addrMode": "imm"},
    0xc1: {"mnemonic": "cmp", "addrMode": "idx"},
    0xc4: {"mnemonic": "cpy", "addrMode": "zp"},
    0xc5: {"mnemonic": "cmp", "addrMode": "zp"},
    0xc6: {"mnemonic": "dec", "addrMode": "zp"},
    0xc8: {"mnemonic": "iny", "addrMode": "imp"},
    0xc9: {"mnemonic": "cmp", "addrMode": "imm"},
    0xca: {"mnemonic": "dex", "addrMode": "imp"},
    0xcc: {"mnemonic": "cpy", "addrMode": "ab"},
    0xcd: {"mnemonic": "cmp", "addrMode": "ab"},
    0xce: {"mnemonic": "dec", "addrMode": "ab"},
    0xd0: {"mnemonic": "bne", "addrMode": "re"},
    0xd1: {"mnemonic": "cmp", "addrMode": "idy"},
    0xd5: {"mnemonic": "cmp", "addrMode": "zpx"},
    0xd6: {"mnemonic": "dec", "addrMode": "zpx"},
    0xd8: {"mnemonic": "cld", "addrMode": "imp"},
    0xd9: {"mnemonic": "cmp", "addrMode": "aby"},
    0xdd: {"mnemonic": "cmp", "addrMode": "abx"},
    0xde: {"mnemonic": "dec", "addrMode": "abx"},
    0xe0: {"mnemonic": "cpx", "addrMode": "imm"},
    0xe1: {"mnemonic": "sbc", "addrMode": "idx"},
    0xe4: {"mnemonic": "cpx", "addrMode": "zp"},
    0xe5: {"mnemonic": "sbc", "addrMode": "zp"},
    0xe6: {"mnemonic": "inc", "addrMode": "zp"},
    0xe8: {"mnemonic": "inx", "addrMode": "imp"},
    0xe9: {"mnemonic": "sbc", "addrMode": "imm"},
    0xea: {"mnemonic": "nop", "addrMode": "imp"},
    0xec: {"mnemonic": "cpx", "addrMode": "ab"},
    0xed: {"mnemonic": "sbc", "addrMode": "ab"},
    0xee: {"mnemonic": "inc", "addrMode": "ab"},
    0xf0: {"mnemonic": "beq", "addrMode": "re"},
    0xf1: {"mnemonic": "sbc", "addrMode": "idy"},
    0xf5: {"mnemonic": "sbc", "addrMode": "zpx"},
    0xf6: {"mnemonic": "inc", "addrMode": "zpx"},
    0xf8: {"mnemonic": "sed", "addrMode": "imp"},
    0xf9: {"mnemonic": "sbc", "addrMode": "aby"},
    0xfd: {"mnemonic": "sbc", "addrMode": "abx"},
    0xfe: {"mnemonic": "inc", "addrMode": "abx"},
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

    noOpcodes = set(parse_opcode_list(args.no_opcodes))
    noAccess = set(parse_address_ranges(args.no_access))
    noWrite = set(parse_address_ranges(args.no_write))
    noExecute = set(parse_address_ranges(args.no_execute))

    fileSize = get_file_size(handle)
    bankSize = get_bank_size(fileSize, args)
    origin = get_origin(bankSize, args)

    # quite similar to main loops in get_labels() and disassemble()
    for (bankIndex, bankAddr) in enumerate(range(0, fileSize, bankSize)):
        handle.seek(bankAddr)
        bankContents = handle.read(bankSize)
        offset = 0  # within bank

        while offset < bankSize:
            opcode = bankContents[offset]

            # are the next 1...3 bytes a valid opcode and operand?
            # (this can't be a function because we access many look-up tables)
            isInstruction = False
            if opcode in INSTRUCTIONS and opcode not in noOpcodes:
                mnemonic = INSTRUCTIONS[opcode]["mnemonic"]
                addrMode = INSTRUCTIONS[opcode]["addrMode"]

                if bankSize - offset >= 1 + ADDR_MODES[addrMode]["operandSize"]:
                    # operand fits in same bank
                    if addrMode in ("imp", "ac", "imm"):
                        # operand is not an address; accept it
                        isInstruction = True
                    else:
                        # decode address
                        if addrMode in ("zp", "zpx", "zpy", "idx", "idy", "re"):
                            addr = bankContents[offset+1]
                            if addrMode == "re":
                                addr = offset + 2 - (addr & 0x80) + (addr & 0x7f)
                                if 0 <= addr < bankSize:
                                    addr += origin
                                else:
                                    addr = None  # invalid (target in different bank)
                        else:
                            addr = bankContents[offset+1] + bankContents[offset+2] * 0x100

                        if addr is not None:
                            # address was valid
                            isInstruction = not (
                                # uses absolute instead of zero page
                                args.no_absolute_zp
                                and addrMode == "ab" and mnemonic not in ("jmp", "jsr")
                                and addr <= 0xff
                            ) and not (
                                # uses absolute indexed instead of corresponding zero page indexed
                                args.no_absolute_indexed_zp \
                                and (addrMode == "abx" or addrMode == "aby" and mnemonic == "ldx")
                                and addr <= 0xff
                            ) and not (
                                # accesses an excluded address
                                any(addr in rng for rng in noAccess)
                            ) and not(
                                # writes an excluded address
                                mnemonic in (
                                    "asl", "dec", "inc", "lsr", "rol", "ror", "sta", "stx", "sty"
                                )
                                and addrMode in ("zp", "zpx", "zpy", "ab", "abx", "aby")
                                and any(addr in rng for rng in noWrite)
                            ) and not (
                                # executes an excluded address
                                (
                                    mnemonic in ("jmp", "jsr") and addrMode == "ab"
                                    or addrMode == "re"
                                )
                                and any(addr in rng for rng in noExecute)
                            )

            if isInstruction:
                yield bankAddr + offset
                offset += 1 + ADDR_MODES[addrMode]["operandSize"]
            else:
                # data
                offset += 1

def get_labels(handle, instrAddresses, args):
    """Get addresses of labels from a PRG file.
    handle: file handle, instrAddresses: set, args: from argparse,
    return: dict (CPU address -> name)"""

    validPRGLabels = set()  # valid addresses for PRG ROM labels (0x8000...0xffff)

    codeLabels = set()  # addresses referred to as code
    dataLabels = set()  # addresses referred to as data (may contain addresses also in codeLabels)

    fileSize = get_file_size(handle)
    bankSize = get_bank_size(fileSize, args)
    if bankSize < fileSize:
        print("Warning: game uses bankswitching; PRG ROM labels disabled.", file=sys.stderr)
    origin = get_origin(bankSize, args)

    # quite similar to main loops elsewhere
    for (bankIndex, bankAddr) in enumerate(range(0, fileSize, bankSize)):
        handle.seek(bankAddr)
        bankContents = handle.read(bankSize)

        offset = 0  # within bank

        while offset < bankSize:
            validPRGLabels.add(origin + offset)

            if bankAddr + offset in instrAddresses:
                # instruction
                opcode = bankContents[offset]
                mnemonic = INSTRUCTIONS[opcode]["mnemonic"]
                addrMode = INSTRUCTIONS[opcode]["addrMode"]

                if addrMode not in ("imp", "ac", "imm"):
                    # operand is an address
                    # decode operand
                    if addrMode in ("zp", "zpx", "zpy", "idx", "idy", "re"):
                        addr = bankContents[offset+1]
                        if addrMode == "re":
                            addr = origin + offset + 2 - (addr & 0x80) + (addr & 0x7f)
                    else:
                        addr = bankContents[offset+1] + bankContents[offset+2] * 0x100
                    # store as code or data label
                    if mnemonic in ("jmp", "jsr") and addrMode != "id" or addrMode == "re":
                        codeLabels.add(addr)
                    else:
                        dataLabels.add(addr)

                offset += 1 + ADDR_MODES[INSTRUCTIONS[opcode]["addrMode"]]["operandSize"]
            else:
                # data
                offset += 1

    # delete invalid PRG ROM labels, or all if game uses bankswitching
    if bankSize < fileSize:
        validPRGLabels.clear()
    codeLabels = set(addr for addr in codeLabels if addr <= 0x7fff or addr in validPRGLabels)
    dataLabels = set(addr for addr in dataLabels if addr <= 0x7fff or addr in validPRGLabels)
    del validPRGLabels

    # convert labels into a dict
    labelDict = {}
    # RAM
    addresses = sorted(addr for addr in codeLabels | dataLabels if addr <= 0x1fff)
    labelDict.update((addr, f"ram{i+1}") for (i, addr) in enumerate(addresses))
    # hardware registers
    addresses = sorted((codeLabels | dataLabels) & set(HARDWARE_REGISTERS))
    labelDict.update((addr, HARDWARE_REGISTERS[addr]) for addr in addresses)
    # misc (0x2000...0x7fff excluding HARDWARE_REGISTERS)
    addresses = sorted(
        addr for addr in (codeLabels | dataLabels) - set(HARDWARE_REGISTERS)
        if 0x2000 <= addr <= 0x7fff
    )
    labelDict.update((addr, f"misc{i+1}") for (i, addr) in enumerate(addresses))
    # PRG ROM - code
    addresses = sorted(addr for addr in codeLabels - dataLabels if addr >= 0x8000)
    labelDict.update((addr, f"code{i+1}") for (i, addr) in enumerate(addresses))
    # PRG ROM - data
    addresses = sorted(addr for addr in dataLabels - codeLabels if addr >= 0x8000)
    labelDict.update((addr, f"data{i+1}") for (i, addr) in enumerate(addresses))
    # PRG ROM - code & data
    addresses = sorted(addr for addr in codeLabels & dataLabels if addr >= 0x8000)
    labelDict.update((addr, f"codedata{i+1}") for (i, addr) in enumerate(addresses))

    return labelDict

def disassemble(handle, instrAddresses, labels, args):
    """Disassemble a PRG file.
    handle: file handle, instrAddresses: set, labels: dict, args: from argparse, return: None"""

    def generate_data_lines(data, addr, labels):
        """Generate lines with data bytes.
        data: bytes, addr: int, labels: dict, yield: str"""

        def generate_data_block(data, addr):
            """Generate lines with data bytes without labels.
            If addr is specified, output it on the first line only.
            data: bytes, addr: int, yield: str"""

            for offset in range(0, len(data), 8):
                line = "    hex " + " ".join(f"{byte:02x}" for byte in data[offset:offset+8])
                yield f"{line:33s}; {addr+offset:04x}"

        startOffset = 0  # offset of the first byte not yet output

        for (offset, byte) in enumerate(data):
            label = labels.get(addr + offset)
            if label is not None:
                yield from generate_data_block(data[startOffset:offset], addr + startOffset)
                startOffset = offset
                print(f"{label+':':33s}; {addr+offset:04x}")

        yield from generate_data_block(data[startOffset:], addr + startOffset)

    fileSize = get_file_size(handle)
    bankSize = get_bank_size(fileSize, args)
    origin = get_origin(bankSize, args)

    print(f"; Input file: {os.path.basename(handle.name)}")
    print(f"; PRG ROM size: {fileSize} (0x{fileSize:04x})")
    print(f"; Bank size: {bankSize} (0x{bankSize:04x})")
    print(f"; Number of banks: {fileSize//bankSize}")
    print(f"; Bank CPU address: 0x{origin:04x}...0x{origin+bankSize-1:04x}")
    print(f"; Number of instructions: {len(instrAddresses)}")
    print(f"; Number of labels: {len(labels)}")
    print()

    print("; === RAM labels ($0000...$01fff) ===")
    print()
    # zero page
    for addr in sorted(l for l in labels if l <= 0xff):
        print(f"{labels[addr]:15s} equ ${addr:02x}")
    print()
    # other RAM labels
    for addr in sorted(l for l in labels if 0x0100 <= l <= 0x1fff):
        print(f"{labels[addr]:15s} equ ${addr:04x}")
    print()

    print("; === NES memory-mapped registers ===")
    print()
    for addr in sorted(HARDWARE_REGISTERS):
        print("{name:11s} equ ${addr:04x}".format(
            name=("" if addr in labels else ";") + HARDWARE_REGISTERS[addr],
            addr=addr
        ))
    print()

    print("; === Misc labels ($2000...$7fff excluding NES memory-mapped registers) ===")
    print()
    for addr in sorted(l for l in set(labels) - set(HARDWARE_REGISTERS) if 0x2000 <= l <= 0x7fff):
        print(f"{labels[addr]:15s} equ ${addr:04x}")
    print()

    # quite similar to main loops elsewhere
    for (bankIndex, bankAddr) in enumerate(range(0, fileSize, bankSize)):
        print(
            f"; === Bank {bankIndex} (PRG ROM 0x{bankAddr:04x}...0x{bankAddr+bankSize-1:04x}) ==="
        )
        print()
        print("    base ${:04x}".format(origin))
        print()

        handle.seek(bankAddr)
        bankContents = handle.read(bankSize)

        offset = 0  # within bank
        dataStartOffset = None  # where current string of data bytes started

        while offset < bankSize:
            if bankAddr + offset in instrAddresses:
                if dataStartOffset is not None:
                    # print previous data bytes
                    for line in generate_data_lines(
                        bankContents[dataStartOffset:offset], origin + dataStartOffset, labels
                    ):
                        print(line)
                    print()
                    dataStartOffset = None
                # print label if any
                try:
                    print(f"{labels[origin+offset]}:")
                except KeyError:
                    pass

                opcode = bankContents[offset]
                addrMode = INSTRUCTIONS[opcode]["addrMode"]
                mnemonic = INSTRUCTIONS[opcode]["mnemonic"]
                operandSize = ADDR_MODES[INSTRUCTIONS[opcode]["addrMode"]]["operandSize"]

                # format operand value
                if addrMode in ("imp", "ac"):
                    # none
                    operand = ""
                elif addrMode == "imm":
                    # immediate
                    if mnemonic in ("and", "eor", "ora"):
                        operand = f"%{bankContents[offset+1]:08b}"  # binary
                    elif mnemonic in ("cpx", "cpy", "ldx", "ldy"):
                        operand = f"{bankContents[offset+1]:d}"  # decimal
                    else:
                        operand = f"${bankContents[offset+1]:02x}"  # hexadecimal
                elif addrMode in ("zp", "zpx", "zpy", "idx", "idy"):
                    # 8-bit address
                    addr = bankContents[offset+1]
                    operand = labels.get(addr, f"${addr:02x}")
                else:
                    # relative or 16-bit
                    if addrMode == "re":
                        addr = bankContents[offset+1]
                        addr = origin + offset + 2 - (addr & 0x80) + (addr & 0x7f)
                    else:
                        addr = bankContents[offset+1] + bankContents[offset+2] * 0x100
                    operand = labels.get(addr, f"${addr:04x}")

                # add prefix and suffix to operand
                operand = ADDR_MODES[INSTRUCTIONS[opcode]["addrMode"]]["prefix"] \
                + operand \
                + ADDR_MODES[INSTRUCTIONS[opcode]["addrMode"]]["suffix"]

                # combine indentation, mnemonic and operand
                line = "    " \
                + INSTRUCTIONS[opcode]["mnemonic"] \
                + (" " + operand if operand else "")

                # format comment
                instrBytes = bankContents[offset:offset+1+operandSize]
                hexBytes = " ".join(f"{byte:02x}" for byte in instrBytes)

                print(f"{line:33s}; {origin+offset:04x}: {hexBytes}")
                if mnemonic in ("jmp", "rti", "rts"):
                    print()

                offset += 1 + operandSize
            else:
                dataStartOffset = offset if dataStartOffset is None else dataStartOffset
                offset += 1

        if dataStartOffset is not None:
            # print last data bytes
            for line in generate_data_lines(
                bankContents[dataStartOffset:offset], origin + dataStartOffset, labels
            ):
                print(line)

        print()

# -------------------------------------------------------------------------------------------------

def main():
    """The main function."""

    args = parse_arguments()

    with open(args.input_file, "rb") as handle:
        instrAddresses = set(get_instruction_addresses(handle, args))
        labels = get_labels(handle, instrAddresses, args)
        disassemble(handle, instrAddresses, labels, args)

if __name__ == "__main__":
    main()

