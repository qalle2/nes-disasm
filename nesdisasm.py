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
        "--no-brk", action="store_true",
        help="Assume the game never uses the BRK instruction (opcode 0x00)."
    )
    parser.add_argument(
        "--no-indirect-x", action="store_true",
        help="Assume the game never uses the (indirect,x) addressing mode."
    )
    parser.add_argument(
        "--no-absolute-zp-access", action="store_true",
        help="Assume the game never accesses zero page using absolute addressing if the "
        "instruction also supports zero page addressing."
    )
    parser.add_argument(
        "--no-absolute-indexed-zp-access", action="store_true",
        help="Assume the game never accesses zero page using absolute indexed addressing if the "
        "instruction also supports the corresponding zero page indexed addressing mode."
    )
    parser.add_argument(
        "--no-mirror-access", action="store_true",
        help="Assume the game never accesses mirrors of RAM (0x0800...0x1fff) or mirrors of PPU "
        "registers (0x2008...0x3fff)."
    )
    parser.add_argument(
        "--no-cart-space-start-access", action="store_true",
        help="Assume the game never accesses the beginning of cartridge space (0x4020...0x5fff)."
    )
    parser.add_argument(
        "--no-prg-ram-access", action="store_true",
        help="Assume the game never accesses PRG RAM (0x6000...0x7fff)."
    )
    parser.add_argument(
        "--no-access", action="store_true",
        help="Shortcut for --no-absolute-zp-access, --no-absolute-indexed-zp-access, "
        "--no-mirror-access, --no-cart-space-start-access and --no-prg-ram-access."
    )
    parser.add_argument(
        "--no-register-execute", action="store_true",
        help="Assume the game never executes memory-mapped registers (0x2000...0x3fff and "
        "0x4000...0x401f)."
    )
    parser.add_argument(
        "--no-rom-write", action="store_true",
        help="Assume the game never writes to PRG ROM (0x8000...0xffff)."
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

def decode_relative_address(programCounter, offset):
    """Get the effective address of a branch instruction.
    programCounter: 16-bit int, offset: 8-bit int, return: int (may over-/underflow)"""

    return programCounter + 2 - (offset & 0x80) + (offset & 0x7f)

def starts_with_instruction(instrBytes, offset, bankSize, args):
    """Does the specified substring of PRG data start with a valid instruction (opcode and
    operand)?
    instrBytes: 1 to 3 bytes, offset: int, bankSize: int, args: from argparse, return: bool"""

    instrInfo = INSTRUCTIONS.get(instrBytes[0])

    if instrInfo is None:
        return False  # undocumented opcode

    if len(instrBytes) < 1 + ADDR_MODES[instrInfo["addrMode"]]["operandSize"]:
        return False  # operand does not fit in same bank

    if instrInfo["addrMode"] == "re" \
    and not 0 <= decode_relative_address(offset, instrBytes[1]) < bankSize:
        return False  # branch target in different bank

    if args.no_brk and instrInfo["mnemonic"] == "brk":
        return False  # BRK

    if args.no_indirect_x and instrInfo["addrMode"] == "idx":
        return False  # (indirect,x) addressing

    if instrInfo["addrMode"] in ("ab", "abx", "aby", "id"):
        addr = instrBytes[1] + instrBytes[2] * 0x100

        if (args.no_absolute_zp_access or args.no_access) \
        and instrInfo["addrMode"] == "ab" \
        and instrInfo["mnemonic"] not in ("jmp", "jsr") \
        and addr <= 0x00ff:
            return False  # uses absolute instead of zero page

        if (args.no_absolute_indexed_zp_access or args.no_access) \
        and (
            instrInfo["addrMode"] == "abx"
            or instrInfo["addrMode"] == "aby" and instrInfo["mnemonic"] == "ldx"
        ) \
        and addr <= 0x00ff:
            return False  # uses absolute indexed instead of corresponding zero page indexed

        if (args.no_mirror_access or args.no_access) \
        and (0x0800 <= addr <= 0x1fff or 0x2008 <= addr <= 0x3fff):
            return False  # accesses RAM mirrors or PPU register mirrors

        if (args.no_cart_space_start_access or args.no_access) and 0x4020 <= addr <= 0x5fff:
            return False  # accesses the beginning of cartridge space

        if (args.no_prg_ram_access or args.no_access) and 0x6000 <= addr <= 0x7fff:
            return False  # accesses PRG RAM

        if args.no_register_execute \
        and instrInfo["mnemonic"] in ("jmp", "jsr") \
        and instrInfo["addrMode"] == "ab" \
        and (0x2000 <= addr <= 0x3fff or 0x4000 <= addr <= 0x401f):
            return False  # executes memory-mapped registers

        if args.no_rom_write \
        and instrInfo["mnemonic"] \
        in ("asl", "dec", "inc", "lsr", "rol", "ror", "sta", "stx", "sty") \
        and addr >= 0x8000:
            return False  # writes PRG ROM

    return True

def get_labels(handle, args):
    """Get addresses of labels from a PRG file.
    Note: always returns an empty dict if the game uses bankswitching.
    handle: file handle, args: from argparse, return: dict (CPU address -> name)"""

    # all valid addresses for labels (not inside an instruction etc.)
    validLabels = set(range(0x0800))

    # note: the same address may occur in both of these
    codeLabels = set()  # addresses referred to as code
    dataLabels = set()  # addresses referred to as data

    fileSize = get_file_size(handle)
    bankSize = get_bank_size(fileSize, args)
    if bankSize < fileSize:
        print("Warning: game uses bankswitching; PRG ROM labels disabled.", file=sys.stderr)
    origin = get_origin(bankSize, args)

    # quite similar to the main loop in disassemble()
    for (bankIndex, bankAddr) in enumerate(range(0, fileSize, bankSize)):
        handle.seek(bankAddr)
        bankContents = handle.read(bankSize)

        offset = 0  # within bank
        dataStartOffset = None  # where current string of data bytes started

        while offset < bankSize:
            validLabels.add(origin + offset)
            # look at next 1...3 bytes
            if starts_with_instruction(bankContents[offset:offset+3], offset, bankSize, args):
                instrInfo = INSTRUCTIONS[bankContents[offset]]
                if instrInfo["addrMode"] in ("zp", "zpx", "zpy", "idx", "idy"):
                    # 8-bit address
                    dataLabels.add(bankContents[offset+1])  # zero page
                elif instrInfo["addrMode"] in ("ab", "abx", "aby", "id"):
                    # 16-bit address
                    targetAddr = bankContents[offset+1] + bankContents[offset+2] * 0x100
                    if targetAddr <= 0x07ff or targetAddr >= 0x8000 and bankSize == fileSize:
                        # RAM or PRG ROM (the latter for non-bankswitched games only)
                        if instrInfo["mnemonic"] in ("jmp", "jsr"):
                            codeLabels.add(targetAddr)
                        else:
                            dataLabels.add(targetAddr)
                elif instrInfo["addrMode"] == "re" and bankSize == fileSize:
                    # relative address (non-bankswitched games only)
                    codeLabels.add(decode_relative_address(
                        origin + offset, bankContents[offset+1]
                    ))
                offset += 1 + ADDR_MODES[instrInfo["addrMode"]]["operandSize"]
            else:
                offset += 1

    # delete invalid labels
    codeLabels.intersection_update(validLabels)
    dataLabels.intersection_update(validLabels)
    del validLabels

    # convert labels into a dict (there are 3 * 3 = 9 types of labels)
    labelDict = {}
    for (addrRange, rangeName) in zip(
        (
            range(0x100),           # zero page
            range(0x0100, 0x0800),  # other RAM addresses
            range(0x8000, 0x10000)  # PRG ROM
        ),
        ("zp", "ram", "prg")
    ):
        for (addrSet, setName) in zip(
            (
                codeLabels - dataLabels,  # code only
                dataLabels - codeLabels,  # data only
                codeLabels & dataLabels   # code & data
            ),
            ("code", "data", "codedata")
        ):
            addresses = sorted(addr for addr in addrSet if addr in addrRange)
            labelDict.update(
                (addr, f"{rangeName}{setName}{i+1}") for (i, addr) in enumerate(addresses)
            )

    return labelDict

def disassemble(handle, labels, args):
    """Disassemble a PRG file.
    handle: file handle, labels: dict, args: from argparse, return: None"""

    def format_instruction_line(instrBytes, addr, labels):
        """Disassemble a valid instruction.
        instrBytes: 1 to 3 bytes, addr: 16-bit int, labels: dict, return: str"""

        def format_operand_value(instrBytes, programCounter, labels):
            """Decode and format the value of an operand.
            instrBytes: 1 to 3 bytes, programCounter: 16-bit int, labels: dict, return: str"""

            instrInfo = INSTRUCTIONS[instrBytes[0]]
            addrMode = instrInfo["addrMode"]
            operandSize = ADDR_MODES[addrMode]["operandSize"]

            # note: instrBytes may contain unnecessary trailing bytes
            if operandSize == 0:
                return ""
            elif operandSize == 1:
                value = instrBytes[1]
                if addrMode == "re":
                    # program counter relative (bank boundary crossing handled elsewhere)
                    value = decode_relative_address(programCounter, value)
                    return labels.get(value, f"${value:04x}")  # label or hexadecimal
                if addrMode == "imm":
                    # immediate
                    if instrInfo["mnemonic"] in ("and", "eor", "ora"):
                        return f"%{value:08b}"  # bitmask (in binary)
                    return f"${value:02x}"  # other immediate value (in hexadecimal)
                # other 1-byte operand
                return labels.get(value, f"${value:02x}")  # label or hexadecimal
            # 2 bytes
            value = instrBytes[1] + instrBytes[2] * 0x100
            return HARDWARE_REGISTERS.get(value, labels.get(value, f"${value:04x}"))

        instrInfo = INSTRUCTIONS[instrBytes[0]]
        addrModeInfo = ADDR_MODES[instrInfo["addrMode"]]
        operand = addrModeInfo["prefix"] + format_operand_value(instrBytes, addr, labels) \
        + addrModeInfo["suffix"]
        line = "    " + instrInfo["mnemonic"] + (" " + operand if operand else "")
        hexBytes = " ".join(f"{byte:02x}" for byte in instrBytes[:1+addrModeInfo["operandSize"]])
        return f"{line:33s}; {addr:04x}: {hexBytes}"

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
    print()

    print("; === NES memory-mapped registers ===")
    print()
    for addr in sorted(HARDWARE_REGISTERS):
        print(f"{HARDWARE_REGISTERS[addr]:10s} equ ${addr:04x}")
    print()

    print("; === RAM labels ===")
    print()
    # zero page (longest name possible: "zpcodedata256")
    for addr in sorted(l for l in labels if l <= 0xff):
        print(f"{labels[addr]:13s} equ ${addr:02x}")
    print()
    # other RAM labels (longest name possible: "ramcodedata1792")
    for addr in sorted(l for l in labels if 0x0100 <= l <= 0x07ff):
        print(f"{labels[addr]:15s} equ ${addr:04x}")
    print()

    # quite similar to the main loop in get_labels()
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
            # look at next 1...3 bytes
            if starts_with_instruction(bankContents[offset:offset+3], offset, bankSize, args):
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
                print(format_instruction_line(
                    bankContents[offset:offset+3], origin + offset, labels
                ))
                instrInfo = INSTRUCTIONS[bankContents[offset]]
                if instrInfo["mnemonic"] in ("jmp", "rti", "rts"):
                    print()
                offset += 1 + ADDR_MODES[instrInfo["addrMode"]]["operandSize"]
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
        labels = get_labels(handle, args)
        disassemble(handle, labels, args)

if __name__ == "__main__":
    main()

