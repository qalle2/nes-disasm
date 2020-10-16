"""NES disassembler."""

import argparse
import math
import os
import sys

# TODO: require file size to be a multiple of 256
# TODO: require bank size to be 256/512/.../32768

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

    # todo: if game is NROM, use --no-rom-writes automatically

    parser = argparse.ArgumentParser(description="An NES (6502) disassembler.")

    parser.add_argument(
        "--bank-size", type=int,
        help="Size of PRG ROM banks in bytes. 1 to 32768, but the input file size must be a "
        "multiple of this or equal to this. Default: greatest common divisor of file size and "
        "32768."
    )
    parser.add_argument(
        "--origin", type=int,
        help="The NES CPU address each PRG ROM bank starts from. Minimum: 32768. Default & "
        "maximum: 65536 minus --bank-size."
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
        "--no-absolute-x-zp-access", action="store_true",
        help="Assume the game never accesses zero page using absolute,x addressing."
    )
    parser.add_argument(
        "--no-absolute-y-zp-access", action="store_true",
        help="Assume the game never accesses zero page using absolute,y addressing if the "
        "instruction also supports zeroPage,y addressing."
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
        help="Shortcut for --no-absolute-zp-access, --no-absolute-x-zp-access, "
        "--no-absolute-y-zp-access, --no-mirror-access, --no-cart-space-start-access and "
        "--no-prg-ram-access."
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
        help="The PRG ROM file to read. Size: 1 byte to 4 MiB (4,194,304 bytes). (.nes files "
        "aren't currently supported.)"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        sys.exit("Input file not found.")

    return args

def disassemble(handle, args):
    """Disassemble a PRG file.
    handle: file handle, args: from argparse, return: None"""

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
                return False  # pointlessly uses absolute instead of zero page

            if (args.no_absolute_x_zp_access or args.no_access) \
            and instrInfo["addrMode"] == "abx" \
            and addr <= 0x00ff:
                return False  # pointlessly uses absolute,x instead of zeroPage,x

            if (args.no_absolute_y_zp_access or args.no_access) \
            and instrInfo["addrMode"] == "aby" \
            and instrInfo["mnemonic"] == "ldx" \
            and addr <= 0x00ff:
                return False  # pointlessly uses absolute,y instead of zeroPage,y

            if (args.no_mirror_access or args.no_access) \
            and 0x0800 <= addr <= 0x1fff or 0x2008 <= addr <= 0x3fff:
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

    def format_instruction_line(instrBytes, addr):
        """Disassemble a valid instruction.
        instrBytes: 1 to 3 bytes, addr: 16-bit int, return: str"""

        def format_operand_value(instrBytes, programCounter):
            """Decode and format the value of an operand.
            instrBytes: 1 to 3 bytes, programCounter: 16-bit int, return: str"""

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
                    return f"${value:04x}"
                if addrMode == "imm" and instrInfo["mnemonic"] in ("and", "eor", "ora"):
                    # immediate bitmask (in binary)
                    return f"%{value:08b}"
                return f"${value:02x}"
            # 2 bytes
            value = instrBytes[1] + instrBytes[2] * 0x100
            return HARDWARE_REGISTERS.get(value, f"${value:04x}")

        instrInfo = INSTRUCTIONS[instrBytes[0]]
        addrModeInfo = ADDR_MODES[instrInfo["addrMode"]]
        operand = addrModeInfo["prefix"] + format_operand_value(instrBytes, addr) \
        + addrModeInfo["suffix"]
        line = instrInfo["mnemonic"] + (" " + operand if operand else "")
        hexBytes = " ".join(f"{byte:02x}" for byte in instrBytes[:1+addrModeInfo["operandSize"]])
        return f"    {line:29s}; {addr:04x}: {hexBytes}"

    def generate_data_lines(addr, data):
        """Generate lines with data bytes.
        addr: int, data: bytes, yield: str"""

        for i in range(0, len(data), 8):
            line = "hex " + " ".join(f"{byte:02x}" for byte in data[i:i+8])
            yield f"    {line:29s}; {addr+i:04x}"

    # get file size, bank size, bank count and origin
    fileSize = handle.seek(0, 2)
    if not 1 <= fileSize <= 4 * 1024 * 1024:
        sys.exit("The input file size must be 1 byte to 4 MiB.")

    # get bank size
    bankSize = math.gcd(fileSize, 32 * 1024) if args.bank_size is None else args.bank_size
    if not 1 <= bankSize <= 32 * 1024 or fileSize % bankSize:
        sys.exit("Invalid bank size.")

    # get origin
    origin = 64 * 1024 - bankSize if args.origin is None else args.origin
    if not 32 * 1024 <= origin <= 64 * 1024 - bankSize:
        sys.exit("Origin must not be less than 32768 or greater than 65536 minus bank size.")

    bankCount = fileSize // bankSize

    print(f"; Input file: {os.path.basename(handle.name)}")
    print(f"; PRG ROM size: {fileSize} (0x{fileSize:04x})")
    print(f"; Number of banks: {bankCount}")
    print(f"; Bank size: {bankSize} (0x{bankSize:04x})")
    print(f"; Bank CPU address: 0x{origin:04x}...0x{origin+bankSize-1:04x}")
    print()

    print("; === NES memory-mapped registers ===")
    print()
    for addr in sorted(HARDWARE_REGISTERS):
        print(f"{HARDWARE_REGISTERS[addr]:10s} equ ${addr:04x}")
    print()

    handle.seek(0)
    for bank in range(bankCount):
        print(
            f"; === Bank {bank} (PRG ROM 0x{bank*bankSize:04x}...0x{(bank+1)*bankSize-1:04x}) ==="
        )
        print()
        print("    base ${:04x}".format(origin))
        print()

        bankData = handle.read(bankSize)
        offset = 0  # within bank
        dataStartOffset = None  # where current string of data bytes started

        while offset < bankSize:
            # look at next 1...3 bytes
            if starts_with_instruction(bankData[offset:offset+3], offset, bankSize, args):
                if dataStartOffset is not None:
                    # print previous data bytes
                    for line in generate_data_lines(
                        origin + dataStartOffset, bankData[dataStartOffset:offset]
                    ):
                        print(line)
                    print()
                    dataStartOffset = None
                print(format_instruction_line(bankData[offset:offset+3], origin + offset))
                instrInfo = INSTRUCTIONS[bankData[offset]]
                if instrInfo["mnemonic"] in ("jmp", "rti", "rts"):
                    print()
                offset += 1 + ADDR_MODES[instrInfo["addrMode"]]["operandSize"]
            else:
                dataStartOffset = offset if dataStartOffset is None else dataStartOffset
                offset += 1

        if dataStartOffset is not None:
            # print last data bytes
            for line in generate_data_lines(
                origin + dataStartOffset, bankData[dataStartOffset:offset]
            ):
                print(line)

        print()

def main():
    """The main function."""

    args = parse_arguments()

    with open(args.input_file, "rb") as handle:
        disassemble(handle, args)

if __name__ == "__main__":
    main()

