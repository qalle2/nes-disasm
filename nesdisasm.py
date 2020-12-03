"""NES disassembler."""

import argparse
import math
import os
import sys
from nesdisasm_defines import *

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
        "--unaccessed-as-data", action="store_true",
        help="If a CDL file is used, disassemble all unaccessed bytes as data."
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

    if args.unaccessed_as_data and not args.cdl_file:
        sys.exit("--unaccessed-as-data cannot be used without a CDL file.")

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
    """bytes_: 2 bytes (little endian), return: 16-bit unsigned int"""

    assert len(bytes_) == 2
    return bytes_[0] + bytes_[1] * 0x100

def decode_relative_address(base, offset):
    """base: 16-bit int, offset: 8-bit int, return: int (may underflow/overflow 16 bits)"""

    assert 0 <= base <= 0xffff
    assert 0 <= offset <= 0xff
    offset = -(offset & 0x80) + (offset & 0x7f)  # -128...+127
    return base + 2 + offset

def get_origin(PRGSize):
    """Get origin CPU address for PRG ROM."""

    assert PRGSize <= 32 * 1024
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

        # any byte of the instruction forbidden according to CDL file and --unaccessed-as-data?
        if args.unaccessed_as_data:
            # must be code (not data or unaccessed)
            if not any(
                PRGAddr in rng and PRGAddr + operandSize in rng for rng in CDLCodeRanges
            ):
                return False
        else:
            # must not contain data
            if any(
                any(addr in rng for rng in CDLDataRanges)
                for addr in range(PRGAddr, PRGAddr + 1 + operandSize)
            ):
                return False
            # also, must not be partially code and partially unaccessed
            # (because comments denoting unaccessed code can't be "inside" instructions)
            if not any(
                PRGAddr in rng and PRGAddr + operandSize in rng for rng in CDLCodeRanges
            ) and any(
                any(addr in rng for rng in CDLCodeRanges)
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

    CDLCodeRanges = set(rng for rng in CDLData if CDLData[rng] == CDL_CODE)
    CDLDataRanges = set(rng for rng in CDLData if CDLData[rng] == CDL_DATA)
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

def get_instruction_addresses(handle, instrAddrRanges):
    """Generate PRG addresses of instructions.
    instrAddrRanges: set of PRG address ranges"""

    for rng in sorted(instrAddrRanges, key=lambda r: r.start):
        handle.seek(rng.start)
        chunk = handle.read(len(rng))
        pos = 0  # within range
        while pos < len(rng):
            yield rng.start + pos
            opcode = chunk[pos]
            addrMode = OPCODES[opcode][1]
            operandSize = ADDRESSING_MODES[addrMode][0]
            pos += 1 + operandSize

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

    for pos in get_instruction_addresses(handle, instrAddrRanges):
        instrAddresses.add(pos)

        opcode = PRGData[pos]
        (mnemonic, addrMode) = OPCODES[opcode]

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

    # only keep labels that refer to:
    # - outside of PRG ROM
    # - first bytes of instructions
    # - data
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
        if not CDLData:
            print("; No CDL file was used.")
            return
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

    def generate_data_lines(data, origin, PRGAddr):
        """Format lines with data bytes.
        data: bytes, origin: int, PRGAddr: int, labels: dict, yield: str"""

        def format_data_line(label, bytes_, origin, PRGAddr):
            indentWidth = max(INDENT_WIDTH, len(label) + 1)
            hexBytes = " ".join(f"{byte:02x}" for byte in bytes_)

            # flag as unaccessed?
            flagUnaccessed = CDLData and not any(PRGAddr in rng for rng in CDLDataRanges)

            return (
                format(label, f"{indentWidth}s")
                + format("hex " + hexBytes, "29s")
                + f"; {origin+PRGAddr:04x}"
                + (11 * " " + "(unaccessed)" if flagUnaccessed else "")
            )

        startOffset = 0  # current block
        prevLabel = ""

        for (offset, byte) in enumerate(data):
            label = labels.get(origin + PRGAddr + offset, "")
            if label or offset - startOffset == 8:
                # a new block starts; print old one, if any
                if offset > startOffset:
                    yield format_data_line(
                        prevLabel, data[startOffset:offset], origin, PRGAddr + startOffset
                    )
                    startOffset = offset
                prevLabel = label

        # print last block, if any
        if len(data) > startOffset:
            yield format_data_line(prevLabel, data[startOffset:], origin, PRGAddr + startOffset)

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

    instrAddresses = set(get_instruction_addresses(handle, instrAddrRanges))
    CDLCodeRanges = set(rng for rng in CDLData if CDLData[rng] == CDL_CODE)
    CDLDataRanges = set(rng for rng in CDLData if CDLData[rng] == CDL_DATA)

    handle.seek(0)
    PRGData = handle.read()

    pos = 0  # position in PRG data
    dataStart = None  # where current string of data bytes started
    prevBlockWasData = False

    while pos < PRGSize:
        if pos in instrAddresses:
            # instruction

            if dataStart is not None:
                # print previous data block
                if not prevBlockWasData:
                    print()
                for line in generate_data_lines(PRGData[dataStart:pos], origin, dataStart):
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

            # flag the instruction as unaccessed?
            flagUnaccessed = CDLData and not any(pos in rng for rng in CDLCodeRanges)

            # print instruction line
            operand = operandFormat.format(format_operand_value(instrBytes, origin + pos))
            instrBytesHex = " ".join(f"{byte:02x}" for byte in instrBytes)
            print(
                format(label, f"{max(INDENT_WIDTH, len(label) + 1)}s")
                + format(mnemonic + " " + operand, "29s")
                + f"; {origin+pos:04x}: {instrBytesHex}"
                + ((9 - len(instrBytesHex)) * " " + "(unaccessed)" if flagUnaccessed else "")
            )

            pos += 1 + operandSize
            prevBlockWasData = False
        else:
            # data

            accessed = any(pos in rng for rng in CDLDataRanges)

            if dataStart is None or accessed != prevDataBlockAccessed:
                if dataStart is not None:
                    # print previous data block
                    if not prevBlockWasData:
                        print()
                    for line in generate_data_lines(PRGData[dataStart:pos], origin, dataStart):
                        print(line)
                    prevBlockWasData = True
                # start new data block
                dataStart = pos
                prevDataBlockAccessed = accessed

            pos += 1

    if dataStart is not None:
        # print last data block
        for line in generate_data_lines(PRGData[dataStart:], origin, dataStart):
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

