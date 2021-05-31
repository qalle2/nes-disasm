# NES (6502) disassembler

import argparse, math, os, sys
from nesdisasm_defines import *

def parse_arguments():
    # parse command line arguments using argparse

    parser = argparse.ArgumentParser(description="An NES (6502) disassembler.")

    parser.add_argument(
        "-c", "--cdl-file", type=str, default="",
        help="The FCEUX code/data log file (.cdl) to read."
    )
    parser.add_argument(
        "-i", "--indentation", type=int, default=8,
        help="How many spaces to use for indentation (1 to 100, default=8)."
    )
    parser.add_argument(
        "-d", "--data-bytes-per-line", type=int, default=8,
        help="How many data bytes to print per 'hex ...' line (1 to 100, default=8)."
    )
    parser.add_argument(
        "--no-abs-zp", action="store_true",
        help="Assume the game never accesses zero page using absolute addressing if the "
        "instruction also supports zeroPage addressing."
    )
    parser.add_argument(
        "--no-abs-zpx", action="store_true",
        help="Assume the game never accesses zero page using absolute,x addressing if the "
        "instruction also supports zeroPage,x addressing."
    )
    parser.add_argument(
        "--no-abs-zpy", action="store_true",
        help="Assume the game never accesses zero page using absolute,y addressing if the "
        "instruction also supports zeroPage,y addressing."
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
        help="Assume the game never writes these addresses (via "
        "STA/STX/STY/DEC/INC/ASL/LSR/ROL/ROR). Same syntax as in --no-access. "
        "Example: 8000-ffff = PRG ROM."
    )
    parser.add_argument(
        "--no-execute", type=str, default="",
        help="Assume the game never executes these addresses (via JMP, JSR or a branch "
        "instruction). Same syntax as in --no-access. "
        "Example: 2000-401f = memory-mapped registers."
    )
    parser.add_argument(
        "--unaccessed-as-data", action="store_true",
        help="Output unaccessed bytes as data instead of trying to disassemble them. "
        "(Note: without a CDL file, all bytes will be output as data.)"
    )
    parser.add_argument(
        "--no-anonymous-labels", action="store_true",
        help="Do not use anonymous PRG ROM labels ('+' and '-')."
    )
    parser.add_argument(
        "input_file",
        help="The PRG ROM file to read. Size: 32 KiB or less. (.nes files are not supported.)"
    )

    args = parser.parse_args()

    if not 1 <= args.indentation <= 100:
        sys.exit("Invalid indentation argument.")
    if not 1 <= args.data_bytes_per_line <= 100:
        sys.exit("Invalid 'data bytes per line' argument.")
    if not os.path.isfile(args.input_file):
        sys.exit("Input file not found.")
    if args.cdl_file and not os.path.isfile(args.cdl_file):
        sys.exit("CDL file not found.")

    return args

# --- get_instruction_address_ranges() and related -------------------------------------------------

def parse_opcodes(arg):
    # generate integers from a string of comma-separated hexadecimal opcodes
    if arg == "":
        return None
    for n in arg.split(","):
        try:
            n = int(n, 16)
            if n not in OPCODES:
                raise ValueError
        except ValueError:
            sys.exit("Invalid opcode.")
        yield n

def parse_address_ranges(arg):
    # generate ranges from a string of comma-separated 16-bit address ranges
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

def instruction_allowed_at_address(addrRange, cdlCodeRanges, cdlDataRanges, args):
    # is an instruction allowed at addrRange according to CDL file and --unaccessed-as-data?
    # accept if condition 1 or both 2 and 3:
    #   1. all bytes were accessed as code
    #   2. unaccessed code should be disassembled
    #   3. all bytes were unaccessed
    # (comments denoting unaccessed code cannot be "inside" instructions)

    return any(
        addrRange.start in rng and addrRange.stop - 1 in rng
        for rng in cdlCodeRanges
    ) or (
        (not args.unaccessed_as_data) \
        and not any(
            any(addr in rng for rng in cdlCodeRanges)
            or any(addr in rng for rng in cdlDataRanges)
            for addr in addrRange
        )
    )

def get_instruction_address_ranges(handle, cdlData, args):
    # generate PRG address ranges of instructions from a PRG file
    # cdlData: {address_range: chunk_type, ...}, yield: one range per call

    cdlCodeRanges = set(rng for rng in cdlData if cdlData[rng] == CDL_CODE)
    cdlDataRanges = set(rng for rng in cdlData if cdlData[rng] == CDL_DATA)
    noOpcodes = set(parse_opcodes(args.no_opcodes))
    noAccess = set(parse_address_ranges(args.no_access))
    noWrite = set(parse_address_ranges(args.no_write))
    noExecute = set(parse_address_ranges(args.no_execute))

    prgSize = handle.seek(0, 2)
    origin = 0x10000 - prgSize

    handle.seek(0)
    PRGData = handle.read()

    codeStart = None  # start of current code chunk
    pos = 0  # position in PRG data

    # quite similar to main loops elsewhere
    while pos < prgSize:
        opcode = PRGData[pos]

        isInstruction = True  # does remaining PRG ROM start with an instruction?

        # a long mess of code that sets isInstruction to False or doesn't
        if opcode in OPCODES and opcode not in noOpcodes:
            (mnemonic, addrMode) = OPCODES[opcode]
            operandSize = ADDRESSING_MODES[addrMode][0]

            # enough space for operand and instruction address not forbidden?
            if prgSize - pos >= 1 + operandSize \
            and instruction_allowed_at_address(
                range(pos, pos + 1 + operandSize), cdlCodeRanges, cdlDataRanges, args
            ):
                # valid operand?
                if addrMode in (AM_IMP, AM_AC, AM_IMM):
                    pass  # no address, no more validation
                else:
                    # get address from operand
                    if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
                        # 1-byte address
                        addr = PRGData[pos+1]
                        if addrMode == AM_R:
                            addr = pos + 2 - (addr & 0x80) + (addr & 0x7f)
                            if 0 <= addr < prgSize:
                                addr += origin
                            else:
                                isInstruction = False  # target outside PRG ROM
                    else:
                        # 2-byte address
                        addr = PRGData[pos+1] | (PRGData[pos+2] << 8)

                    if isInstruction and (
                        # uses absolute/absolute,x/absolute,y instead of zp/zp,x/zp,y?
                        addr <= 0xff and (
                            args.no_abs_zp and addrMode == AM_AB and mnemonic not in ("jmp", "jsr")
                            or args.no_abs_zpx and addrMode == AM_ABX
                            or args.no_abs_zpy and addrMode == AM_ABY and mnemonic == "ldx"
                        )
                        # accesses an excluded address?
                        or any(addr in r for r in noAccess)
                        # writes an excluded address?
                        or mnemonic in WRITE_INSTRUCTIONS
                        and addrMode in WRITE_ADDRESSING_MODES
                        and any(addr in r for r in noWrite)
                        # executes an excluded address?
                        or mnemonic in JUMP_INSTRUCTIONS
                        and addrMode in JUMP_ADDRESSING_MODES
                        and any(addr in r for r in noExecute)
                    ):
                        isInstruction = False
            else:
                isInstruction = False
        else:
            isInstruction = False

        if isInstruction:
            # instruction
            if codeStart is None:
                # start new code chunk
                codeStart = pos
            pos += 1 + operandSize
        else:
            # data byte
            if codeStart is not None:
                # end current code chunk
                yield range(codeStart, pos)
                codeStart = None
            pos += 1

    if codeStart is not None:
        # end last code chunk
        yield range(codeStart, prgSize)

# --- get_label_names() and related ---------------------------------------------------------------

def get_instruction_addresses(handle, instrAddrRanges):
    # generate PRG addresses of instructions
    # instrAddrRanges: set of PRG address ranges

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

def get_access_method(mnemonic, addrMode):
    # how does the instruction access its operand; see enumeration
    if addrMode in (AM_ZX, AM_ZY, AM_ABX, AM_ABY):
        return ACME_ARRAY
    if mnemonic in JUMP_INSTRUCTIONS and addrMode in JUMP_ADDRESSING_MODES:
        return ACME_SUB if mnemonic == "jsr" else ACME_CODE
    return ACME_DATA

def get_label_stats(handle, instrAddrRanges, args):
    # get addresses and statistics of labels from a PRG file
    # instrAddrRanges: set of PRG address ranges
    # return: {
    #     CPU_address: [
    #         set_of_access_methods, first_referring_CPU_address, last_referring_CPU_address
    #     ], ...
    # }

    instrAddresses = set()  # PRG addresses of instructions
    labelStats = {}  # see function description

    prgSize = handle.seek(0, 2)
    origin = 0x10000 - prgSize

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
                # 1-byte address
                addr = PRGData[pos+1]
                if addrMode == AM_R:
                    addr = origin + pos + 2 - (addr & 0x80) + (addr & 0x7f)
            else:
                # 2-byte address
                addr = PRGData[pos+1] | (PRGData[pos+2] << 8)

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
        if addr <= 0x7fff or (
            addr >= origin and (
                addr - origin in instrAddresses
                or not any(addr - origin in rng for rng in instrAddrRanges)
            )
        )
    )

def get_anon_labels_forwards(prgCodeLabels, labelStats, anonLabelsBackwards):
    # generate addresses that can be used as '+' anonymous labels
    # anonLabelsBackwards: previously-found '-' anonymous labels

    for addr in prgCodeLabels:
        # - must be within forward branch range from all references
        # - there must be no labels other than '-' in between
        if labelStats[addr][2] < addr <= labelStats[addr][1] + 2 + 127 and not any(
            labelStats[addr][1] < otherAddr < addr and otherAddr not in anonLabelsBackwards
            for otherAddr in labelStats
        ):
            yield addr

def get_anon_labels_backwards(prgCodeLabels, labelStats, anonLabelsForwards):
    # generate addresses that can be used as '-' anonymous labels
    # anonLabelsForwards: previously-found '+' anonymous labels

    for addr in prgCodeLabels:
        # - must be within backward branch range from all references
        # - there must be no labels other than '+' in between
        if labelStats[addr][2] + 2 - 128 <= addr <= labelStats[addr][1] and not any(
            addr < otherAddr < labelStats[addr][2] and otherAddr not in anonLabelsForwards
            for otherAddr in labelStats
        ):
            yield addr

def get_label_names(handle, instrAddrRanges, args):
    # handle: PRG file, instrAddrRanges: set of ranges, yield: (CPU_address, name)

    labelStats = get_label_stats(handle, instrAddrRanges, args)

    # RAM
    RAMLabels = set(addr for addr in labelStats if addr <= 0x1fff)
    # accessed at least once as an array
    addresses = sorted(addr for addr in RAMLabels if ACME_ARRAY in labelStats[addr][0])
    yield from ((addr, f"arr{i+1}") for (i, addr) in enumerate(addresses))
    # never accessed as an array
    addresses = sorted(addr for addr in RAMLabels if ACME_ARRAY not in labelStats[addr][0])
    yield from ((addr, f"ram{i+1}") for (i, addr) in enumerate(addresses))
    del RAMLabels

    # between RAM and PRG ROM
    # hardware registers
    addresses = sorted(set(labelStats) & set(HARDWARE_REGISTERS))
    yield from ((addr, HARDWARE_REGISTERS[addr]) for addr in addresses)
    # 0x2000-0x7fff excluding hardware registers
    addresses = sorted(
        addr for addr in set(labelStats) - set(HARDWARE_REGISTERS) if 0x2000 <= addr <= 0x7fff
    )
    yield from ((addr, f"misc{i+1}") for (i, addr) in enumerate(addresses))

    # anonymous PRG ROM labels
    anonLabelsForwards  = set()  # "+"
    anonLabelsBackwards = set()  # "-"
    if not args.no_anonymous_labels:
        # addresses only referred to by branches or direct jumps
        prgCodeLabels = set(
            addr for addr in labelStats
            if addr >= 0x8000 and labelStats[addr][0] == set((ACME_CODE,))
        )
        # look for "+" labels, then "-" labels, then "+" labels again
        anonLabelsForwards.update(
            get_anon_labels_forwards(prgCodeLabels, labelStats, anonLabelsBackwards)
        )
        anonLabelsBackwards.update(
            get_anon_labels_backwards(prgCodeLabels, labelStats, anonLabelsForwards)
        )
        anonLabelsForwards.update(
            get_anon_labels_forwards(prgCodeLabels, labelStats, anonLabelsBackwards)
        )
        del prgCodeLabels
        yield from ((addr, "+") for addr in anonLabelsForwards)
        yield from ((addr, "-") for addr in anonLabelsBackwards)

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
    yield from ((addr, f"cod{i+1}") for (i, addr) in enumerate(addresses))
    # data (almost always arrays)
    addresses = sorted(
        addr for addr in namedPRGLabels
        if ACME_SUB not in labelStats[addr][0]
        and ACME_CODE not in labelStats[addr][0]
    )
    yield from ((addr, f"dat{i+1}") for (i, addr) in enumerate(addresses))

# --- disassemble() and related -------------------------------------------------------------------

def print_CDL_stats(cdlData, prgSize):
    if not cdlData:
        print("; No CDL file was used.")
        return
    instrByteCnt = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_CODE)
    dataByteCnt = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_DATA)
    unaccByteCnt = prgSize - instrByteCnt - dataByteCnt
    print(f"; CDL file - instruction bytes: {instrByteCnt}")
    print(f"; CDL file - data        bytes: {dataByteCnt}")
    print(f"; CDL file - unaccessed  bytes: {unaccByteCnt}")

def format_literal(n, *, bits=8, base=16):
    # format an ASM6 integer literal
    # n: integer, bits: 8/16, base: 2/10/16

    if bits == 16:
        assert 0 <= n <= 0xffff
        return f"${n:04x}"
    else:
        assert 0 <= n <= 0xff
        if base == 16:
            return f"${n:02x}"
        elif base == 10:
            return f"{n}"
        else:
            return f"%{n:08b}"

def print_data_line(label, bytes_, origin, PRGAddr, cdlDataRanges, args):
    # print data line (as 2 lines if label is too long)

    if len(label) > args.indentation - 1:
        print(label)
        label = ""

    maxInstructionWidth = args.data_bytes_per_line * 3 + 5
    isUnaccessed = cdlDataRanges and not any(PRGAddr in rng for rng in cdlDataRanges)

    print(
        format(label, f"{args.indentation}s")
        + format("hex " + " ".join(f"{b:02x}" for b in bytes_), f"{maxInstructionWidth}s")
        + f"; {origin+PRGAddr:04x}"
        + (11 * " " + "(unaccessed)" if isUnaccessed else "")
    )

def print_data_lines(data, origin, PRGAddr, labels, cdlDataRanges, args):
    # print lines with data bytes
    # labels: dict

    startOffset = 0  # current block
    prevLabel = ""

    for (offset, byte) in enumerate(data):
        label = labels.get(origin + PRGAddr + offset, "")
        if label or offset - startOffset == args.data_bytes_per_line:
            # a new block starts; print old one, if any
            if offset > startOffset:
                print_data_line(
                    prevLabel, data[startOffset:offset], origin, PRGAddr + startOffset,
                    cdlDataRanges, args
                )
                startOffset = offset
            prevLabel = label

    # print last block, if any
    if len(data) > startOffset:
        print_data_line(
            prevLabel, data[startOffset:], origin, PRGAddr + startOffset, cdlDataRanges, args
        )

def format_operand_value(instrBytes, PRGAddr, labels):
    # instrBytes: 1-3 bytes

    (mnemonic, addrMode) = OPCODES[instrBytes[0]]

    if addrMode in (AM_IMP, AM_AC):
        return ""
    if addrMode == AM_IMM:
        if mnemonic in ("and", "eor", "ora"):
            return format_literal(instrBytes[1], base=2)
        if mnemonic in ("ldx", "ldy", "cpx", "cpy"):
            return format_literal(instrBytes[1], base=10)
        return format_literal(instrBytes[1])
    if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
        # 1-byte address
        addr = instrBytes[1]
        if addrMode == AM_R:
            addr = PRGAddr + 2 - (addr & 0x80) + (addr & 0x7f)
            bits = 16
        else:
            bits = 8
        return labels.get(addr, format_literal(addr, bits=bits))
    # 2-byte address
    addr = instrBytes[1] | (instrBytes[2] << 8)
    return labels.get(addr, format_literal(addr, bits=16))

def print_instruction(label, cpuAddr, instrBytes, operand, isUnaccessed, args):
    # print instruction line (as 2 lines if label is too long)
    # operand: formatted operand

    if len(label) > args.indentation - 1:
        print(label)
        label = ""

    mnemonic = OPCODES[instrBytes[0]][0]
    instrBytesHex = " ".join(f"{b:02x}" for b in instrBytes)

    print(
        format(label, f"{args.indentation}s")
        + format(mnemonic + " " + operand, f"{args.data_bytes_per_line*3+5}s")
        + f"; {cpuAddr:04x}: {instrBytesHex}"
        + ((9 - len(instrBytesHex)) * " " + "(unaccessed)" if isUnaccessed else "")
    )

def disassemble(handle, cdlData, args):
    # disassemble PRG file
    # cdlData: {PRG_address_range: chunk_type, ...}, return: None

    # ranges of PRG addresses
    instrAddrRanges = set(get_instruction_address_ranges(handle, cdlData, args))

    # {CPU_address: name, ...}
    labels = dict(get_label_names(handle, instrAddrRanges, args))

    prgSize = handle.seek(0, 2)
    origin = 0x10000 - prgSize

    print(f"; Input file: {os.path.basename(handle.name)}")
    instrByteCnt = sum(len(rng) for rng in instrAddrRanges)
    print(f"; Bytes - total      : {prgSize}")
    print(f"; Bytes - instruction: {instrByteCnt}")
    print(f"; Bytes - data       : {prgSize-instrByteCnt}")
    anonLabelCnt = sum(1 for a in labels if labels[a] in ("+", "-"))
    print(f"; Labels - total    : {len(labels)}")
    print(f"; Labels - named    : {len(labels)-anonLabelCnt}")
    print(f"; Labels - anonymous: {anonLabelCnt}")
    print_CDL_stats(cdlData, prgSize)
    print()

    print(f"; === Address labels outside PRG ROM ===")
    print()

    # zero page
    for addr in sorted(l for l in labels if l <= 0xff):
        print(f"{labels[addr]:15s} equ {format_literal(addr)}")
    print()

    # other RAM
    for addr in sorted(l for l in labels if 0x0100 <= l <= 0x1fff):
        print(f"{labels[addr]:15s} equ {format_literal(addr,bits=16)}")
    print()

    # memory-mapped registers
    for addr in sorted(HARDWARE_REGISTERS):
        name = ("" if addr in labels else ";") + HARDWARE_REGISTERS[addr]
        print(f"{name:15s} equ {format_literal(addr,bits=16)}")
    print()

    # misc labels at $2000-$7fff
    for addr in sorted(l for l in set(labels) - set(HARDWARE_REGISTERS) if 0x2000 <= l <= 0x7fff):
        print(f"{labels[addr]:15s} equ " + format_literal(addr, bits=16))
    print()

    print(f"; === PRG ROM (CPU ${origin:04x}-${origin+prgSize-1:04x}) ===")
    print()
    print(args.indentation * " " + "org " + format_literal(origin, bits=16))
    print()

    instrAddresses = set(get_instruction_addresses(handle, instrAddrRanges))
    cdlCodeRanges = set(rng for rng in cdlData if cdlData[rng] == CDL_CODE)
    cdlDataRanges = set(rng for rng in cdlData if cdlData[rng] == CDL_DATA)

    handle.seek(0)
    PRGData = handle.read()

    pos = 0  # position in PRG data
    dataStart = None  # where current string of data bytes started
    prevBlockWasData = False

    while pos < prgSize:
        if pos in instrAddresses:
            # instruction

            if dataStart is not None:
                # print previous data block
                if not prevBlockWasData:
                    print()
                print_data_lines(
                    PRGData[dataStart:pos], origin, dataStart, labels, cdlDataRanges, args
                )
                print()
                dataStart = None

            label = labels.get(origin + pos, "")
            (operandSize, operandFormat) = ADDRESSING_MODES[OPCODES[PRGData[pos]][1]]
            instrBytes = PRGData[pos:pos+1+operandSize]  # opcode + operand
            operand = operandFormat.format(format_operand_value(instrBytes, origin + pos, labels))
            isUnaccessed = cdlData and not any(pos in r for r in cdlCodeRanges)

            print_instruction(label, origin + pos, instrBytes, operand, isUnaccessed, args)

            pos += 1 + operandSize
            prevBlockWasData = False
        else:
            # data

            accessed = any(pos in rng for rng in cdlDataRanges)

            if dataStart is None or accessed != prevDataBlockAccessed:
                if dataStart is not None:
                    # print previous data block
                    if not prevBlockWasData:
                        print()
                    print_data_lines(
                        PRGData[dataStart:pos], origin, dataStart, labels, cdlDataRanges, args
                    )
                    prevBlockWasData = True
                # start new data block
                dataStart = pos
                prevDataBlockAccessed = accessed

            pos += 1

    if dataStart is not None:
        # print last data block
        print_data_lines(PRGData[dataStart:], origin, dataStart, labels, cdlDataRanges, args)

    print()

# --- Argument parsing, CDL file reading, main ----------------------------------------------------

def read_cdl_file(handle, prgSize):
    # read an FCEUX CDL file
    # yield: (range_of_PRG_addresses, chunk_type)

    if handle.seek(0, 2) < prgSize:
        sys.exit("The CDL file must be at least as large as the PRG ROM file.")

    handle.seek(0)
    cdlData = handle.read(prgSize)

    chunkStart = None  # start address of current chunk
    chunkType = CDL_UNACCESSED  # type of current chunk

    for (pos, byte) in enumerate(cdlData):
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
        yield (range(chunkStart, prgSize), chunkType)

def main():
    args = parse_arguments()

    # get PRG ROM size
    try:
        prgSize = os.path.getsize(args.input_file)
    except OSError:
        sys.exit("Could not get PRG file size.")
    if not 1 <= prgSize <= 32 * 1024:
        sys.exit("Input file must be 32 KiB or less.")

    # get CDL data
    if args.cdl_file:
        try:
            with open(args.cdl_file, "rb") as handle:
                cdlData = dict(read_cdl_file(handle, prgSize))
        except OSError:
            sys.exit("Error reading CDL file.")
    else:
        cdlData = dict()

    # disassemble input file
    try:
        with open(args.input_file, "rb") as handle:
            disassemble(handle, cdlData, args)
    except OSError:
        sys.exit("Error reading input file.")

if __name__ == "__main__":
    main()
