# NES (6502) disassembler

import argparse, math, os, sys
from nesdisasm_defines import *

def list_opcodes():
    # list supported opcodes
    for opcode in sorted(OPCODES):
        (mnemonic, addrMode) = OPCODES[opcode]
        (operandSize, operandFormat) = ADDRESSING_MODES[addrMode]
        addrModeStr = operandFormat.format(operandSize * "nn")
        print(f'{opcode},"{mnemonic}","{addrModeStr}"')

def parse_arguments():
    # parse command line arguments using argparse
    # note: indentation 0 forbidden as "0s" is an invalid string format code

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
        "--no-zp-ab", action="store_true",
        help="Assume the game never accesses zero page using absolute addressing if the "
        "instruction also supports zeroPage addressing."
    )
    parser.add_argument(
        "--no-zp-abx", action="store_true",
        help="Assume the game never accesses zero page using absolute,x addressing if the "
        "instruction also supports zeroPage,x addressing."
    )
    parser.add_argument(
        "--no-zp-aby", action="store_true",
        help="Assume the game never accesses zero page using absolute,y addressing if the "
        "instruction also supports zeroPage,y addressing."
    )
    parser.add_argument(
        "--no-opcodes", type=str, default="",
        help="Assume the game never executes these opcodes. Zero or more opcodes separated by "
        "commas. Each opcode is an 8-bit hexadecimal integer. E.g. '00,01' = BRK, ORA "
        "(indirect,x)."
    )
    parser.add_argument(
        "--no-access", type=str, default="",
        help="Assume the game never reads/writes/executes these addresses. Zero or more ranges "
        "ranges separated by commas. A range is two 16-bit hexadecimal addresses separated by a "
        "hyphen. E.g. '0800-1fff,2008-3fff,4020-5fff,6000-7fff' = mirrors of RAM, mirrors of PPU "
        "registers, beginning of cartridge space, PRG RAM."
    )
    parser.add_argument(
        "--no-write", type=str, default="",
        help="Assume the game never writes these addresses. Same syntax as in --no-access. E.g. "
        "'8000-ffff' = PRG ROM."
    )
    parser.add_argument(
        "--no-execute", type=str, default="",
        help="Assume the game never executes these addresses. Same syntax as in --no-access. E.g. "
        "'2000-401f' = memory-mapped registers."
    )
    parser.add_argument(
        "--unaccessed-as-data", action="store_true",
        help="Output unaccessed bytes as data instead of trying to disassemble them."
    )
    parser.add_argument(
        "--no-anonymous-labels", action="store_true",
        help="Always use named labels instead of anonymous labels ('+' and '-')."
    )
    parser.add_argument(
        "--list-opcodes", action="store_true",
        help="List supported opcodes in CSV format and exit. (Note: specify a dummy input file.)"
    )
    parser.add_argument(
        "input_file",
        help="The PRG ROM file to read. Size: 32 KiB or less. (.nes files are not supported.)"
    )

    args = parser.parse_args()

    if args.list_opcodes:
        list_opcodes()
        exit()

    if not 1 <= args.indentation <= 100:
        sys.exit("Invalid indentation argument.")
    if not 1 <= args.data_bytes_per_line <= 100:
        sys.exit("Invalid 'data bytes per line' argument.")
    if not os.path.isfile(args.input_file):
        sys.exit("PRG file not found.")
    if args.cdl_file and not os.path.isfile(args.cdl_file):
        sys.exit("CDL file not found.")

    return args

def read_cdl_file(handle, prgSize):
    # read an FCEUX CDL file; generate: (range_of_PRG_addresses, chunk_type)

    if handle.seek(0, 2) < prgSize:
        sys.exit("CDL file must be at least as large as PRG ROM file.")

    handle.seek(0)
    cdlData = handle.read(prgSize)

    chunkStart = None           # start address of current chunk
    chunkType = CDL_UNACCESSED  # type of current chunk

    for (pos, byte) in enumerate(cdlData):
        if byte & 0x1:
            byteType = CDL_CODE
        elif byte & 0x02:
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
    ) or not args.unaccessed_as_data and not any(
        any(addr in r for r in cdlCodeRanges) or any(addr in r for r in cdlDataRanges)
        for addr in addrRange
    )

def decode_16bit_address(byte1, byte2):
    # decode little-endian 16-bit integer
    assert 0x00 <= byte1 <= 0xff
    assert 0x00 <= byte2 <= 0xff
    return byte1 | (byte2 << 8)

def decode_relative_address(pc, offset):
    # decode program counter relative address (note: result may be outside 0x0000-0xffff)
    assert 0x0000 <= pc <= 0xffff
    assert 0x00 <= offset <= 0xff
    return pc + 2 - (offset & 0x80) + (offset & 0x7f)

def get_instruction_address_ranges(handle, cdlData, args):
    # generate PRG address ranges of instructions from a PRG file
    # cdlData: {address_range: chunk_type, ...}, yield: one range per call

    cdlCodeRanges = {rng for rng in cdlData if cdlData[rng] == CDL_CODE}
    cdlDataRanges = {rng for rng in cdlData if cdlData[rng] == CDL_DATA}
    noOpcodes = set(parse_opcodes(args.no_opcodes))
    noAccess  = set(parse_address_ranges(args.no_access))
    noWrite   = set(parse_address_ranges(args.no_write))
    noExecute = set(parse_address_ranges(args.no_execute))

    prgSize = handle.seek(0, 2)
    origin = 0x10000 - prgSize

    handle.seek(0)
    prgData = handle.read()

    codeStart = None  # start of current code chunk
    pos = 0  # position in PRG data

    # quite similar to main loops elsewhere
    while pos < prgSize:
        opcode = prgData[pos]

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
                        addr = prgData[pos+1]
                        if addrMode == AM_R:
                            addr = decode_relative_address(pos, addr)
                            if 0 <= addr < prgSize:
                                addr += origin
                            else:
                                isInstruction = False  # target outside PRG ROM
                    else:
                        # 2-byte address
                        addr = decode_16bit_address(prgData[pos+1], prgData[pos+2])

                    if isInstruction and (
                        # uses absolute/absolute,x/absolute,y instead of zp/zp,x/zp,y?
                        addr <= 0xff and (
                            args.no_zp_ab and addrMode == AM_AB and mnemonic not in ("jmp", "jsr")
                            or args.no_zp_abx and addrMode == AM_ABX
                            or args.no_zp_aby and addrMode == AM_ABY and mnemonic == "ldx"
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
    prgData = handle.read()

    pos = 0  # position in PRG ROM

    for pos in get_instruction_addresses(handle, instrAddrRanges):
        instrAddresses.add(pos)

        opcode = prgData[pos]
        (mnemonic, addrMode) = OPCODES[opcode]

        if addrMode not in (AM_IMP, AM_AC, AM_IMM):
            # operand is an address
            # decode operand
            if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
                # 1-byte address
                addr = prgData[pos+1]
                if addrMode == AM_R:
                    addr = decode_relative_address(origin + pos, addr)
            else:
                # 2-byte address
                addr = decode_16bit_address(prgData[pos+1], prgData[pos+2])

            # remember access method, first reference and last reference
            accessMethod = get_access_method(mnemonic, addrMode)
            referrer = origin + pos
            if addr in labelStats:
                labelStats[addr][0].add(accessMethod)
                labelStats[addr][1] = min(labelStats[addr][1], referrer)
                labelStats[addr][2] = max(labelStats[addr][2], referrer)
            else:
                labelStats[addr] = [{accessMethod,}, referrer, referrer]

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

    # 0x0000-0x1fff
    RAMLabels = {addr for addr in labelStats if addr <= 0x1fff}
    # accessed at least once as an array
    addresses = sorted(addr for addr in RAMLabels if ACME_ARRAY in labelStats[addr][0])
    yield from ((addr, f"arr{i+1}") for (i, addr) in enumerate(addresses))
    # never accessed as an array
    addresses = sorted(addr for addr in RAMLabels if ACME_ARRAY not in labelStats[addr][0])
    yield from ((addr, f"ram{i+1}") for (i, addr) in enumerate(addresses))
    del RAMLabels

    # 0x2000-0x7fff
    # hardware registers
    addresses = sorted(set(labelStats) & set(HARDWARE_REGISTERS))
    yield from ((addr, HARDWARE_REGISTERS[addr]) for addr in addresses)
    # other
    addresses = sorted(
        addr for addr in set(labelStats) - set(HARDWARE_REGISTERS) if 0x2000 <= addr <= 0x7fff
    )
    yield from ((addr, f"misc{i+1}") for (i, addr) in enumerate(addresses))

    # anonymous PRG ROM labels
    anonLabelsForwards  = set()  # "+"
    anonLabelsBackwards = set()  # "-"
    if not args.no_anonymous_labels:
        # addresses only referred to by branches or direct jumps
        prgCodeLabels = {
            addr for addr in labelStats if addr >= 0x8000 and labelStats[addr][0] == {ACME_CODE,}
        }
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
    namedPrgLabels = \
    {addr for addr in set(labelStats) if addr >= 0x8000} - anonLabelsForwards - anonLabelsBackwards
    del anonLabelsForwards, anonLabelsBackwards
    # subs
    addresses = sorted(
        addr for addr in namedPrgLabels if ACME_SUB in labelStats[addr][0]
    )
    yield from ((addr, f"sub{i+1}") for (i, addr) in enumerate(addresses))
    # other code
    addresses = sorted(
        addr for addr in namedPrgLabels
        if ACME_SUB not in labelStats[addr][0]
        and ACME_CODE in labelStats[addr][0]
    )
    yield from ((addr, f"cod{i+1}") for (i, addr) in enumerate(addresses))
    # data (almost always arrays)
    addresses = sorted(
        addr for addr in namedPrgLabels
        if ACME_SUB not in labelStats[addr][0]
        and ACME_CODE not in labelStats[addr][0]
    )
    yield from ((addr, f"dat{i+1}") for (i, addr) in enumerate(addresses))

# --- disassemble() and related -------------------------------------------------------------------

def print_cdl_stats(cdlData, prgSize):
    if not cdlData:
        print("; No CDL file was used.")
        return
    instrByteCnt = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_CODE)
    dataByteCnt = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_DATA)
    unaccByteCnt = prgSize - instrByteCnt - dataByteCnt
    print(f"; CDL file - instruction bytes: {instrByteCnt}")
    print(f"; CDL file - data        bytes: {dataByteCnt}")
    print(f"; CDL file - unaccessed  bytes: {unaccByteCnt}")

def format_literal(n, bits=8):
    # format an ASM6 integer literal
    assert bits in (8, 16) and 0 <= n < 2 ** bits
    return f"${n:02x}" if bits == 8 else f"${n:04x}"

def print_data_line(label, bytes_, origin, prgAddr, cdlDataRanges, args):
    # print data line (as 2 lines if label is too long)

    if len(label) > args.indentation - 1:
        print(label)
        label = ""

    maxInstructionWidth = args.data_bytes_per_line * 3 + 5
    isUnaccessed = cdlDataRanges and not any(prgAddr in rng for rng in cdlDataRanges)

    print(
        format(label, f"{args.indentation}s")
        + format("hex " + " ".join(f"{b:02x}" for b in bytes_), f"{maxInstructionWidth}s")
        + f"; {origin+prgAddr:04x}"
        + (11 * " " + "(unaccessed)" if isUnaccessed else "")
    )

def print_data_lines(data, origin, prgAddr, labels, cdlDataRanges, args):
    # print lines with data bytes
    # labels: dict

    startOffset = 0  # current block
    prevLabel = ""

    for (offset, byte) in enumerate(data):
        label = labels.get(origin + prgAddr + offset, "")
        if label or offset - startOffset == args.data_bytes_per_line:
            # a new block starts; print old one, if any
            if offset > startOffset:
                print_data_line(
                    prevLabel, data[startOffset:offset], origin, prgAddr + startOffset,
                    cdlDataRanges, args
                )
                startOffset = offset
            prevLabel = label

    # print last block, if any
    if len(data) > startOffset:
        print_data_line(
            prevLabel, data[startOffset:], origin, prgAddr + startOffset, cdlDataRanges, args
        )

def format_operand_value(instrBytes, prgAddr, labels):
    # instrBytes: 1-3 bytes

    (mnemonic, addrMode) = OPCODES[instrBytes[0]]

    if addrMode in (AM_IMP, AM_AC):
        return ""
    if addrMode == AM_IMM:
        return format_literal(instrBytes[1])
    if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
        # 1-byte address
        addr = instrBytes[1]
        if addrMode == AM_R:
            addr = decode_relative_address(prgAddr, addr)
            bits = 16
        else:
            bits = 8
        return labels.get(addr, format_literal(addr, bits))
    # 2-byte address
    addr = decode_16bit_address(instrBytes[1], instrBytes[2])
    return labels.get(addr, format_literal(addr, 16))

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
    print_cdl_stats(cdlData, prgSize)
    print()

    print(f"; === Address constants at $0000-$7fff ===")
    print()
    print("; 'arr' = RAM array, 'ram' = RAM non-array, 'misc' = $2000-$7fff")
    print("; note: unused hardware registers commented out")
    print()
    # unused hardware registers are printed but commented out
    for addr in sorted(l for l in set(labels) | set(HARDWARE_REGISTERS) if l <= 0x7fff):
        name = labels[addr] if addr in labels else ";" + HARDWARE_REGISTERS[addr]
        print(f"{name:15s} equ " + format_literal(addr, 8 if addr <= 0xff else 16))
    print()

    print(f"; === PRG ROM (CPU ${origin:04x}-${origin+prgSize-1:04x}) ===")
    print()
    print("; labels: 'sub' = subroutine, 'cod' = code, 'dat' = data")
    print()
    print(args.indentation * " " + "org " + format_literal(origin, 16))
    print()

    instrAddresses = set(get_instruction_addresses(handle, instrAddrRanges))
    cdlCodeRanges = {rng for rng in cdlData if cdlData[rng] == CDL_CODE}
    cdlDataRanges = {rng for rng in cdlData if cdlData[rng] == CDL_DATA}

    handle.seek(0)
    prgData = handle.read()

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
                    prgData[dataStart:pos], origin, dataStart, labels, cdlDataRanges, args
                )
                print()
                dataStart = None

            label = labels.get(origin + pos, "")
            (operandSize, operandFormat) = ADDRESSING_MODES[OPCODES[prgData[pos]][1]]
            instrBytes = prgData[pos:pos+1+operandSize]  # opcode + operand
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
                        prgData[dataStart:pos], origin, dataStart, labels, cdlDataRanges, args
                    )
                    prevBlockWasData = True
                # start new data block
                dataStart = pos
                prevDataBlockAccessed = accessed

            pos += 1

    if dataStart is not None:
        # print last data block
        print_data_lines(prgData[dataStart:], origin, dataStart, labels, cdlDataRanges, args)

    print()

def main():
    args = parse_arguments()

    # get PRG file size
    try:
        prgSize = os.path.getsize(args.input_file)
    except OSError:
        sys.exit("Error getting PRG file size.")
    if not 1 <= prgSize <= 32 * 1024:
        sys.exit("Invalid PRG file size.")

    # read CDL file
    if args.cdl_file:
        try:
            with open(args.cdl_file, "rb") as handle:
                cdlData = dict(read_cdl_file(handle, prgSize))
        except OSError:
            sys.exit("Error reading CDL file.")
    else:
        cdlData = dict()

    # disassemble PRG file
    try:
        with open(args.input_file, "rb") as handle:
            disassemble(handle, cdlData, args)
    except OSError:
        sys.exit("Error reading input file.")

if __name__ == "__main__":
    main()
