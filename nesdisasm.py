# an NES (6502) disassembler

import argparse, math, os, sys

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
    AM_R,    # program counter relative
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
# note: four opcodes per line, but newline before 0x10, 0x20, etc.
OPCODES = {
    0x00: ("brk", AM_IMP), 0x01: ("ora", AM_IX), 0x05: ("ora", AM_Z), 0x06: ("asl", AM_Z),
    0x08: ("php", AM_IMP), 0x09: ("ora", AM_IMM), 0x0a: ("asl", AM_AC), 0x0d: ("ora", AM_AB),
    0x0e: ("asl", AM_AB),
    0x10: ("bpl", AM_R), 0x11: ("ora", AM_IY), 0x15: ("ora", AM_ZX), 0x16: ("asl", AM_ZX),
    0x18: ("clc", AM_IMP), 0x19: ("ora", AM_ABY), 0x1d: ("ora", AM_ABX), 0x1e: ("asl", AM_ABX),
    0x20: ("jsr", AM_AB), 0x21: ("and", AM_IX), 0x24: ("bit", AM_Z), 0x25: ("and", AM_Z),
    0x26: ("rol", AM_Z), 0x28: ("plp", AM_IMP), 0x29: ("and", AM_IMM), 0x2a: ("rol", AM_AC),
    0x2c: ("bit", AM_AB), 0x2d: ("and", AM_AB), 0x2e: ("rol", AM_AB),
    0x30: ("bmi", AM_R), 0x31: ("and", AM_IY), 0x35: ("and", AM_ZX), 0x36: ("rol", AM_ZX),
    0x38: ("sec", AM_IMP), 0x39: ("and", AM_ABY), 0x3d: ("and", AM_ABX), 0x3e: ("rol", AM_ABX),
    0x40: ("rti", AM_IMP), 0x41: ("eor", AM_IX), 0x45: ("eor", AM_Z), 0x46: ("lsr", AM_Z),
    0x48: ("pha", AM_IMP), 0x49: ("eor", AM_IMM), 0x4a: ("lsr", AM_AC), 0x4c: ("jmp", AM_AB),
    0x4d: ("eor", AM_AB), 0x4e: ("lsr", AM_AB),
    0x50: ("bvc", AM_R), 0x51: ("eor", AM_IY), 0x55: ("eor", AM_ZX), 0x56: ("lsr", AM_ZX),
    0x58: ("cli", AM_IMP), 0x59: ("eor", AM_ABY), 0x5d: ("eor", AM_ABX), 0x5e: ("lsr", AM_ABX),
    0x60: ("rts", AM_IMP), 0x61: ("adc", AM_IX), 0x65: ("adc", AM_Z), 0x66: ("ror", AM_Z),
    0x68: ("pla", AM_IMP), 0x69: ("adc", AM_IMM), 0x6a: ("ror", AM_AC), 0x6c: ("jmp", AM_I),
    0x6d: ("adc", AM_AB), 0x6e: ("ror", AM_AB),
    0x70: ("bvs", AM_R), 0x71: ("adc", AM_IY), 0x75: ("adc", AM_ZX), 0x76: ("ror", AM_ZX),
    0x78: ("sei", AM_IMP), 0x79: ("adc", AM_ABY), 0x7d: ("adc", AM_ABX), 0x7e: ("ror", AM_ABX),
    0x81: ("sta", AM_IX), 0x84: ("sty", AM_Z), 0x85: ("sta", AM_Z), 0x86: ("stx", AM_Z),
    0x88: ("dey", AM_IMP), 0x8a: ("txa", AM_IMP), 0x8c: ("sty", AM_AB), 0x8d: ("sta", AM_AB),
    0x8e: ("stx", AM_AB),
    0x90: ("bcc", AM_R), 0x91: ("sta", AM_IY), 0x94: ("sty", AM_ZX), 0x95: ("sta", AM_ZX),
    0x96: ("stx", AM_ZY), 0x98: ("tya", AM_IMP), 0x99: ("sta", AM_ABY), 0x9a: ("txs", AM_IMP),
    0x9d: ("sta", AM_ABX),
    0xa0: ("ldy", AM_IMM), 0xa1: ("lda", AM_IX), 0xa2: ("ldx", AM_IMM), 0xa4: ("ldy", AM_Z),
    0xa5: ("lda", AM_Z), 0xa6: ("ldx", AM_Z), 0xa8: ("tay", AM_IMP), 0xa9: ("lda", AM_IMM),
    0xaa: ("tax", AM_IMP), 0xac: ("ldy", AM_AB), 0xad: ("lda", AM_AB), 0xae: ("ldx", AM_AB),
    0xb0: ("bcs", AM_R), 0xb1: ("lda", AM_IY), 0xb4: ("ldy", AM_ZX), 0xb5: ("lda", AM_ZX),
    0xb6: ("ldx", AM_ZY), 0xb8: ("clv", AM_IMP), 0xb9: ("lda", AM_ABY), 0xba: ("tsx", AM_IMP),
    0xbc: ("ldy", AM_ABX), 0xbd: ("lda", AM_ABX), 0xbe: ("ldx", AM_ABY),
    0xc0: ("cpy", AM_IMM), 0xc1: ("cmp", AM_IX), 0xc4: ("cpy", AM_Z), 0xc5: ("cmp", AM_Z),
    0xc6: ("dec", AM_Z), 0xc8: ("iny", AM_IMP), 0xc9: ("cmp", AM_IMM), 0xca: ("dex", AM_IMP),
    0xcc: ("cpy", AM_AB), 0xcd: ("cmp", AM_AB), 0xce: ("dec", AM_AB),
    0xd0: ("bne", AM_R), 0xd1: ("cmp", AM_IY), 0xd5: ("cmp", AM_ZX), 0xd6: ("dec", AM_ZX),
    0xd8: ("cld", AM_IMP), 0xd9: ("cmp", AM_ABY), 0xdd: ("cmp", AM_ABX), 0xde: ("dec", AM_ABX),
    0xe0: ("cpx", AM_IMM), 0xe1: ("sbc", AM_IX), 0xe4: ("cpx", AM_Z), 0xe5: ("sbc", AM_Z),
    0xe6: ("inc", AM_Z), 0xe8: ("inx", AM_IMP), 0xe9: ("sbc", AM_IMM), 0xea: ("nop", AM_IMP),
    0xec: ("cpx", AM_AB), 0xed: ("sbc", AM_AB), 0xee: ("inc", AM_AB),
    0xf0: ("beq", AM_R), 0xf1: ("sbc", AM_IY), 0xf5: ("sbc", AM_ZX), 0xf6: ("inc", AM_ZX),
    0xf8: ("sed", AM_IMP), 0xf9: ("sbc", AM_ABY), 0xfd: ("sbc", AM_ABX), 0xfe: ("inc", AM_ABX),
}
assert all(0x00 <= o <= 0xff for o in OPCODES)
assert all(len(OPCODES[o][0]) == 3 for o in OPCODES)
assert all(OPCODES[o][1] in ADDRESSING_MODES for o in OPCODES)

# NES memory-mapped registers
HARDWARE_REGISTERS = {
    0x2000: "ppu_ctrl", 0x2001: "ppu_mask", 0x2002: "ppu_status", 0x2003: "oam_addr",
    0x2004: "oam_data", 0x2005: "ppu_scroll", 0x2006: "ppu_addr", 0x2007: "ppu_data",
    0x4000: "sq1_vol", 0x4001: "sq1_sweep", 0x4002: "sq1_lo", 0x4003: "sq1_hi",
    0x4004: "sq2_vol", 0x4005: "sq2_sweep", 0x4006: "sq2_lo", 0x4007: "sq2_hi",
    0x4008: "tri_linear", 0x400a: "tri_lo", 0x400b: "tri_hi",
    0x400c: "noise_vol", 0x400e: "noise_lo", 0x400f: "noise_hi",
    0x4010: "dmc_freq", 0x4011: "dmc_raw", 0x4012: "dmc_start", 0x4013: "dmc_len",
    0x4014: "oam_dma", 0x4015: "snd_chn", 0x4016: "joypad1", 0x4017: "joypad2",
    # http://wiki.nesdev.com/w/index.php/CPU_Test_Mode
    0x4018: "apu_test1", 0x4019: "apu_test2", 0x401a: "apu_test3",
    0x401c: "cpu_timer1", 0x401d: "cpu_timer2", 0x401e: "cpu_timer3", 0x401f: "cpu_timer4",
}
assert all(0x2000 <= r <= 0x401f for r in HARDWARE_REGISTERS)

# enumerate CDL file chunk types
(
    CDL_UNACCESSED,  # not accessed
    CDL_CODE,        # accessed as code (and possibly also as data)
    CDL_INDIR_DATA,  # accessed as indirect data (and possibly also as direct data)
    CDL_DATA,        # accessed as direct data only
) = range(4)

# enumerate label access methods
(
    ACME_ARRAY,  # array (zeroPage,x / zeroPage,y / absolute,x / absolute,y)
    ACME_SUB,    # subroutine (JSR)
    ACME_CODE,   # other code (branch / JMP absolute)
    ACME_DATA,   # data (none of the above)
) = range(4)

# bitmasks for CDL bytes
CDL_CODE_MASK          = 1 << 0
CDL_DATA_MASK          = 1 << 1
CDL_INDIRECT_DATA_MASK = 1 << 5

def list_opcodes():
    # list supported opcodes
    for opcode in sorted(OPCODES):
        (mnemonic, addrMode) = OPCODES[opcode]
        (operandSize, operandFormat) = ADDRESSING_MODES[addrMode]
        addrModeStr = operandFormat.format(operandSize * "nn")
        print(f"0x{opcode:02x} = {mnemonic} {addrModeStr}")

def parse_arguments():
    # parse command line arguments using argparse
    # note: indentation 0 forbidden as "0s" is an invalid string format code

    parser = argparse.ArgumentParser(description="An NES (6502) disassembler.")

    parser.add_argument(
        "-c", "--cdl-file", type=str, default="",
        help="The FCEUX code/data log file (.cdl) to read. (If you don't specify one, all PRG "
        "ROM bytes will be considered unaccessed.)"
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
        "-a", "--no-access", type=str, default="",
        help="Assume the game never interacts with these addresses (using any instruction with "
        "absolute addressing, or indexed absolute with these addresses as the base address). Zero "
        "or more ranges separated by commas. A range is two 16-bit hexadecimal addresses "
        "separated by a hyphen. E.g. '0800-1fff,2008-3fff,4020-5fff,6000-7fff' = mirrors of RAM, "
        "mirrors of PPU registers, beginning of cartridge space, PRG RAM."
    )
    parser.add_argument(
        "-w", "--no-write", type=str, default="",
        help="Assume the game never writes these addresses (using STA/STX/STY/DEC/INC/ASL/LSR/ROL/"
        "ROR with absolute addressing, or indexed absolute with these addresses as the base "
        "address). Same syntax as in --no-access. E.g. '8000-ffff' = PRG ROM."
    )
    parser.add_argument(
        "--no-anonymous-labels", action="store_true",
        help="Always use named labels instead of anonymous labels ('+' and '-')."
    )
    parser.add_argument(
        "-l", "--list-opcodes", action="store_true",
        help="List supported opcodes and exit. (Note: specify a dummy input file.)"
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

    # read CDL data corresponding to PRG data (if PRG data is less than 16 KiB, read from end of
    # first 16 KiB of CDL data)
    cdlSize = handle.seek(0, 2)
    if prgSize < 16 * 1024 and cdlSize >= 16 * 1024:
        cdlStart = 16 * 1024 - prgSize
    else:
        cdlStart = 0
    handle.seek(cdlStart)
    cdlData = handle.read(prgSize)

    chunkStart = None           # start address of current chunk
    chunkType = CDL_UNACCESSED  # type of current chunk

    for (pos, byte) in enumerate(cdlData):
        if byte & CDL_CODE_MASK:
            byteType = CDL_CODE
        elif byte & CDL_DATA_MASK:
            if byte & CDL_INDIRECT_DATA_MASK:
                byteType = CDL_INDIR_DATA
            else:
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

def instruction_allowed_at_address(addrRange, cdlCodeRanges, cdlDataRanges):
    # does the CDL data allow an instruction at addrRange?
    # either all bytes must be code or all bytes must be unaccessed
    # (comments denoting unaccessed code can only be printed at the start of each instruction)

    return any(
        addrRange.start in r and addrRange.stop - 1 in r for r in cdlCodeRanges
    ) or not any(
        any(a in r for r in cdlCodeRanges) or any(a in r for r in cdlDataRanges)
        for a in addrRange
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

def get_instruction_address_ranges(prgData, cdlData, args):
    # generate PRG address ranges of instructions from PRG data
    # cdlData: {address_range: chunk_type, ...}, yield: one range per call

    cdlCodeRanges = {rng for rng in cdlData if cdlData[rng] == CDL_CODE}
    cdlDataRanges = {rng for rng in cdlData if cdlData[rng] in (CDL_INDIR_DATA, CDL_DATA)}
    noAccess = set(parse_address_ranges(args.no_access))
    noWrite  = set(parse_address_ranges(args.no_write))

    origin = 0x10000 - len(prgData)

    codeStart = None  # start of current code chunk
    pos = 0  # position in PRG data

    # quite similar to main loops elsewhere
    while pos < len(prgData):
        opcode = prgData[pos]

        # does the remaining PRG ROM start with an instruction?
        # (the long mess of code may or may not set this variable to True)
        isInstruction = False
        # documented opcode?
        if opcode in OPCODES:
            (mnemonic, addrMode) = OPCODES[opcode]
            operandSize = ADDRESSING_MODES[addrMode][0]
            # enough space left for operand; address not forbidden by CDL file?
            if len(prgData) - pos >= 1 + operandSize and instruction_allowed_at_address(
                range(pos, pos + 1 + operandSize), cdlCodeRanges, cdlDataRanges
            ):
                # validate operand
                if addrMode in (AM_AB, AM_ABX, AM_ABY):
                    # direct absolute
                    addr = decode_16bit_address(prgData[pos+1], prgData[pos+2])
                    isInstruction = not (
                        # accesses an excluded address?
                        any(addr in r for r in noAccess)
                        # writes an excluded address?
                        or mnemonic in (
                            "sta", "stx", "sty", "dec", "inc", "asl", "lsr", "rol", "ror"
                        )
                        and any(addr in r for r in noWrite)
                    )
                elif addrMode == AM_R:
                    # relative (target must be within PRG ROM)
                    if 0 <= decode_relative_address(pos, prgData[pos+1]) < len(prgData):
                        isInstruction = True
                else:
                    # indirect or less than two bytes
                    isInstruction = True

        if isInstruction:
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
        yield range(codeStart, len(prgData))

def get_instruction_addresses(prgData, instrAddrRanges):
    # generate PRG addresses of instructions
    # instrAddrRanges: set of PRG address ranges

    for rng in instrAddrRanges:
        pos = rng.start
        while pos < rng.stop:
            yield pos
            pos += 1 + ADDRESSING_MODES[OPCODES[prgData[pos]][1]][0]  # operand size

def get_access_method(mnemonic, addrMode):
    # how does the instruction access its operand; see enumeration
    if addrMode in (AM_ZX, AM_ZY, AM_ABX, AM_ABY):
        return ACME_ARRAY
    if mnemonic == "jsr":
        return ACME_SUB
    if mnemonic == "jmp" and addrMode == AM_AB \
    or mnemonic in ("bne", "beq", "bpl", "bmi", "bcc", "bcs", "bvc", "bvs"):
        return ACME_CODE
    return ACME_DATA

def get_label_stats(prgData, instrAddrRanges, args):
    # get addresses and statistics of labels from PRG data
    # instrAddrRanges: set of PRG address ranges
    # return: {
    #     CPU_address: [
    #         set_of_access_methods, first_referring_CPU_address, last_referring_CPU_address
    #     ], ...
    # }

    instrAddresses = set()  # PRG addresses of instructions
    labelStats = {}  # see function description

    origin = 0x10000 - len(prgData)
    pos = 0  # position in PRG ROM

    for pos in get_instruction_addresses(prgData, instrAddrRanges):
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

def get_label_names(prgData, instrAddrRanges, args):
    # instrAddrRanges: set of ranges, yield: (CPU_address, name)

    labelStats = get_label_stats(prgData, instrAddrRanges, args)

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

def print_cdl_stats(cdlData, prgSize):
    instrByteCnt     = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_CODE)
    indirDataByteCnt = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_INDIR_DATA)
    dirDataByteCnt   = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_DATA)
    unaccByteCnt = prgSize - instrByteCnt - indirDataByteCnt - dirDataByteCnt
    print("; Bytes in CDL file:")
    print("; - instruction  :", instrByteCnt)
    print("; - indirect data:", indirDataByteCnt)
    print("; - direct data  :", dirDataByteCnt)
    print("; - unaccessed   :", unaccByteCnt)

def is_abs_opcode_with_zp_equivalent(opcode):
    # is the opcode an absolute/absolute,x/absolute,y opcode that has a zero page equivalent?

    (mnemonic, addrMode) = OPCODES[opcode]
    return (
        addrMode == AM_AB and mnemonic not in ("jmp", "jsr")
        or addrMode == AM_ABX
        or addrMode == AM_ABY and mnemonic == "ldx"
    )

def get_needed_macros(prgData, instrAddrRanges):
    # which macros need to be defined? return a set of opcodes

    instrAddresses = set(get_instruction_addresses(prgData, instrAddrRanges))
    pos = 0
    # get opcodes for instructions that ASM6 would auto-optimize (2-byte operand <= $00ff, has a
    # zeropage equivalent)
    opcodes = set()
    while pos < len(prgData):
        if pos in instrAddresses:
            # instruction
            operandSize = ADDRESSING_MODES[OPCODES[prgData[pos]][1]][0]
            if operandSize == 2 and prgData[pos+2] == 0:
                opcodes.add(prgData[pos])
            pos += 1 + operandSize
        else:
            # data
            pos += 1
    return {o for o in opcodes if is_abs_opcode_with_zp_equivalent(o)}

def format_literal(n, bits=8, base=16):
    # format an ASM6 integer literal
    assert bits in (8, 16) and 0 <= n < 2 ** bits
    assert base in (2, 16)
    if base == 2:
        return f"%{n:08b}"
    return f"${n:02x}" if bits == 8 else f"${n:04x}"

def print_data_line(label, bytes_, origin, prgAddr, cdlDataRanges, args):
    # print data line (as 2 lines if label is too long)

    if len(label) > args.indentation - 1:
        print(label)
        label = ""

    maxInstructionWidth = args.data_bytes_per_line * 3 + 5
    isUnaccessed = not any(prgAddr in rng for rng in cdlDataRanges)

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
        base = 2 if mnemonic in ("and", "eor", "ora") else 16
        return format_literal(instrBytes[1], 8, base)
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

    if is_abs_opcode_with_zp_equivalent(instrBytes[0]) and instrBytes[2] == 0x00:
        # use macro instead of mnemonic
        (mnemonic, addrMode) = OPCODES[instrBytes[0]]
        addrModeName = {AM_AB: "abs", AM_ABX: "absx", AM_ABY: "absy"}[addrMode]
        mnemonic = f"{mnemonic}_{addrModeName}"
    else:
        mnemonic = OPCODES[instrBytes[0]][0]

    instrBytesHex = " ".join(f"{b:02x}" for b in instrBytes)

    print(
        format(label, f"{args.indentation}s")
        + format(mnemonic + " " + operand, f"{args.data_bytes_per_line*3+5}s")
        + f"; {cpuAddr:04x}: {instrBytesHex}"
        + ((9 - len(instrBytesHex)) * " " + "(unaccessed)" if isUnaccessed else "")
    )

def disassemble(prgData, cdlData, args):
    # disassemble PRG data
    # cdlData: {PRG_address_range: chunk_type, ...}, return: None

    # ranges of PRG addresses
    instrAddrRanges = set(get_instruction_address_ranges(prgData, cdlData, args))

    # {CPU_address: name, ...}
    labels = dict(get_label_names(prgData, instrAddrRanges, args))

    instrByteCnt = sum(len(rng) for rng in instrAddrRanges)
    print("; Bytes:")
    print("; - instruction:", instrByteCnt)
    print("; - data       :", len(prgData) - instrByteCnt)
    anonLabelCnt = sum(1 for a in labels if labels[a] in ("+", "-"))
    print("; Labels:")
    print("; - named    :", len(labels) - anonLabelCnt)
    print("; - anonymous:", anonLabelCnt)
    print_cdl_stats(cdlData, len(prgData))
    print()

    print("; === Macros ===")
    print()
    print("; force 16-bit addressing (absolute/absolute,x/absolute,y) with operands <= $ff")
    for opcode in sorted(get_needed_macros(prgData, instrAddrRanges)):
        (mnemonic, addrMode) = OPCODES[opcode]
        addrModeName = {AM_AB: "abs", AM_ABX: "absx", AM_ABY: "absy"}[addrMode]
        print(f"macro {mnemonic}_{addrModeName} _zp")
        print(args.indentation * " " + f"db ${opcode:02x}, _zp, $00")
        print("endm")
    print()

    print("; === Address constants at $0000-$7fff ===")
    print()
    print("; 'arr' = RAM array, 'ram' = RAM non-array, 'misc' = $2000-$7fff")
    print("; note: unused hardware registers commented out")
    print()
    for addr in sorted(l for l in set(labels) | set(HARDWARE_REGISTERS) if l <= 0x7fff):
        name = labels[addr] if addr in labels else ";" + HARDWARE_REGISTERS[addr]
        print(f"{name:15s} equ " + format_literal(addr, 8 if addr <= 0xff else 16))
    print()

    origin = 0x10000 - len(prgData)

    print(f"; === PRG ROM (CPU ${origin:04x}-${origin+len(prgData)-1:04x}) ===")
    print()
    print("; labels: 'sub' = subroutine, 'cod' = code, 'dat' = data")
    print()
    print(args.indentation * " " + "org " + format_literal(origin, 16))
    print()

    instrAddresses = set(get_instruction_addresses(prgData, instrAddrRanges))
    cdlCodeRanges = {rng for rng in cdlData if cdlData[rng] == CDL_CODE}
    cdlDataRanges = {rng for rng in cdlData if cdlData[rng] in (CDL_INDIR_DATA, CDL_DATA)}

    pos = 0  # position in PRG data
    dataStart = None  # where current string of data bytes started
    prevBlockWasData = False

    while pos < len(prgData):
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
            isUnaccessed = not any(pos in r for r in cdlCodeRanges)

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

    # read PRG file
    try:
        with open(args.input_file, "rb") as handle:
            handle.seek(0)
            prgData = handle.read()
    except OSError:
        sys.exit("Error reading PRG file.")

    if not 1 <= len(prgData) <= 32 * 1024:
        sys.exit("Invalid PRG file size.")

    # read CDL file
    if args.cdl_file:
        try:
            if os.path.getsize(args.cdl_file) < len(prgData):
                sys.exit("The CDL file must be at least as large as the PRG file.")
            with open(args.cdl_file, "rb") as handle:
                cdlData = dict(read_cdl_file(handle, len(prgData)))
        except OSError:
            sys.exit("Error reading CDL file.")
    else:
        cdlData = dict()

    disassemble(prgData, cdlData, args)

main()
