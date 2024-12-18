# an NES (6502) disassembler; see https://github.com/qalle2/nes-disasm

import argparse, os, sys

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
ADDR_MODES = {
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

# names of addressing modes in names of macros
MACRO_ADDR_MODE_NAMES = {
    AM_AB:  "abs",
    AM_ABX: "absx",
    AM_ABY: "absy",
}

# enumerate mnemonics
(
    I_ADC, I_AND, I_ASL, I_BCC, I_BCS, I_BEQ, I_BIT, I_BMI, I_BNE, I_BPL,
    I_BRK, I_BVC, I_BVS, I_CLC, I_CLD, I_CLI, I_CLV, I_CMP, I_CPX, I_CPY,
    I_DEC, I_DEX, I_DEY, I_EOR, I_INC, I_INX, I_INY, I_JMP, I_JSR, I_LDA,
    I_LDX, I_LDY, I_LSR, I_NOP, I_ORA, I_PHA, I_PHP, I_PLA, I_PLP, I_ROL,
    I_ROR, I_RTI, I_RTS, I_SBC, I_SEC, I_SED, I_SEI, I_STA, I_STX, I_STY,
    I_TAX, I_TAY, I_TSX, I_TXA, I_TXS, I_TYA,
) = range(56)

# mnemonic: string
MNEMONICS = {
    I_ADC: "adc", I_AND: "and", I_ASL: "asl", I_BCC: "bcc", I_BCS: "bcs",
    I_BEQ: "beq", I_BIT: "bit", I_BMI: "bmi", I_BNE: "bne", I_BPL: "bpl",
    I_BRK: "brk", I_BVC: "bvc", I_BVS: "bvs", I_CLC: "clc", I_CLD: "cld",
    I_CLI: "cli", I_CLV: "clv", I_CMP: "cmp", I_CPX: "cpx", I_CPY: "cpy",
    I_DEC: "dec", I_DEX: "dex", I_DEY: "dey", I_EOR: "eor", I_INC: "inc",
    I_INX: "inx", I_INY: "iny", I_JMP: "jmp", I_JSR: "jsr", I_LDA: "lda",
    I_LDX: "ldx", I_LDY: "ldy", I_LSR: "lsr", I_NOP: "nop", I_ORA: "ora",
    I_PHA: "pha", I_PHP: "php", I_PLA: "pla", I_PLP: "plp", I_ROL: "rol",
    I_ROR: "ror", I_RTI: "rti", I_RTS: "rts", I_SBC: "sbc", I_SEC: "sec",
    I_SED: "sed", I_SEI: "sei", I_STA: "sta", I_STX: "stx", I_STY: "sty",
    I_TAX: "tax", I_TAY: "tay", I_TSX: "tsx", I_TXA: "txa", I_TXS: "txs",
    I_TYA: "tya",
}

# opcode: (mnemonic, addressing mode)
OPCODES = {
    0x00: (I_BRK, AM_IMP), 0x01: (I_ORA, AM_IX),  0x05: (I_ORA, AM_Z),
    0x06: (I_ASL, AM_Z),   0x08: (I_PHP, AM_IMP), 0x09: (I_ORA, AM_IMM),
    0x0a: (I_ASL, AM_AC),  0x0d: (I_ORA, AM_AB),  0x0e: (I_ASL, AM_AB),
    0x10: (I_BPL, AM_R),   0x11: (I_ORA, AM_IY),  0x15: (I_ORA, AM_ZX),
    0x16: (I_ASL, AM_ZX),  0x18: (I_CLC, AM_IMP), 0x19: (I_ORA, AM_ABY),
    0x1d: (I_ORA, AM_ABX), 0x1e: (I_ASL, AM_ABX), 0x20: (I_JSR, AM_AB),
    0x21: (I_AND, AM_IX),  0x24: (I_BIT, AM_Z),   0x25: (I_AND, AM_Z),
    0x26: (I_ROL, AM_Z),   0x28: (I_PLP, AM_IMP), 0x29: (I_AND, AM_IMM),
    0x2a: (I_ROL, AM_AC),  0x2c: (I_BIT, AM_AB),  0x2d: (I_AND, AM_AB),
    0x2e: (I_ROL, AM_AB),  0x30: (I_BMI, AM_R),   0x31: (I_AND, AM_IY),
    0x35: (I_AND, AM_ZX),  0x36: (I_ROL, AM_ZX),  0x38: (I_SEC, AM_IMP),
    0x39: (I_AND, AM_ABY), 0x3d: (I_AND, AM_ABX), 0x3e: (I_ROL, AM_ABX),
    0x40: (I_RTI, AM_IMP), 0x41: (I_EOR, AM_IX),  0x45: (I_EOR, AM_Z),
    0x46: (I_LSR, AM_Z),   0x48: (I_PHA, AM_IMP), 0x49: (I_EOR, AM_IMM),
    0x4a: (I_LSR, AM_AC),  0x4c: (I_JMP, AM_AB),  0x4d: (I_EOR, AM_AB),
    0x4e: (I_LSR, AM_AB),  0x50: (I_BVC, AM_R),   0x51: (I_EOR, AM_IY),
    0x55: (I_EOR, AM_ZX),  0x56: (I_LSR, AM_ZX),  0x58: (I_CLI, AM_IMP),
    0x59: (I_EOR, AM_ABY), 0x5d: (I_EOR, AM_ABX), 0x5e: (I_LSR, AM_ABX),
    0x60: (I_RTS, AM_IMP), 0x61: (I_ADC, AM_IX),  0x65: (I_ADC, AM_Z),
    0x66: (I_ROR, AM_Z),   0x68: (I_PLA, AM_IMP), 0x69: (I_ADC, AM_IMM),
    0x6a: (I_ROR, AM_AC),  0x6c: (I_JMP, AM_I),   0x6d: (I_ADC, AM_AB),
    0x6e: (I_ROR, AM_AB),  0x70: (I_BVS, AM_R),   0x71: (I_ADC, AM_IY),
    0x75: (I_ADC, AM_ZX),  0x76: (I_ROR, AM_ZX),  0x78: (I_SEI, AM_IMP),
    0x79: (I_ADC, AM_ABY), 0x7d: (I_ADC, AM_ABX), 0x7e: (I_ROR, AM_ABX),
    0x81: (I_STA, AM_IX),  0x84: (I_STY, AM_Z),   0x85: (I_STA, AM_Z),
    0x86: (I_STX, AM_Z),   0x88: (I_DEY, AM_IMP), 0x8a: (I_TXA, AM_IMP),
    0x8c: (I_STY, AM_AB),  0x8d: (I_STA, AM_AB),  0x8e: (I_STX, AM_AB),
    0x90: (I_BCC, AM_R),   0x91: (I_STA, AM_IY),  0x94: (I_STY, AM_ZX),
    0x95: (I_STA, AM_ZX),  0x96: (I_STX, AM_ZY),  0x98: (I_TYA, AM_IMP),
    0x99: (I_STA, AM_ABY), 0x9a: (I_TXS, AM_IMP), 0x9d: (I_STA, AM_ABX),
    0xa0: (I_LDY, AM_IMM), 0xa1: (I_LDA, AM_IX),  0xa2: (I_LDX, AM_IMM),
    0xa4: (I_LDY, AM_Z),   0xa5: (I_LDA, AM_Z),   0xa6: (I_LDX, AM_Z),
    0xa8: (I_TAY, AM_IMP), 0xa9: (I_LDA, AM_IMM), 0xaa: (I_TAX, AM_IMP),
    0xac: (I_LDY, AM_AB),  0xad: (I_LDA, AM_AB),  0xae: (I_LDX, AM_AB),
    0xb0: (I_BCS, AM_R),   0xb1: (I_LDA, AM_IY),  0xb4: (I_LDY, AM_ZX),
    0xb5: (I_LDA, AM_ZX),  0xb6: (I_LDX, AM_ZY),  0xb8: (I_CLV, AM_IMP),
    0xb9: (I_LDA, AM_ABY), 0xba: (I_TSX, AM_IMP), 0xbc: (I_LDY, AM_ABX),
    0xbd: (I_LDA, AM_ABX), 0xbe: (I_LDX, AM_ABY), 0xc0: (I_CPY, AM_IMM),
    0xc1: (I_CMP, AM_IX),  0xc4: (I_CPY, AM_Z),   0xc5: (I_CMP, AM_Z),
    0xc6: (I_DEC, AM_Z),   0xc8: (I_INY, AM_IMP), 0xc9: (I_CMP, AM_IMM),
    0xca: (I_DEX, AM_IMP), 0xcc: (I_CPY, AM_AB),  0xcd: (I_CMP, AM_AB),
    0xce: (I_DEC, AM_AB),  0xd0: (I_BNE, AM_R),   0xd1: (I_CMP, AM_IY),
    0xd5: (I_CMP, AM_ZX),  0xd6: (I_DEC, AM_ZX),  0xd8: (I_CLD, AM_IMP),
    0xd9: (I_CMP, AM_ABY), 0xdd: (I_CMP, AM_ABX), 0xde: (I_DEC, AM_ABX),
    0xe0: (I_CPX, AM_IMM), 0xe1: (I_SBC, AM_IX),  0xe4: (I_CPX, AM_Z),
    0xe5: (I_SBC, AM_Z),   0xe6: (I_INC, AM_Z),   0xe8: (I_INX, AM_IMP),
    0xe9: (I_SBC, AM_IMM), 0xea: (I_NOP, AM_IMP), 0xec: (I_CPX, AM_AB),
    0xed: (I_SBC, AM_AB),  0xee: (I_INC, AM_AB),  0xf0: (I_BEQ, AM_R),
    0xf1: (I_SBC, AM_IY),  0xf5: (I_SBC, AM_ZX),  0xf6: (I_INC, AM_ZX),
    0xf8: (I_SED, AM_IMP), 0xf9: (I_SBC, AM_ABY), 0xfd: (I_SBC, AM_ABX),
    0xfe: (I_INC, AM_ABX),
}
assert all(0x00 <= o <= 0xff           for o in OPCODES)
assert all(OPCODES[o][0] in MNEMONICS  for o in OPCODES)
assert all(OPCODES[o][1] in ADDR_MODES for o in OPCODES)

# instructions that can write memory
WRITE_INSTRUCTIONS = frozenset((
    I_ASL, I_DEC, I_INC, I_LSR, I_ROL, I_ROR, I_STA, I_STX, I_STY
))

# NES memory-mapped registers
HARDWARE_REGISTERS = {
    0x2000: "ppu_ctrl", 0x2001: "ppu_mask",  0x2002: "ppu_status",
    0x2003: "oam_addr", 0x2004: "oam_data",  0x2005: "ppu_scroll",
    0x2006: "ppu_addr", 0x2007: "ppu_data",
    0x4000: "sq1_vol",  0x4001: "sq1_sweep", 0x4002: "sq1_lo",
    0x4003: "sq1_hi",   0x4004: "sq2_vol",   0x4005: "sq2_sweep",
    0x4006: "sq2_lo",   0x4007: "sq2_hi",    0x4008: "tri_linear",
    0x400a: "tri_lo",   0x400b: "tri_hi",    0x400c: "noise_vol",
    0x400e: "noise_lo", 0x400f: "noise_hi",  0x4010: "dmc_freq",
    0x4011: "dmc_raw",  0x4012: "dmc_start", 0x4013: "dmc_len",
    0x4014: "oam_dma",  0x4015: "snd_chn",   0x4016: "joypad1",
    0x4017: "joypad2",
}
assert all(0x2000 <= a <= 0x4017 for a in HARDWARE_REGISTERS)

# enumerate CDL file chunk types
(
    CDL_UNACCESSED,  # not accessed
    CDL_CODE,        # accessed as code (and possibly also as data)
    CDL_DATA,        # accessed as data only
) = range(3)

# enumerate label access methods (how an instruction accesses an address)
(
    ACME_ARRAY,  # array      (zeroPage,x / zeroPage,y / absolute,x / absolute,y)
    ACME_SUB,    # subroutine (JSR)
    ACME_CODE,   # other code (branch / JMP absolute)
    ACME_DATA,   # data       (none of the above)
) = range(4)

# bitmasks for CDL bytes
CDL_CODE_MASK = 0b0000_0001
CDL_DATA_MASK = 0b0000_0010

# --- Help and argument parsing -----------------------------------------------

def list_opcodes():
    # list supported opcodes
    for opcode in sorted(OPCODES):
        (mnemonic, addrMode) = OPCODES[opcode]
        mnemonicStr = MNEMONICS[mnemonic]
        (operandSize, operandFormat) = ADDR_MODES[addrMode]
        addrModeStr = operandFormat.format(operandSize * "nn")
        print(f"0x{opcode:02x} = {mnemonicStr} {addrModeStr}")

def parse_addr_ranges(arg):
    # generate ranges from a string of comma-separated 16-bit address ranges;
    # e.g. "0010-001f,0030-003f" -> range(16, 32), range(48, 64)

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

def parse_args():
    # parse command line arguments using argparse
    # note: indentation 0 forbidden as "0s" is an invalid string format code

    parser = argparse.ArgumentParser(
        description="An NES (6502) disassembler. See README.md for help."
    )

    parser.add_argument("-c", "--cdl-file",            type=str, default="")
    parser.add_argument("-i", "--indentation",         type=int, default=16)
    parser.add_argument("-d", "--data-bytes-per-line", type=int, default=8)
    parser.add_argument("-a", "--no-access",           type=str, default="")
    parser.add_argument("-w", "--no-write",            type=str, default="")
    parser.add_argument(      "--no-anonymous-labels", action="store_true")
    parser.add_argument("-l", "--list-opcodes",        action="store_true")
    parser.add_argument("input_file")

    args = parser.parse_args()

    if args.list_opcodes:
        list_opcodes()
        exit()

    if not 1 <= args.indentation <= 100:
        sys.exit("Indentation must be 1 to 100.")
    if not 1 <= args.data_bytes_per_line <= 100:
        sys.exit("'Data bytes per line' must be 1 to 100.")
    list(parse_addr_ranges(args.no_access))  # just validate
    list(parse_addr_ranges(args.no_write))   # just validate

    if not os.path.isfile(args.input_file):
        sys.exit("PRG ROM file not found.")
    if args.cdl_file and not os.path.isfile(args.cdl_file):
        sys.exit("CDL file not found.")

    return args

# --- CDL file reading --------------------------------------------------------

def get_cdl_byte_type(byte):
    if byte & CDL_CODE_MASK:
        return CDL_CODE
    if byte & CDL_DATA_MASK:
        return CDL_DATA
    return CDL_UNACCESSED

def read_cdl_file(handle, prgSize):
    # read an FCEUX CDL file; generate: (range_of_PRG_addresses, chunk_type)

    # read CDL data corresponding to PRG data (if PRG data is less than 16 KiB,
    # read from end of first 16 KiB of CDL data)
    cdlSize = handle.seek(0, 2)
    if prgSize < 16 * 1024 and cdlSize >= 16 * 1024:
        cdlStart = 16 * 1024 - prgSize
    else:
        cdlStart = 0
    handle.seek(cdlStart)
    cdlData = handle.read(prgSize)

    chunkStart = None            # start address of current chunk
    chunkType  = CDL_UNACCESSED  # type          of current chunk

    for (pos, byte) in enumerate(cdlData):
        byteType = get_cdl_byte_type(byte)
        if byteType != chunkType:
            if chunkType != CDL_UNACCESSED:
                # end current chunk
                yield (range(chunkStart, pos), chunkType)
                chunkType = CDL_UNACCESSED
            if byteType != CDL_UNACCESSED:
                # start a new chunk
                chunkStart = pos
                chunkType  = byteType

    if chunkType != CDL_UNACCESSED:
        yield (range(chunkStart, prgSize), chunkType)  # end the last chunk

# --- Disassembly (not output) ------------------------------------------------

def decode_16bit_addr(byte1, byte2):
    # decode 16-bit address (little-endian)
    assert 0x00 <= byte1 <= 0xff
    assert 0x00 <= byte2 <= 0xff
    return byte1 | (byte2 << 8)

def decode_rel_addr(pc, offset):
    # decode program counter relative address (note: result may be outside
    # 0x0000-0xffff)
    assert 0x0000 <= pc     <= 0xffff
    assert 0x00   <= offset <= 0xff
    return pc + 2 - (offset & 0x80) + (offset & 0x7f)

def is_operand_valid(instrBytes, prgAddr, prgDataLen, noAccess, noWrite):
    # is the operand of the instruction valid?
    # instrBytes: 1-3 bytes
    # prgAddr: PRG address of first byte

    (mnemonic, addrMode) = OPCODES[instrBytes[0]]

    if addrMode in (AM_AB, AM_ABX, AM_ABY):
        # direct absolute (must not access or write an excluded address)
        addr = decode_16bit_addr(instrBytes[1], instrBytes[2])
        return not (
            mnemonic in WRITE_INSTRUCTIONS
            and any(addr in r for r in noWrite )
            or  any(addr in r for r in noAccess)
        )

    if addrMode == AM_R:  # relative (target must be within PRG ROM)
        return 0 <= decode_rel_addr(prgAddr, instrBytes[1]) < prgDataLen

    return True  # indirect or only 1 byte

def allow_instr_at_addr(addrRange, cdlCodeRngs, cdlDataRngs):
    # does the CDL data allow an instruction at specified address range?
    # either all bytes must be code or all bytes must be unaccessed
    # (comments denoting unaccessed code can only be printed at the start of
    # each instruction)

    return any(
        addrRange.start in r and addrRange.stop - 1 in r for r in cdlCodeRngs
    ) or not any(
        any(a in r for r in cdlCodeRngs) or any(a in r for r in cdlDataRngs)
        for a in addrRange
    )

def get_instr_addr_ranges(prgData, cdlData, args):
    # generate PRG address ranges of instructions from PRG data
    # cdlData: {address_range: chunk_type, ...}, yield: one range per call

    cdlCodeRngs = set(rng for rng in cdlData if cdlData[rng] == CDL_CODE)
    cdlDataRngs = set(rng for rng in cdlData if cdlData[rng] == CDL_DATA)
    noAccess    = set(parse_addr_ranges(args.no_access))
    noWrite     = set(parse_addr_ranges(args.no_write))

    origin = 0x10000 - len(prgData)

    codeStart = None  # start of current code chunk
    pos       = 0     # position in PRG data

    # quite similar to main loops elsewhere
    while pos < len(prgData):
        opcode = prgData[pos]

        # does the remaining PRG ROM start with an instruction?
        if opcode in OPCODES:  # documented opcode?
            (mnemonic, addrMode) = OPCODES[opcode]
            operandSize = ADDR_MODES[addrMode][0]
            # enough space left for operand; operand valid; instruction allowed
            # here by CDL file?
            isInstruction = (
                pos <= len(prgData) - operandSize - 1
                and is_operand_valid(
                    prgData[pos:pos+operandSize+1], pos, len(prgData),
                    noAccess, noWrite
                )
                and allow_instr_at_addr(
                    range(pos, pos + 1 + operandSize), cdlCodeRngs, cdlDataRngs
                )
            )
        else:
            isInstruction = False

        if isInstruction:
            if codeStart is None:
                codeStart = pos  # start a new code chunk
            pos += 1 + operandSize
        else:  # data byte
            if codeStart is not None:
                yield range(codeStart, pos)  # end current code chunk
                codeStart = None
            pos += 1

    if codeStart is not None:
        yield range(codeStart, len(prgData))  # end the last code chunk

def get_instr_addresses(prgData, instrAddrRngs):
    # generate PRG addresses of instructions
    # instrAddrRngs: set of PRG address ranges

    for rng in instrAddrRngs:
        pos = rng.start
        while pos < rng.stop:
            yield pos
            operandSize = ADDR_MODES[OPCODES[prgData[pos]][1]][0]
            pos += 1 + operandSize

def get_access_method(mnemonic, addrMode):
    # how does the instruction access its operand; see ACME_... enumeration
    if addrMode in (AM_ZX, AM_ZY, AM_ABX, AM_ABY):
        return ACME_ARRAY
    if mnemonic == I_JSR:
        return ACME_SUB
    if mnemonic == I_JMP and addrMode == AM_AB or addrMode == AM_R:
        return ACME_CODE
    return ACME_DATA

def get_label_stats(prgData, instrAddrRngs):
    # get addresses and statistics of labels from PRG data
    # instrAddrRngs: set of PRG address ranges
    # return: {
    #     CPU_address: [
    #         set_of_access_methods,
    #         first_referring_CPU_address,
    #         last_referring_CPU_address
    #     ], ...
    # }

    origin = 0x10000 - len(prgData)

    instrAddresses = set()  # PRG addresses of instructions
    labelStats     = {}     # same type as this function's return value
    pos            = 0      # position in PRG ROM

    for pos in get_instr_addresses(prgData, instrAddrRngs):
        instrAddresses.add(pos)

        opcode = prgData[pos]
        (mnemonic, addrMode) = OPCODES[opcode]

        # is the operand an address?
        if ADDR_MODES[addrMode][0] >= 1 and addrMode != AM_IMM:
            # decode operand
            if ADDR_MODES[addrMode][0] == 1:  # 1-byte address?
                addr = prgData[pos+1]
                if addrMode == AM_R:
                    addr = decode_rel_addr(origin + pos, addr)
            else:  # 2-byte address
                addr = decode_16bit_addr(prgData[pos+1], prgData[pos+2])

            # remember access method, first reference and last reference
            accessMethod = get_access_method(mnemonic, addrMode)
            referrer = origin + pos
            if addr in labelStats:
                labelStats[addr][0].add(accessMethod)
                labelStats[addr][1] = min(labelStats[addr][1], referrer)
                labelStats[addr][2] = max(labelStats[addr][2], referrer)
            else:
                labelStats[addr] = [{accessMethod,}, referrer, referrer]

    # only keep labels that refer to any of these:
    # - outside of PRG ROM
    # - first bytes of instructions
    # - data
    return dict(
        (addr, labelStats[addr]) for addr in labelStats
        if addr <= 0x7fff or (
            addr >= origin and (
                addr - origin in instrAddresses
                or not any(addr - origin in rng for rng in instrAddrRngs)
            )
        )
    )

def get_anon_labels_frw(prgCodeLabels, labelStats, anonLabelsBkw):
    # generate addresses that can be used as forwards ("+") anonymous labels
    # anonLabelsBkw: previously-found backwards ("-") anonymous labels

    for addr in prgCodeLabels:
        # - must be within forward branch range from all references
        # - there must be no labels other than "-" in between
        if (
            labelStats[addr][2] < addr <= labelStats[addr][1] + 2 + 127
            and not any(
                labelStats[addr][1] < otherAddr < addr
                and otherAddr not in anonLabelsBkw
                for otherAddr in labelStats
            )
        ):
            yield addr

def get_anon_labels_bkw(prgCodeLabels, labelStats, anonLabelsFrw):
    # generate addresses that can be used as backwards ("-") anonymous labels
    # anonLabelsFrw: previously-found forwards ("+") anonymous labels

    for addr in prgCodeLabels:
        # - must be within backward branch range from all references
        # - there must be no labels other than "+" in between
        if (
            labelStats[addr][2] + 2 - 128 <= addr <= labelStats[addr][1]
            and not any(
                addr < otherAddr < labelStats[addr][2]
                and otherAddr not in anonLabelsFrw
                for otherAddr in labelStats
            )
        ):
            yield addr

def get_label_names(prgData, instrAddrRngs, args):
    # instrAddrRngs: set of ranges, yield: (CPU_address, name)

    labelStats = get_label_stats(prgData, instrAddrRngs)

    # 0x0000-0x1fff
    ramLabels = set(addr for addr in labelStats if addr <= 0x1fff)
    # accessed at least once as an array
    addresses = sorted(
        addr for addr in ramLabels if ACME_ARRAY in labelStats[addr][0]
    )
    yield from ((a, f"arr{i+1}") for (i, a) in enumerate(addresses))
    # never accessed as an array
    addresses = sorted(
        addr for addr in ramLabels if ACME_ARRAY not in labelStats[addr][0]
    )
    yield from ((a, f"ram{i+1}") for (i, a) in enumerate(addresses))
    del ramLabels

    # 0x2000-0x7fff
    # hardware registers
    addresses = sorted(set(labelStats) & set(HARDWARE_REGISTERS))
    yield from ((a, HARDWARE_REGISTERS[a]) for a in addresses)
    # other
    addresses = sorted(
        addr for addr in set(labelStats) - set(HARDWARE_REGISTERS)
        if 0x2000 <= addr <= 0x7fff
    )
    yield from ((a, f"misc{i+1}") for (i, a) in enumerate(addresses))

    # anonymous PRG ROM labels
    anonLabelsFrw = set()  # forwards  ("+")
    anonLabelsBkw = set()  # backwards ("-")
    if not args.no_anonymous_labels:
        # addresses only referred to by branches or direct jumps
        prgCodeLabels = {
            addr for addr in labelStats
            if addr >= 0x8000 and labelStats[addr][0] == set((ACME_CODE,))
        }
        # look for "+" labels, then "-" labels, then "+" labels again
        anonLabelsFrw.update(
            get_anon_labels_frw(prgCodeLabels, labelStats, anonLabelsBkw)
        )
        anonLabelsBkw.update(
            get_anon_labels_bkw(prgCodeLabels, labelStats, anonLabelsFrw)
        )
        anonLabelsFrw.update(
            get_anon_labels_frw(prgCodeLabels, labelStats, anonLabelsBkw)
        )
        del prgCodeLabels
        yield from ((addr, "+") for addr in anonLabelsFrw)
        yield from ((addr, "-") for addr in anonLabelsBkw)

    # named PRG ROM labels
    namedPrgLabels = (
        set(addr for addr in set(labelStats) if addr >= 0x8000)
        - anonLabelsFrw - anonLabelsBkw
    )
    del anonLabelsFrw, anonLabelsBkw
    # subs
    addresses = sorted(
        addr for addr in namedPrgLabels
        if ACME_SUB in labelStats[addr][0]
    )
    yield from ((a, f"sub{i+1}") for (i, a) in enumerate(addresses))
    # other code
    addresses = sorted(
        addr for addr in namedPrgLabels
        if  ACME_SUB  not in labelStats[addr][0]
        and ACME_CODE     in labelStats[addr][0]
    )
    yield from ((a, f"cod{i+1}") for (i, a) in enumerate(addresses))
    # data
    addresses = sorted(
        addr for addr in namedPrgLabels
        if  ACME_SUB  not in labelStats[addr][0]
        and ACME_CODE not in labelStats[addr][0]
    )
    yield from ((a, f"dat{i+1}") for (i, a) in enumerate(addresses))

def opcode_has_zp_equiv(opcode):
    # is the opcode an absolute/absolute,x/absolute,y opcode that has a zero
    # page equivalent?
    (mnemonic, addrMode) = OPCODES[opcode]
    return (
           addrMode == AM_AB  and mnemonic not in (I_JMP, I_JSR)
        or addrMode == AM_ABX
        or addrMode == AM_ABY and mnemonic == I_LDX
    )

def get_needed_macros(prgData, instrAddrRngs):
    # which macros need to be defined? return a set of opcodes

    instrAddresses = set(get_instr_addresses(prgData, instrAddrRngs))
    pos = 0
    # get opcodes for instructions that ASM6 would auto-optimize
    # (2-byte operand <= $00ff, has a zeropage equivalent)
    opcodes = set()
    while pos < len(prgData):
        if pos in instrAddresses:
            # instruction
            operandSize = ADDR_MODES[OPCODES[prgData[pos]][1]][0]
            if operandSize == 2 and prgData[pos+2] == 0:
                opcodes.add(prgData[pos])
            pos += 1 + operandSize
        else:
            # data
            pos += 1
    return set(o for o in opcodes if opcode_has_zp_equiv(o))

# --- Output ------------------------------------------------------------------

def print_cdl_stats(cdlData, prgSize):
    instrByteCnt = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_CODE)
    dataByteCnt  = sum(len(rng) for rng in cdlData if cdlData[rng] == CDL_DATA)
    unaccByteCnt = prgSize - instrByteCnt - dataByteCnt
    print("; Bytes in CDL file:")
    print("; - instruction  :", instrByteCnt)
    print("; - data         :", dataByteCnt)
    print("; - unaccessed   :", unaccByteCnt)

def print_comment_heading(text):
    # print "; --- text ---"... padded to 79 characters
    print(f"; --- {text} " + (max(0, 79 - 7 - len(text))) * "-")

def format_literal(n, bits=8, base=16):
    # format an ASM6 integer literal
    if bits == 8 and 0 <= n <= 0xff:
        if base == 2:
            return f"%{n:08b}"
        if base == 10:
            return f"{n}"
        if base == 16:
            return f"${n:02x}"
    if bits == 16 and 0 <= n <= 0xffff and base == 16:
        return f"${n:04x}"
    raise ValueError

def print_data_line(label, bytes_, origin, prgAddr, cdlDataRngs, args):
    # print data line (as two lines if label is too long)

    if len(label) > args.indentation - 1:
        print(label)
        label = ""

    maxInstructionWidth = args.data_bytes_per_line * 3 + 5
    isAccessed = any(prgAddr in rng for rng in cdlDataRngs)

    print(
        format(label, f"{args.indentation}s")
        + format(
            "hex " + " ".join(f"{b:02x}" for b in bytes_),
            f"{maxInstructionWidth}s"
        )
        + f"; {origin+prgAddr:04x}"
        + ("" if isAccessed else 11 * " " + "(unaccessed)")
    )

def print_data_lines(data, origin, prgAddr, labels, cdlDataRngs, args):
    # print lines with data bytes
    # labels: dict

    startOffset = 0   # current block
    prevLabel   = ""

    for (offset, byte) in enumerate(data):
        label = labels.get(origin + prgAddr + offset, "")
        if label or offset - startOffset == args.data_bytes_per_line:
            # a new block starts; print old one, if any
            if offset > startOffset:
                print_data_line(
                    prevLabel, data[startOffset:offset], origin,
                    prgAddr + startOffset, cdlDataRngs, args
                )
                startOffset = offset
            prevLabel = label

    # print last block, if any
    if len(data) > startOffset:
        print_data_line(
            prevLabel, data[startOffset:], origin, prgAddr + startOffset,
            cdlDataRngs, args
        )

def format_operand_value(instrBytes, prgAddr, labels):
    # instrBytes: 1-3 bytes

    (mnemonic, addrMode) = OPCODES[instrBytes[0]]

    if addrMode in (AM_IMP, AM_AC):
        return ""
    if addrMode == AM_IMM:
        if mnemonic in (I_AND, I_EOR, I_ORA):
            base = 2
        elif instrBytes[1] <= 9:
            base = 10
        else:
            base = 16
        return format_literal(instrBytes[1], 8, base)
    if addrMode in (AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R):
        # 1-byte address
        addr = instrBytes[1]
        if addrMode == AM_R:
            addr = decode_rel_addr(prgAddr, addr)
            bits = 16
        else:
            bits = 8
        return labels.get(addr, format_literal(addr, bits))
    # 2-byte address
    addr = decode_16bit_addr(instrBytes[1], instrBytes[2])
    return labels.get(addr, format_literal(addr, 16))

def print_instr(label, cpuAddr, instrBytes, operand, isAccessed, args):
    # print instruction line (as 2 lines if label is too long)
    # operand: formatted operand

    if len(label) > args.indentation - 1:
        print(label)
        label = ""

    if opcode_has_zp_equiv(instrBytes[0]) and instrBytes[2] == 0x00:
        # use macro instead of mnemonic
        (mnemonic, addrMode) = OPCODES[instrBytes[0]]
        mnemonic = MNEMONICS[mnemonic] + "_" + MACRO_ADDR_MODE_NAMES[addrMode]
        if operand.endswith(",x") or operand.endswith(",y"):
            operand = operand[:-2]
    else:
        mnemonic = MNEMONICS[OPCODES[instrBytes[0]][0]]

    instrBytesHex = " ".join(f"{b:02x}" for b in instrBytes)

    print(
        format(label, f"{args.indentation}s")
        + format(mnemonic + " " + operand, f"{args.data_bytes_per_line*3+5}s")
        + f"; {cpuAddr:04x}: {instrBytesHex}"
        + (
            "" if isAccessed
            else (9 - len(instrBytesHex)) * " " + "(unaccessed)"
        )
    )

def disassemble(prgData, cdlData, args):
    # disassemble PRG data
    # cdlData: {PRG_address_range: chunk_type, ...}, return: None

    # ranges of PRG addresses
    instrAddrRngs = set(get_instr_addr_ranges(prgData, cdlData, args))

    # {CPU_address: name, ...}
    labels = dict(get_label_names(prgData, instrAddrRngs, args))

    instrByteCnt = sum(len(rng) for rng in instrAddrRngs)
    print("; Bytes:")
    print("; - instruction:", instrByteCnt)
    print("; - data       :", len(prgData) - instrByteCnt)
    anonLabelCnt = sum(1 for a in labels if labels[a] in ("+", "-"))
    print("; Labels:")
    print("; - named    :", len(labels) - anonLabelCnt)
    print("; - anonymous:", anonLabelCnt)
    print_cdl_stats(cdlData, len(prgData))
    print()

    print_comment_heading("Macros")
    print()
    print("; force 16-bit addressing (absolute/absolute,x/absolute,y) with")
    print("; operands <= $ff")
    for opcode in sorted(get_needed_macros(prgData, instrAddrRngs)):
        (mnemonic, addrMode) = OPCODES[opcode]
        print("macro {}_{} _zp".format(
            MNEMONICS[mnemonic], MACRO_ADDR_MODE_NAMES[addrMode]
        ))
        print(args.indentation * " " + f"db ${opcode:02x}, _zp, $00")
        print("endm")
    print()

    print_comment_heading("Address constants at $0000-$7fff")
    print()
    print("; 'arr' = RAM array, 'ram' = RAM non-array, 'misc' = $2000-$7fff")
    print("; note: unused hardware registers commented out")
    print()
    for addr in sorted(
        l for l in set(labels) | set(HARDWARE_REGISTERS) if l <= 0x7fff
    ):
        name = (
            labels[addr] if addr in labels else ";" + HARDWARE_REGISTERS[addr]
        )
        print(
            f"{name:15s} equ "
            + format_literal(addr, 8 if addr <= 0xff else 16)
        )
    print()

    origin = 0x10000 - len(prgData)

    print_comment_heading(
        f"PRG ROM (CPU ${origin:04x}-${origin+len(prgData)-1:04x})"
    )
    print()
    print("; labels: 'sub' = subroutine, 'cod' = code, 'dat' = data")
    print()
    print(args.indentation * " " + "org " + format_literal(origin, 16))
    print()

    instrAddresses = set(get_instr_addresses(prgData, instrAddrRngs))
    cdlCodeRngs = set(rng for rng in cdlData if cdlData[rng] == CDL_CODE)
    cdlDataRngs = set(rng for rng in cdlData if cdlData[rng] == CDL_DATA)

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
                    prgData[dataStart:pos], origin, dataStart, labels,
                    cdlDataRngs, args
                )
                print()
                dataStart = None

            label = labels.get(origin + pos, "")
            (operandSize, operandFormat) = ADDR_MODES[OPCODES[prgData[pos]][1]]
            instrBytes = prgData[pos:pos+1+operandSize]  # opcode + operand
            operand = operandFormat.format(
                format_operand_value(instrBytes, origin + pos, labels)
            )
            isAccessed = any(pos in r for r in cdlCodeRngs)

            print_instr(
                label, origin + pos, instrBytes, operand, isAccessed, args
            )

            pos += 1 + operandSize
            prevBlockWasData = False
        else:
            # data

            accessed = any(pos in r for r in cdlDataRngs)

            if dataStart is None or accessed != prevDataBlockAccessed:
                if dataStart is not None:
                    # print previous data block
                    if not prevBlockWasData:
                        print()
                    print_data_lines(
                        prgData[dataStart:pos], origin, dataStart, labels,
                        cdlDataRngs, args
                    )
                    prevBlockWasData = True
                # start a new data block
                dataStart = pos
                prevDataBlockAccessed = accessed

            pos += 1

    if dataStart is not None:
        # print last data block
        print_data_lines(
            prgData[dataStart:], origin, dataStart, labels, cdlDataRngs, args
        )

    print()

def main():
    args = parse_args()

    # read PRG file
    try:
        with open(args.input_file, "rb") as handle:
            handle.seek(0)
            prgData = handle.read()
    except OSError:
        sys.exit("Error reading PRG ROM file.")

    if not 1 <= len(prgData) <= 32 * 1024:
        sys.exit("PRG ROM file size must be 1 byte to 32 KiB.")

    # read CDL file
    if args.cdl_file:
        try:
            if os.path.getsize(args.cdl_file) < len(prgData):
                sys.exit("The CDL file must not be smaller than the PRG file.")
            with open(args.cdl_file, "rb") as handle:
                cdlData = dict(read_cdl_file(handle, len(prgData)))
        except OSError:
            sys.exit("Error reading CDL file.")
    else:
        cdlData = dict()

    disassemble(prgData, cdlData, args)

main()
