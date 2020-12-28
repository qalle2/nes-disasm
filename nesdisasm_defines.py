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
    AM_IMP: (0, "{}"),      # implied
    AM_AC:  (0, "a{}"),     # accumulator
    AM_IMM: (1, "#{}"),     # immediate
    AM_Z:   (1, "{}"),      # zeroPage
    AM_ZX:  (1, "{},x"),    # zeroPage,x
    AM_ZY:  (1, "{},y"),    # zeroPage,y
    AM_IX:  (1, "({},x)"),  # (indirect,x)
    AM_IY:  (1, "({}),y"),  # (indirect),y
    AM_R:   (1, "{}"),      # program counter relative
    AM_AB:  (2, "{}"),      # absolute
    AM_ABX: (2, "{},x"),    # absolute,x
    AM_ABY: (2, "{},y"),    # absolute,y
    AM_I:   (2, "({})"),    # (indirect)
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

# sets of addressing modes
NON_ADDRESS_ADDRESSING_MODES    = set((AM_IMP, AM_AC, AM_IMM))
ZERO_PAGE_ADDRESSING_MODES      = set((AM_Z, AM_ZX, AM_ZY, AM_IX, AM_IY, AM_R))
DIRECT_INDEXED_ADDRESSING_MODES = set((AM_ZX, AM_ZY, AM_ABX, AM_ABY))

BITMASK_INSTRUCTIONS                  = set(("and", "ora", "eor"))
IMMEDIATE_INDEX_REGISTER_INSTRUCTIONS = set(("ldx", "ldy", "cpx", "cpy"))

# instructions and addressing modes that can write to memory
WRITE_INSTRUCTIONS = set(("sta", "stx", "sty", "dec", "inc", "asl", "lsr", "rol", "ror"))
WRITE_ADDRESSING_MODES = set((AM_Z, AM_ZX, AM_ZY, AM_AB, AM_ABX, AM_ABY))

# instructions and addressing modes that can jump to an address
JUMP_INSTRUCTIONS = set(("jmp", "jsr", "bne", "beq", "bpl", "bmi", "bcc", "bcs", "bvc", "bvs"))
JUMP_ADDRESSING_MODES = set((AM_AB, AM_R))

# NES CPU address space layout
NES_RAM        = range(0x0000, 0x2000)
NES_MISC_SPACE = range(0x2000, 0x8000)   # registers, PRG RAM
NES_PRG_ROM    = range(0x8000, 0x10000)

