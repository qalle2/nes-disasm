# nes-disasm
An NES (6502) disassembler. Work in progress, not very useful yet.

Note: the Linux script `test` is intended for my personal use. Do not run it without reading it.

## Command line arguments
```
usage: nesdisasm.py [-h] [-o {32,40,48,56}] [-b {8,16,32}]
                    [--no-uncommon-opcodes] [--no-rom-writes]
                    [--no-suboptimal-absolute]
                    input_file

An NES (6502) disassembler.

positional arguments:
  input_file            The PRG ROM file to read. (.nes files aren't currently
                        supported.)

optional arguments:
  -h, --help            show this help message and exit
  -o {32,40,48,56}, --origin {32,40,48,56}
                        The CPU address each ROM bank starts from, in KiB.
  -b {8,16,32}, --bank-size {8,16,32}
                        Size of PRG ROM banks in KiB. -o plus -b must not
                        exceed 64.
  --no-uncommon-opcodes
                        Always interpret bytes 0x00 [BRK] and 0x01 [ORA
                        (zp,x)] as data instead of opcodes.
  --no-rom-writes       Assume the game never writes PRG ROM (most NROM
                        games). Interpret such instructions as data.
  --no-suboptimal-absolute
                        Assume the game never accesses zero page using
                        absolute addressing modes if the instruction also
                        supports zero page addressing (e.g. "lda $0012").
                        Interpret such instructions as data.
```

## To do
* Test with files greater than 32 KiB.
* Support reading iNES ROM files (`.nes`).
* Support reading FCEUX Code/Data Logger files (`.cdl`).

