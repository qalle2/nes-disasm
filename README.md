# nes-disasm
An NES (6502) disassembler. The output is compatible with asm6f. Work in progress, not very useful yet.

Note: the Linux script `test` is intended for my personal use. Do not run it without reading it.

## Command line arguments
```
usage: nesdisasm.py [-h] [--bank-size BANK_SIZE] [--origin ORIGIN]
                    [--no-uncommon-opcodes] [--no-access-rarely-used-memory]
                    [--no-rom-writes] [--no-suboptimal-absolute]
                    input_file

An NES (6502) disassembler.

positional arguments:
  input_file            The PRG ROM file to read. Size: 1 byte to 4 MiB
                        (4,194,304 bytes). (.nes files aren't currently
                        supported.)

optional arguments:
  -h, --help            show this help message and exit
  --bank-size BANK_SIZE
                        Size of PRG ROM banks in bytes. 1 to 32768, but the
                        input file size must be a multiple of this or equal to
                        this. Default: greatest common divisor of file size
                        and 32768.
  --origin ORIGIN       The NES CPU address each PRG ROM bank starts from.
                        Minimum: 32768. Default & maximum: 65536 minus --bank-
                        size.
  --no-uncommon-opcodes
                        Assume the game never uses the BRK instruction (0x00)
                        or the (indirect,x) addressing mode. Interpret such
                        instructions as data.
  --no-access-rarely-used-memory
                        Assume the game never reads, writes or jumps to
                        0x0800...0x1fff, 0x2008...0x3fff or 0x4018...0x7fff.
                        Interpret such instructions as data.
  --no-rom-writes       Assume the game never writes PRG ROM (most NROM
                        games). Interpret such instructions as data.
  --no-suboptimal-absolute
                        Assume the game never accesses zero page using
                        absolute addressing modes if the instruction also
                        supports zero page addressing (e.g. "lda $0012").
                        Interpret such instructions as data.
```

## To do
* Automatically search for labels.
* Use labels (constants) for NES hardware registers.
* Support other syntaxes.
* Support reading iNES ROM files (`.nes`).
* Support reading FCEUX Code/Data Logger files (`.cdl`).

