# nes-disasm
An NES (6502) disassembler. The output is compatible with [asm6f](https://github.com/freem/asm6f). Work in progress, not very useful yet.

Note: the Linux script `test` is intended for my personal use. Do not run it without reading it.

## Command line arguments
```
usage: nesdisasm.py [-h]
                    [--bank-size {256,512,1024,2048,4096,8192,16384,32768}]
                    [--origin ORIGIN] [--no-brk] [--no-indirect-x]
                    [--no-absolute-zp-access] [--no-absolute-x-zp-access]
                    [--no-absolute-y-zp-access] [--no-mirror-access]
                    [--no-cart-space-start-access] [--no-prg-ram-access]
                    [--no-access] [--no-register-execute] [--no-rom-write]
                    input_file

An NES (6502) disassembler.

positional arguments:
  input_file            The PRG ROM file to read. Size: 256 bytes to 4 MiB
                        (4,194,304 bytes) and a multiple of 256 bytes. (.nes
                        files are not currently supported.)

optional arguments:
  -h, --help            show this help message and exit
  --bank-size {256,512,1024,2048,4096,8192,16384,32768}
                        Size of PRG ROM banks in bytes. The input file size
                        must be a multiple of this or equal to this. Default:
                        the greatest common divisor of file size and 32768.
  --origin ORIGIN       The NES CPU address each PRG ROM bank starts from.
                        Minimum: 32768. Default & maximum: 65536 minus --bank-
                        size.
  --no-brk              Assume the game never uses the BRK instruction (opcode
                        0x00).
  --no-indirect-x       Assume the game never uses the (indirect,x) addressing
                        mode.
  --no-absolute-zp-access
                        Assume the game never accesses zero page using
                        absolute addressing if the instruction also supports
                        zero page addressing.
  --no-absolute-x-zp-access
                        Assume the game never accesses zero page using
                        absolute,x addressing.
  --no-absolute-y-zp-access
                        Assume the game never accesses zero page using
                        absolute,y addressing if the instruction also supports
                        zeroPage,y addressing.
  --no-mirror-access    Assume the game never accesses mirrors of RAM
                        (0x0800...0x1fff) or mirrors of PPU registers
                        (0x2008...0x3fff).
  --no-cart-space-start-access
                        Assume the game never accesses the beginning of
                        cartridge space (0x4020...0x5fff).
  --no-prg-ram-access   Assume the game never accesses PRG RAM
                        (0x6000...0x7fff).
  --no-access           Shortcut for --no-absolute-zp-access, --no-absolute-x-
                        zp-access, --no-absolute-y-zp-access, --no-mirror-
                        access, --no-cart-space-start-access and --no-prg-ram-
                        access.
  --no-register-execute
                        Assume the game never executes memory-mapped registers
                        (0x2000...0x3fff and 0x4000...0x401f).
  --no-rom-write        Assume the game never writes to PRG ROM
                        (0x8000...0xffff).
```

## To do
* Automatically search for labels.
* Support other syntaxes.
* Support reading iNES ROM files (`.nes`).
* Support reading FCEUX Code/Data Logger files (`.cdl`).

