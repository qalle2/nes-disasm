# nes-disasm
An NES (6502) disassembler. The output is compatible with [asm6f](https://github.com/freem/asm6f). Work in progress.

Notes:
* The Linux script `test` is intended for my personal use. Do not run it without reading it.
* The program does not support iNES ROM files (`.nes`); to convert one into a raw PRG ROM data file, use `ines_split.py` from [my NES utilities](https://github.com/qalle2/nes-util).

## Features
* Automatically assigns labels to addresses:
  * `ram1`, `ram2`, &hellip;: RAM (including mirrors; `$0000`&hellip;`$1fff`)
  * `ppu_ctrl`, `ppu_mask`: NES memory-mapped registers
  * `misc1`, `misc2`, &hellip;: between RAM and PRG ROM (`$2000`&hellip;`$7fff`) but excluding NES memory-mapped registers
  * `code1`, `code2`, &hellip;: PRG ROM (`$8000`&hellip;`$ffff`) accessed as code (via `jmp`, `jsr` or a branch instruction) (not supported if game uses PRG ROM bankswitching)
  * `data1`, `data2`, &hellip;: PRG ROM (`$8000`&hellip;`$ffff`) accessed as data (not supported if game uses PRG ROM bankswitching)
  * `codedata1`, `codedata2`, &hellip;: PRG ROM (`$8000`&hellip;`$ffff`) accessed as both code and data (not supported if game uses PRG ROM bankswitching)

## Command line arguments
```
usage: nesdisasm.py [-h]
                    [--bank-size {256,512,1024,2048,4096,8192,16384,32768}]
                    [--origin ORIGIN] [--no-absolute-zp]
                    [--no-absolute-indexed-zp] [--no-opcodes NO_OPCODES]
                    [--no-access NO_ACCESS] [--no-write NO_WRITE]
                    [--no-execute NO_EXECUTE]
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
                        size. Must be a multiple of 256.
  --no-absolute-zp      Assume the game never accesses zero page using
                        absolute addressing if the instruction also supports
                        zero page addressing.
  --no-absolute-indexed-zp
                        Assume the game never accesses zero page using
                        absolute indexed addressing if the instruction also
                        supports the corresponding zero page indexed
                        addressing mode.
  --no-opcodes NO_OPCODES
                        Assume the game never uses these opcodes. Zero or more
                        opcodes separated by commas. Each opcode is a
                        hexadecimal integer (00 to ff). Examples: 00 = BRK, 01
                        = ORA (indirect,x).
  --no-access NO_ACCESS
                        Assume the game never accesses (reads/writes/executes)
                        these addresses. Zero or more ranges separated by
                        commas. Each range consists of two hexadecimal
                        addresses (0000 to ffff) separated by a hyphen.
                        Examples: 0800-1fff = mirrors of RAM, 2008-3fff =
                        mirrors of PPU registers, 4020-5fff = beginning of
                        cartridge space, 6000-7fff = PRG RAM.
  --no-write NO_WRITE   Assume the game never writes these addresses (via
                        DEC/INC/ASL/LSR/ROL/ROR/STA/STX/STY). Same syntax as
                        in --no-access. Example: 8000-ffff = PRG ROM.
  --no-execute NO_EXECUTE
                        Assume the game never executes these addresses (via
                        JMP/JSR/branch). Same syntax as in --no-access.
                        Examples: 0000-1fff = RAM, 2000-401f = memory-mapped
                        registers.
```

## To do (in order of descending priority)
* Search for PRG ROM labels with bankswitched games too.
* Support reading FCEUX Code/Data Logger files (`.cdl`).
* Support reading iNES ROM files (`.nes`).
* Support other assembler syntaxes.

