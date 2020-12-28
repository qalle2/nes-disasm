# nes-disasm
An NES (6502) disassembler. The output is compatible with [ASM6](https://github.com/qalle2/asm6).

## Features
* Automatically assigns labels to addresses:
  * RAM (including mirrors, i.e. `$0000`&hellip;`$1fff`):
    * `array1`, `array2`, &hellip;: accessed at least once using direct indexed addressing, i.e., zeroPage,x / zeroPage,y / absolute,x / absolute,y
    * `ram1`, `ram2`, &hellip;: never accessed using direct indexed addressing
  * `$2000`&hellip;`$7fff`:
    * `ppu_ctrl`, `ppu_mask`, &hellip;: NES memory-mapped registers
    * `misc1`, `misc2`, &hellip;: other addresses
  * PRG ROM (`$8000`&hellip;`$ffff`):
    * `sub1`, `sub2`, &hellip;: subroutines (accessed at least once using the JSR instruction)
    * `code1`, `code2`, &hellip;: other code (never accessed with JSR, but accessed at least once with JMP absolute or a branch instruction)
    * `+`, `-`, &hellip;: anonymous code labels (only accessed with nearby JMP absolute or branch instructions, with no other labels in between)
    * `data1`, `data2`, &hellip;: data (never accessed with JSR, JMP absolute or a branch instruction)
* Supports FCEUX code/data log files (`.cdl`):
  * bytes flagged as code or both code and data (CDL byte `0bxxxxxxx1`): attempt to disassemble as code
  * bytes flagged as data only (CDL byte `0bxxxxxx10`): disassemble as data
  * bytes flagged as unaccessed (CDL byte `0b00000000`): attempt to disassemble as code, or if `--unaccessed-as-data` is used, disassemble as data; in either case, add `(unaccessed)` to comment

## Limitations
* iNES ROM files (`.nes`) are not supported. (To convert one into a raw PRG ROM data file, use `ines_split.py` from [my NES utilities](https://github.com/qalle2/nes-util).)
* PRG ROM files larger than 32 KiB (i.e., bankswitched games) are not supported.

## Notes
* The Linux scripts `test-*` are intended for my personal use. Do not run them without reading them.
* The origin address is 64 KiB minus the PRG ROM file size.

## Command line arguments
```
usage: nesdisasm.py [-h] [--no-absolute-zp] [--no-absolute-indexed-zp]
                    [--no-opcodes NO_OPCODES] [--no-access NO_ACCESS]
                    [--no-write NO_WRITE] [--no-execute NO_EXECUTE]
                    [--cdl-file CDL_FILE] [--unaccessed-as-data]
                    input_file

An NES (6502) disassembler.

positional arguments:
  input_file            The PRG ROM file to read. Maximum size: 32 KiB. (.nes
                        files are not supported.)

optional arguments:
  -h, --help            show this help message and exit
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
                        addresses (0000...ffff) separated by a hyphen.
                        Examples: 0800-1fff = mirrors of RAM, 2008-3fff =
                        mirrors of PPU registers, 4020-5fff = beginning of
                        cartridge space, 6000-7fff = PRG RAM.
  --no-write NO_WRITE   Assume the game never writes these addresses (via
                        ASL/DEC/INC/LSR/ROL/ROR/STA/STX/STY). Same syntax as
                        in --no-access. Example: 8000-ffff = PRG ROM.
  --no-execute NO_EXECUTE
                        Assume the game never executes these addresses (via
                        BCC/BCS/BEQ/BMI/BNE/BPL/BVC/BVS/JMP/JSR). Same syntax
                        as in --no-access. Examples: 0000-1fff = RAM,
                        2000-401f = memory-mapped registers.
  --cdl-file CDL_FILE   The FCEUX code/data log file (.cdl) to read.
  --unaccessed-as-data  If a CDL file is used, disassemble all unaccessed
                        bytes as data.
```

## Sample output
[Game Genie ROM](sample-output.txt) (see [this script](test-other) for command line arguments used)

## To do
* Better support for CDL files. (Use my [cdl-summary](https://github.com/qalle2/cdl-summary) to extract more info from them.)

