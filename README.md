# nes-disasm
An NES (6502) disassembler. The output is compatible with [ASM6](https://github.com/qalle2/asm6).

## Labels
The disassembler automatically assigns labels to addresses:
* RAM (including mirrors, i.e. `$0000-$1fff`):
  * `arr1`, `arr2`, ...: arrays, i.e., accessed at least once using direct indexed addressing, i.e., zeroPage,x / zeroPage,y / absolute,x / absolute,y.
  * `ram1`, `ram2`, ...: never accessed using direct indexed addressing.
* `$2000-$7fff`:
  * `ppu_ctrl`, `ppu_mask`, ...: NES memory-mapped registers.
  * `misc1`, `misc2`, ...: other addresses.
* PRG ROM (`$8000-$ffff`):
  * `sub1`, `sub2`, ...: subroutines (accessed at least once using the JSR instruction).
  * `cod1`, `cod2`, ...: other code (never accessed with JSR, but accessed at least once with JMP absolute or a branch instruction).
  * `+`, `-`: anonymous code labels (only accessed with nearby JMP absolute or branch instructions, with no other labels in between; use `--no-anonymous-labels` to disable).
  * `dat1`, `dat2`, ...: data (never accessed with JSR, JMP absolute or a branch instruction).

## CDL file support
The disassembler has a limited support for log files created with FCEUX Code/Data Logger (`.cdl`). If a CDL file is used, PRG ROM bytes are treated as follows according to their corresponding CDL bytes:
  * CDL byte `0bxxxxxxx1` (code or both code and data): attempt to disassemble.
  * CDL byte `0bxxxxxx10` (data only): output as data (`hex ...`).
  * CDL byte `0b00000000` (unaccessed): attempt to disassemble, or if `--unaccessed-as-data` is used, output as data; in either case, add `(unaccessed)` to comment.

## Limitations
* iNES ROM files (`.nes`) are not supported. (To convert one into a raw PRG ROM data file, use `ines_split.py` from [my NES utilities](https://github.com/qalle2/nes-util).)
* PRG ROM files larger than 32 KiB are not supported.
* The PRG file is assumed to be at the end of the 6502 memory space. (That is, the origin address is always 64 KiB minus the PRG file size.)
* Undocumented 6502 opcodes are not supported.

## Command line arguments
```
usage: nesdisasm.py [-h] [-c CDL_FILE] [-i INDENTATION] [-d DATA_BYTES_PER_LINE] [-z]
                    [-o NO_OPCODES] [-a NO_ACCESS] [-w NO_WRITE] [-x NO_EXECUTE]
                    [--unaccessed-as-data] [--no-anonymous-labels] [-l]
                    input_file

An NES (6502) disassembler.

positional arguments:
  input_file            The PRG ROM file to read. Size: 32 KiB or less. (.nes files are not
                        supported.)

optional arguments:
  -h, --help            show this help message and exit
  -c CDL_FILE, --cdl-file CDL_FILE
                        The FCEUX code/data log file (.cdl) to read.
  -i INDENTATION, --indentation INDENTATION
                        How many spaces to use for indentation (1 to 100, default=8).
  -d DATA_BYTES_PER_LINE, --data-bytes-per-line DATA_BYTES_PER_LINE
                        How many data bytes to print per 'hex ...' line (1 to 100, default=8).
  -z, --no-absolute-zeropage
                        Assume the game never accesses the zero page using absolute addressing if
                        the instruction also supports zero page addressing.
  -o NO_OPCODES, --no-opcodes NO_OPCODES
                        Assume the game never executes these opcodes. Zero or more opcodes
                        separated by commas. Each opcode is an 8-bit hexadecimal integer. E.g.
                        '00,01' = BRK, ORA (indirect,x).
  -a NO_ACCESS, --no-access NO_ACCESS
                        Assume the game never interacts with these addresses (using any
                        instruction with absolute addressing, or indexed absolute with these
                        addresses as the base address). Zero or more ranges separated by commas. A
                        range is two 16-bit hexadecimal addresses separated by a hyphen. E.g.
                        '0800-1fff,2008-3fff,4020-5fff,6000-7fff' = mirrors of RAM, mirrors of PPU
                        registers, beginning of cartridge space, PRG RAM.
  -w NO_WRITE, --no-write NO_WRITE
                        Assume the game never writes these addresses (using
                        STA/STX/STY/DEC/INC/ASL/LSR/ROL/ROR with absolute addressing, or indexed
                        absolute with these addresses as the base address). Same syntax as in
                        --no-access. E.g. '8000-ffff' = PRG ROM.
  -x NO_EXECUTE, --no-execute NO_EXECUTE
                        Assume the game never runs code at these addresses (using JMP absolute or
                        JSR). Same syntax as in --no-access. E.g. '2000-401f' = memory-mapped
                        registers.
  --unaccessed-as-data  Output unaccessed bytes as data instead of trying to disassemble them.
  --no-anonymous-labels
                        Always use named labels instead of anonymous labels ('+' and '-').
  -l, --list-opcodes    List supported opcodes and exit. (Note: specify a dummy input file.)
```

## Sample output
[Game Genie ROM](sample-output.txt) (see `test.sh` for command line arguments used)

## Hints and notes
* If ASM6 cannot reassemble the disassembly to a binary file that's identical to the original, try enabling the option `--no-absolute-zeropage`.
It prevents the disassembler from outputting instructions that ASM6 would automatically optimize.
* Use a CDL file for clearer output.
If you can't, try these options to help the disassembler avoid disassembling bytes that make no sense as code:
  * `--no-absolute-zeropage`
  * `--no-opcodes` (see `--list-opcodes`)
  * `--no-access`
  * `--no-write`
  * `--no-execute`
* The output may be misleading if the CDL file says some bytes were accessed as code but command line options prevent them from being disassembled.
For example, if the instruction `LDA $0045` (`ad 45 00`) is logged as code in the CDL file and the option `--no-absolute-zeropage` is used,
the disassembler will print `hex ad` and `eor some_label` (0x45 incorrectly interpreted as an opcode). This needs to be fixed.

## To do
* Better support for CDL files. (Use my [cdl-summary](https://github.com/qalle2/cdl-summary) to extract more info from them.)
