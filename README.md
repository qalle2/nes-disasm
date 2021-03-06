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

## Limitations and notes
* iNES ROM files (`.nes`) are not supported. (To convert one into a raw PRG ROM data file, use `ines_split.py` from [my NES utilities](https://github.com/qalle2/nes-util).)
* PRG ROM files larger than 32 KiB (i.e., bankswitched games) are not supported.
* The origin address is always 64 KiB minus the PRG ROM file size.

## Command line arguments
```
usage: nesdisasm.py [-h] [-c CDL_FILE] [-i INDENTATION] [-d DATA_BYTES_PER_LINE] [--no-zp-ab]
                    [--no-zp-abx] [--no-zp-aby] [--no-opcodes NO_OPCODES] [--no-access NO_ACCESS]
                    [--no-write NO_WRITE] [--no-execute NO_EXECUTE] [--unaccessed-as-data]
                    [--no-anonymous-labels] [--list-opcodes]
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
  --no-zp-ab            Assume the game never accesses zero page using absolute addressing if the
                        instruction also supports zeroPage addressing.
  --no-zp-abx           Assume the game never accesses zero page using absolute,x addressing if
                        the instruction also supports zeroPage,x addressing.
  --no-zp-aby           Assume the game never accesses zero page using absolute,y addressing if
                        the instruction also supports zeroPage,y addressing.
  --no-opcodes NO_OPCODES
                        Assume the game never executes these opcodes. Zero or more opcodes
                        separated by commas. Each opcode is an 8-bit hexadecimal integer. E.g.
                        '00,01' = BRK, ORA (indirect,x).
  --no-access NO_ACCESS
                        Assume the game never reads/writes/executes these addresses. Zero or more
                        ranges ranges separated by commas. A range is two 16-bit hexadecimal
                        addresses separated by a hyphen. E.g.
                        '0800-1fff,2008-3fff,4020-5fff,6000-7fff' = mirrors of RAM, mirrors of PPU
                        registers, beginning of cartridge space, PRG RAM.
  --no-write NO_WRITE   Assume the game never writes these addresses. Same syntax as in --no-
                        access. E.g. '8000-ffff' = PRG ROM.
  --no-execute NO_EXECUTE
                        Assume the game never executes these addresses. Same syntax as in --no-
                        access. E.g. '2000-401f' = memory-mapped registers.
  --unaccessed-as-data  Output unaccessed bytes as data instead of trying to disassemble them.
  --no-anonymous-labels
                        Always use named labels instead of anonymous labels ('+' and '-').
  --list-opcodes        List supported opcodes in CSV format and exit. (Note: specify a dummy
                        input file.)
```

## Sample output
[Game Genie ROM](sample-output.txt) (see `test.sh` for command line arguments used)

## Hints
* If ASM6 cannot reassemble the disassembly correctly, try enabling the options `--no-abs-zp`, `--no-abs-zpx` and `--no-abs-zpy`.
* Use a CDL file for a clearer output. If you can't, try these options to help the disassembler avoid disassembling bytes that make no sense as code:
`--no-zp-ab`, `--no-zp-abx`, `--no-zp-aby`, `--no-opcodes`, `--no-access`, `--no-write`, `--no-execute`

## To do
* Better support for CDL files. (Use my [cdl-summary](https://github.com/qalle2/cdl-summary) to extract more info from them.)
