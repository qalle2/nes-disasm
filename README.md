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

## Macros
If the file to be disassembled unnecessarily uses 16-bit addressing (absolute/absolute,x/absolute,y) with operands less than or equal to `$ff`,
the disassembler will replace that instruction with a macro like `lda_abs`.
Otherwise ASM6 would optimize the instruction to use zero page addressing instead, and the reassembled binary would not be identical to the original.

## Limitations
* iNES ROM files (`.nes`) are not supported. (To convert one into a raw PRG ROM data file, use `ines_split.py` from [my NES utilities](https://github.com/qalle2/nes-util).)
* PRG ROM files larger than 32 KiB are not supported.
* The PRG file is assumed to be at the end of the 6502 memory space. (That is, the origin address is always 64 KiB minus the PRG file size.)
* Undocumented 6502 opcodes are not supported.

## Command line arguments
```
usage: nesdisasm.py [-h] [-c CDL_FILE] [-i INDENTATION] [-d DATA_BYTES_PER_LINE] [-a NO_ACCESS]
                    [-w NO_WRITE] [-x NO_EXECUTE] [--unaccessed-as-data] [--no-anonymous-labels]
                    [-l]
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

There's an example of the output in `sample-output.txt`.

## Hints
* Use a CDL file for clearer output.
If you can't, try these options to help the disassembler avoid disassembling bytes that make no sense as code:
`-a, -w, -x`
* Use my [cdl-summary](https://github.com/qalle2/cdl-summary) to extract more info from CDL files.

## To do
* automatically print CLC followed by ADC as a macro; same for SEC and SBC
* allow more anonymous labels (e.g. allow an anonymous forward jump to cross an anonymous backward jump and vice versa)
* better support for CDL files (e.g. print "indirectly accessed" in comments)
