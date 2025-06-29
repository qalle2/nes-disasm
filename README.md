# nes-disasm
*Note: This project has been moved to [Codeberg](https://codeberg.org/qalle/qnesdisasm). This version will no longer be updated.*

An NES (6502) disassembler. The output is compatible with [ASM6](https://www.romhacking.net/utilities/674). There's an example of the output in `sample-output.txt`.

Table of contents:
* [Command line arguments](#command-line-arguments)
* [Labels](#labels)
* [CDL files](#cdl-files)
* [Macros](#macros)
* [Limitations](#limitations)
* [Hints](#hints)
* [To do](#to-do)

## Command line arguments
Syntax: *options* *inputFile*

### Options
* `-h` or `--help`: print a short summary of this help.
* `-c FILE` or `--cdl-file FILE`: The FCEUX code/data log file (`.cdl`) to read. (If you don't specify one, all PRG ROM bytes will be considered unaccessed.)
* `-i INTEGER` or `--indentation INTEGER`: How many spaces to use for indentation (1 to 100, default=16).
* `-d INTEGER` or `--data-bytes-per-line INTEGER`: How many data bytes to print per `hex ...` line (1 to 100, default=8).
* `-a RANGES` or `--no-access RANGES`: Assume the game never reads, writes or executes addresses within these ranges, inclusive
(using any instruction with absolute addressing, or indexed absolute with these addresses as the base address).
  * `RANGES` is zero or more ranges separated by commas.
  * A range is two 16-bit hexadecimal addresses separated by a hyphen.
  * E.g. `0800-1fff,2008-3fff,4020-5fff,6000-7fff` = mirrors of RAM, mirrors of PPU registers, beginning of cartridge space, PRG RAM.
* `-w RANGES` or `--no-write RANGES`: Assume the game never writes addresses within these ranges, inclusive
(using STA, STX, STY, DEC, INC, ASL, LSR, ROL or ROR with absolute addressing, or indexed absolute with these addresses as the base address).
  * `RANGES` is zero or more ranges separated by commas.
  * A range is two 16-bit hexadecimal addresses separated by a hyphen.
  * E.g. `8000-ffff` = PRG ROM.
* `--no-anonymous-labels`: Always output named labels instead of anonymous labels (`+` and `-`).
* `-l` or `--list-opcodes`: Just list supported opcodes and exit. Note: you still need to specify a fake input file (see positional arguments below); it doesn't need to exist.

### Positional arguments
* *inputFile*: The raw PRG ROM file to read.
  * Size: 1 byte to 32 KiB.
  * The file is assumed to be at the end of the 6502 memory space. That is, the origin address is always 64 KiB minus the file size.
  * Note: iNES ROM files (`.nes`) are not supported; to convert one into a raw PRG ROM data file, use `ines_split.py` from [my NES utilities](https://github.com/qalle2/nes-util).

## Labels
The disassembler automatically assigns labels to addresses:
* RAM (including mirrors, i.e. `$0000-$1fff`):
  * `arr1`, `arr2`, &hellip;: arrays, i.e., accessed at least once using direct indexed addressing, i.e., zeroPage,x / zeroPage,y / absolute,x / absolute,y.
  * `ram1`, `ram2`, &hellip;: never accessed using direct indexed addressing.
* `$2000-$7fff`:
  * `ppu_ctrl`, `ppu_mask`, &hellip;: NES memory-mapped registers.
  * `misc1`, `misc2`, &hellip;: other addresses.
* PRG ROM (`$8000-$ffff`):
  * `sub1`, `sub2`, &hellip;: subroutines (accessed at least once using the JSR instruction).
  * `cod1`, `cod2`, &hellip;: other code (never accessed with JSR, but accessed at least once with JMP absolute or a branch instruction).
  * `+`, `-`: anonymous code labels (only accessed with nearby JMP absolute or branch instructions, with no other labels in between; use `--no-anonymous-labels` to disable).
  * `dat1`, `dat2`, &hellip;: data (never accessed with JSR, JMP absolute or a branch instruction).

## CDL files
The disassembler has a limited support for log files created with FCEUX Code/Data Logger (`.cdl`). If a CDL file is used, PRG ROM bytes are treated as follows according to their corresponding CDL bytes:
* CDL byte `0bxxxxxxx1` (code or both code and data): attempt to disassemble.
* CDL byte `0bxxxxxx10` (data only): output as data (`hex ...`).
* CDL byte `0b00000000` (unaccessed): attempt to disassemble, or if `--unaccessed-as-data` is used, output as data; in either case, add `(unaccessed)` to the comment.

## Macros
If the file to be disassembled unnecessarily uses 16-bit addressing (absolute/absolute,x/absolute,y) with addresses less than or equal to `$ff`,
the disassembler will replace that instruction with a macro like `lda_abs`.
Otherwise ASM6 would optimize the instruction to use zero page addressing instead, and the reassembled binary would not be identical to the original.

## Limitations
* Undocumented 6502 opcodes are not supported.
* Directly vs. indirectly accessed code and data are not distinguished when parsing CDL files.

## Hints
* Using a CDL file and the `-a` and `-w` options makes the output a lot clearer.
(They help the disassembler avoid disassembling bytes that make no sense as code.)
* Use my [cdl-summary](https://github.com/qalle2/cdl-summary) to extract more info from CDL files.

## To do
* automatically print CLC followed by ADC as a macro; same for SEC and SBC
* allow more anonymous labels (e.g. allow an anonymous forward jump to cross an anonymous backward jump and vice versa)
