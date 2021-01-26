# nes-disasm
An NES (6502) disassembler. The output is compatible with [ASM6](https://github.com/qalle2/asm6).

## Labels
The disassembler automatically assigns labels to addresses:
* RAM (including mirrors, i.e. `$0000`&hellip;`$1fff`):
  * `array1`, `array2`, &hellip;: accessed at least once using direct indexed addressing, i.e., zeroPage,x / zeroPage,y / absolute,x / absolute,y.
  * `ram1`, `ram2`, &hellip;: never accessed using direct indexed addressing.
* `$2000`&hellip;`$7fff`:
  * `ppu_ctrl`, `ppu_mask`, &hellip;: NES memory-mapped registers.
  * `misc1`, `misc2`, &hellip;: other addresses.
* PRG ROM (`$8000`&hellip;`$ffff`):
  * `sub1`, `sub2`, &hellip;: subroutines (accessed at least once using the JSR instruction).
  * `code1`, `code2`, &hellip;: other code (never accessed with JSR, but accessed at least once with JMP absolute or a branch instruction).
  * `+`, `-`: anonymous code labels (only accessed with nearby JMP absolute or branch instructions, with no other labels in between; use `--no-anonymous-labels` to disable).
  * `data1`, `data2`, &hellip;: data (never accessed with JSR, JMP absolute or a branch instruction).

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
usage: nesdisasm.py [-h] [-c CDL_FILE] [-i INDENTATION]
                    [-d DATA_BYTES_PER_LINE] [--no-absolute-zp]
                    [--no-absolute-indexed-zp] [--no-opcodes NO_OPCODES]
                    [--no-access NO_ACCESS] [--no-write NO_WRITE]
                    [--no-execute NO_EXECUTE] [--unaccessed-as-data]
                    [--no-anonymous-labels]
                    input_file

An NES (6502) disassembler.

positional arguments:
  input_file            The PRG ROM file to read. Size: 32 KiB or less and a
                        power of two. (.nes files are not supported.)

optional arguments:
  -h, --help            show this help message and exit
  -c CDL_FILE, --cdl-file CDL_FILE
                        The FCEUX code/data log file (.cdl) to read.
  -i INDENTATION, --indentation INDENTATION
                        How many spaces to use for indentation (8 to 64,
                        default=8).
  -d DATA_BYTES_PER_LINE, --data-bytes-per-line DATA_BYTES_PER_LINE
                        How many data bytes to print per 'hex ...' line (1 to
                        64, default=8).
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
                        STA/STX/STY/DEC/INC/ASL/LSR/ROL/ROR). Same syntax as
                        in --no-access. Example: 8000-ffff = PRG ROM.
  --no-execute NO_EXECUTE
                        Assume the game never executes these addresses (via
                        JMP, JSR or a branch instruction). Same syntax as in
                        --no-access. Example: 2000-401f = memory-mapped
                        registers.
  --unaccessed-as-data  Output unaccessed bytes as data instead of trying to
                        disassemble them. (Note: without a CDL file, all bytes
                        will be output as data.)
  --no-anonymous-labels
                        Do not use anonymous PRG ROM labels ('+' and '-').
```

## Sample output
[Game Genie ROM](sample-output.txt) (see [this script](test) for command line arguments used)

## Hints
* If ASM6 cannot reassemble the disassembly correctly, try enabling the options starting with `--no-absolute-`.
* Use a CDL file to avoid unnecessary manual work. If you can't, try the options starting with `--no-` (except for `--no-anonymous-labels`) to help the disassembler avoid disassembling bytes that "make no sense" as code.

## To do
* Better support for CDL files. (Use my [cdl-summary](https://github.com/qalle2/cdl-summary) to extract more info from them.)

