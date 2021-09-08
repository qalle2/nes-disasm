# Warning: this script DELETES files. Run at your own risk.

clear

rm -f test-out/*.asm
rm -f test-out/*.prg

# disassemble, reassemble and verify various games; note: opcodes:
#   00                      = BRK
#   01/21/41/61/81/a1/c1/e1 = ORA/AND/EOR/ADC/STA/LDA/CMP/SBC (indirect,x)
#   31/51/71/d1/f1          = AND/EOR/ADC/CMP/SBC             (indirect),y

echo "=== all-instructions.prg ==="
python3 nesdisasm.py -z -o 00 test-in/all-instructions.prg > test-out/all-instructions.asm
asm6 test-out/all-instructions.asm test-out/all-instructions.prg
diff -q test-in/all-instructions.prg test-out/all-instructions.prg
echo

echo "=== all-instructions.prg (don't disassemble anything) ==="
python3 nesdisasm.py --unaccessed-as-data test-in/all-instructions.prg > test-out/all-instructions-nodis.asm
asm6 test-out/all-instructions-nodis.asm test-out/all-instructions-nodis.prg
diff -q test-in/all-instructions.prg test-out/all-instructions-nodis.prg
echo

echo "=== anontest.prg ==="
python3 nesdisasm.py test-in/anontest.prg > test-out/anontest.asm
asm6 test-out/anontest.asm test-out/anontest.prg
diff -q test-in/anontest.prg test-out/anontest.prg
echo

echo "=== anontest.prg (no anonymous labels) ==="
python3 nesdisasm.py --no-anonymous-labels test-in/anontest.prg > test-out/anontest-noanon.asm
asm6 test-out/anontest-noanon.asm test-out/anontest-noanon.prg
diff -q test-in/anontest.prg test-out/anontest-noanon.prg
echo

echo "=== Game Genie ==="
python3 nesdisasm.py -z -o 00,01,21,31,41,51,61,71,81,a1,c1,d1,e1,f1 -a 0800-1fff,2008-3fff,4020-7fff -x 2000-401f -w 8002-ffef,fff2-ffff test-in/gamegenie.prg > test-out/gamegenie.asm
cp test-out/gamegenie.asm sample-output.txt
asm6 test-out/gamegenie.asm test-out/gamegenie.prg
diff -q test-in/gamegenie.prg test-out/gamegenie.prg
echo

echo "=== Excitebike (CDL) ==="
python3 nesdisasm.py -z -o 00 -a 0800-1fff,2008-3fff,4020-bfff -x 2000-401f -w 8000-ffff test-in/excitebike.prg -c ~/nes/cdl/excitebike-ju.cdl > test-out/excitebike.asm
asm6 test-out/excitebike.asm test-out/excitebike.prg
diff -q test-in/excitebike.prg test-out/excitebike.prg
echo

echo "=== Lunar Pool (CDL; disassemble unaccessed bytes) ==="
python3 nesdisasm.py -z -o 00,01,41,c1,e1 -a 0800-1fff,2008-3fff,4020-bfff -x 2000-401f -w 8000-ffff -c ~/nes/cdl/lunarpool-u.cdl test-in/lunarpool.prg > test-out/lunarpool.asm
asm6 test-out/lunarpool.asm test-out/lunarpool.prg
diff -q test-in/lunarpool.prg test-out/lunarpool.prg
echo

echo "=== Lunar Pool (CDL; don't disassemble unaccessed bytes) ==="
python3 nesdisasm.py -z -o 00,01,41,c1,e1 -a 0800-1fff,2008-3fff,4020-bfff -x 2000-401f -w 8000-ffff -c ~/nes/cdl/lunarpool-u.cdl --unaccessed-as-data test-in/lunarpool.prg > test-out/lunarpool-nounacc.asm
asm6 test-out/lunarpool-nounacc.asm test-out/lunarpool-nounacc.prg
diff -q test-in/lunarpool.prg test-out/lunarpool-nounacc.prg
echo

echo "=== Lunar Pool (no CDL, indentation 5) ==="
python3 nesdisasm.py -z -o 00,01,41,c1,e1 -a 0800-1fff,2008-3fff,4020-bfff -x 2000-401f -w 8000-ffff -i 5 test-in/lunarpool.prg > test-out/lunarpool-nocdl.asm
asm6 test-out/lunarpool-nocdl.asm test-out/lunarpool-nocdl.prg
diff -q test-in/lunarpool.prg test-out/lunarpool-nocdl.prg
echo

echo "=== SMB (use CDL file, indentation 12, 16 data bytes/line) ==="
python3 nesdisasm.py -z -o 00,01,11,21,31,41,51,61,71,81,a1,c1,d1,e1,f1 -a 0800-1fff,2008-3fff,4020-7fff -x 2000-401f -w 8000-ffff -c ~/nes/cdl/smb1-w.cdl -i 12 -d 16 test-in/smb1.prg > test-out/smb1.asm
asm6 test-out/smb1.asm test-out/smb1.prg
diff -q test-in/smb1.prg test-out/smb1.prg
echo

rm -f test-out/*.prg
