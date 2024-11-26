# Warning: this script DELETES files. Run at your own risk.

clear
rm -f test-out/*.asm test-out/*.bin

echo "=== Assembling with ASM6 ==="
asm6 test-in/allinstr.asm test-out/allinstr.bin
asm6 test-in/anontest.asm test-out/anontest.bin
echo

echo "=== Disassembling with nesdisasm.py ==="
python3 nesdisasm.py \
    test-out/allinstr.bin > test-out/allinstr.asm
python3 nesdisasm.py \
    test-out/anontest.bin > test-out/anontest.asm
python3 nesdisasm.py \
    --no-anonymous-labels \
    test-out/anontest.bin > test-out/anontest-noanon.asm
python3 nesdisasm.py \
    -c test-in/gamegenie.cdl \
    test-in/gamegenie.bin > test-out/gamegenie.asm
python3 nesdisasm.py \
    -a 0800-1fff,2008-3fff,4020-7fff -w 8002-ffef,fff2-ffff \
    test-in/gamegenie.bin > test-out/gamegenie-nocdl.asm
python3 nesdisasm.py \
    -c test-in/excitebike-ju.cdl \
    test-in/excitebike-ju.bin > test-out/excitebike.asm
python3 nesdisasm.py \
    -a 0800-1fff,2008-3fff,4020-bfff -w 8000-ffff \
    test-in/excitebike-ju.bin > test-out/excitebike-nocdl.asm
python3 nesdisasm.py \
    -c test-in/lunarpool-u.cdl \
    test-in/lunarpool-u.bin > test-out/lunarpool.asm
python3 nesdisasm.py \
    -i 5 -a 0800-1fff,2008-3fff,4020-bfff -w 8000-ffff \
    test-in/lunarpool-u.bin > test-out/lunarpool-nocdl.asm
python3 nesdisasm.py \
    -i 12 -d 16 -c test-in/smb1-w.cdl -a 0800-1fff,2008-3fff,4020-7fff -w 8000-ffff \
    test-in/smb1-w.bin > test-out/smb1.asm
echo

echo "=== Reassembling with ASM6 ==="
asm6 test-out/allinstr.asm         test-out/allinstr2.bin
asm6 test-out/anontest.asm         test-out/anontest2.bin
asm6 test-out/anontest-noanon.asm  test-out/anontest3.bin
asm6 test-out/gamegenie.asm        test-out/gamegenie.bin
asm6 test-out/gamegenie-nocdl.asm  test-out/gamegenie2.bin
asm6 test-out/excitebike.asm       test-out/excitebike.bin
asm6 test-out/excitebike-nocdl.asm test-out/excitebike2.bin
asm6 test-out/lunarpool.asm        test-out/lunarpool.bin
asm6 test-out/lunarpool-nocdl.asm  test-out/lunarpool2.bin
asm6 test-out/smb1.asm             test-out/smb1.bin
echo

echo "=== Verifying ==="
md5sum -c --quiet hashes.md5
echo

rm -f test-out/*.bin
cp test-out/gamegenie.asm sample-output.txt
