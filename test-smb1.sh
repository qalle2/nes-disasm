# Warning: this script DELETES files. Run at your own risk.

clear

rm -f test-out/*.asm test-out/*.bin

echo "=== Disassembling ==="
python3 nesdisasm.py -c test-in/smb1-w.cdl -a 0800-1fff,2008-3fff,4020-7fff -w 8000-ffff \
    test-in/smb1-w.bin > test-out/smb1.asm
echo

echo "=== Reassembling ==="
asm6 test-out/smb1.asm test-out/smb1.bin
echo

echo "=== Verifying ==="
diff -q test-in/smb1-w.bin test-out/smb1.bin
echo

# delete reassembled
rm -f test-out/*.bin
