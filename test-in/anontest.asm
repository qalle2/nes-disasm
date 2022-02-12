; test anonymous labels (the BRK instructions are for readability)

; --- BPL -----------------------------------------------------------------------------------------

        base $ff00

-       bpl -
        brk

; --- BPL, BPL, NOP (1st target >= 2nd target) ----------------------------------------------------

-       bpl -
        bpl -
        nop
        brk

-       bpl +
+       bpl -
        nop
        brk

-       bpl +
        bpl -
+       nop
        brk

        bpl label1
label1  bpl label1
        nop
        brk

        bpl +
-       bpl -
+       nop
        brk

        bpl +
        bpl +
+       nop
        brk

; --- BPL, NOP, BPL, NOP (1st target >= 2nd target) -----------------------------------------------

-       bpl -
        nop
        bpl -
        nop
        brk

-       bpl +
+       nop
        bpl -
        nop
        brk

-       bpl +
        nop
+       bpl -
        nop
        brk

-       bpl +
        nop
        bpl -
+       nop
        brk

        bpl label2
label2  nop
        bpl label2
        nop
        brk

        bpl +
-       nop
+       bpl -
        nop
        brk

        bpl +
-       nop
        bpl -
+       nop
        brk

        bpl label3
        nop
label3  bpl label3
        nop
        brk

        bpl +
        nop
-       bpl -
+       nop
        brk

        bpl +
        nop
        bpl +
+       nop
        brk

; --- misc (1st target >= 2nd target >= 3rd target) -----------------------------------------------

--      bpl ++
-       bpl +
+       bpl -
++      bpl --
        brk

--      bpl +
-       bpl ++
+       bpl --
++      bpl -
        brk

---     bpl +++
--      bpl ++
-       bpl +
+       bpl -
++      bpl --
+++     bpl ---
        brk

---     bpl +
--      bpl ++
-       bpl +++
+       bpl ---
++      bpl --
+++     bpl -
        brk

        pad $10000, $ff
