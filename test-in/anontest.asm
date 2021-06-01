; this is a manually-written test file; assemble with ASM6 into anontest.prg
; note: the "brk" instructions are for readability

    org $ff00

; --- bpl ------------------------------------------------------------------------------------------

-   bpl -

    brk

; --- bpl, bpl, nop (1st target >= 2nd target) -----------------------------------------------------

-   bpl -
    bpl -
    nop

    brk

-   bpl +
+   bpl -
    nop

    brk

-   bpl +
    bpl -
+   nop

    brk

    bpl l1
l1  bpl l1
    nop

    brk

    bpl +
-   bpl -
+   nop

    brk

    bpl +
    bpl +
+   nop

    brk

; --- bpl, nop, bpl, nop (1st target >= 2nd target) ------------------------------------------------

-   bpl -
    nop
    bpl -
    nop

    brk

-   bpl +
+   nop
    bpl -
    nop

    brk

-   bpl +
    nop
+   bpl -
    nop

    brk

-   bpl +
    nop
    bpl -
+   nop

    brk

    bpl l2
l2  nop
    bpl l2
    nop

    brk

    bpl +
-   nop
+   bpl -
    nop

    brk

    bpl +
-   nop
    bpl -
+   nop

    brk

    bpl l3
    nop
l3  bpl l3
    nop

    brk

    bpl +
    nop
-   bpl -
+   nop

    brk

    bpl +
    nop
    bpl +
+   nop

    brk

; --- misc (1st target >= 2nd target >= 3rd target) ------------------------------------------------

--  bpl ++
-   bpl +
+   bpl -
++  bpl --

    brk

--  bpl +
-   bpl ++
+   bpl --
++  bpl -

    brk

--- bpl +++
--  bpl ++
-   bpl +
+   bpl -
++  bpl --
+++ bpl ---

    brk

--- bpl +
--  bpl ++
-   bpl +++
+   bpl ---
++  bpl --
+++ bpl -

    brk

; --------------------------------------------------------------------------------------------------

    pad $10000, $ff
