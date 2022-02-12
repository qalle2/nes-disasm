; test all opcodes

; --- 1-byte instructions -------------------------------------------------------------------------

        base $fd00

        asl a
        brk
        clc
        cld
        cli
        clv
        dex
        dey
        inx
        iny
        lsr a
        nop
        pha
        php
        pla
        plp
        rol a
        ror a
        rti
        rts
        sec
        sed
        sei
        tax
        tay
        tsx
        txa
        txs
        tya

; --- 2-byte instructions -------------------------------------------------------------------------

        adc #$ff
        adc $ff
        adc $ff,x
        adc ($ff,x)
        adc ($ff),y

        and #$ff
        and $ff
        and $ff,x
        and ($ff,x)
        and ($ff),y

        asl $ff
        asl $ff,x

label1  bcc label1+1

label2  bcs label2+1

label3  beq label3+1

        bit $ff

label4  bmi label4+1

label5  bne label5+1

label6  bpl label6+1

label7  bvc label7+1

label8  bvs label8+1

        cmp #$ff
        cmp $ff
        cmp $ff,x
        cmp ($ff,x)
        cmp ($ff),y

        cpx #$ff
        cpx $ff

        cpy #$ff
        cpy $ff

        dec $ff
        dec $ff,x

        eor #$ff
        eor $ff
        eor $ff,x
        eor ($ff,x)
        eor ($ff),y

        inc $ff
        inc $ff,x

        lda #$ff
        lda $ff
        lda $ff,x
        lda ($ff,x)
        lda ($ff),y

        ldx #$ff
        ldx $ff
        ldx $ff,y

        ldy #$ff
        ldy $ff
        ldy $ff,x

        lsr $ff
        lsr $ff,x

        ora #$ff
        ora $ff
        ora $ff,x
        ora ($ff,x)
        ora ($ff),y

        rol $ff
        rol $ff,x

        ror $ff
        ror $ff,x

        sbc #$ff
        sbc $ff
        sbc $ff,x
        sbc ($ff,x)
        sbc ($ff),y

        sta $ff
        sta $ff,x
        sta ($ff,x)
        sta ($ff),y

        stx $ff
        stx $ff,y

        sty $ff
        sty $ff,x

; --- 3-byte instructions -------------------------------------------------------------------------

        ; note: some instructions have been written as bytes to prevent ASM6 from optimizing them

        adc $beef
        adc $beef,x
        adc $beef,y
        hex 6d ff 00  ; adc $00ff
        hex 7d ff 00  ; adc $00ff,x

        and $beef
        and $beef,x
        and $beef,y
        hex 2d ff 00  ; and $00ff
        hex 3d ff 00  ; and $00ff,x

        asl $beef
        asl $beef,x
        hex 0e ff 00  ; asl $00ff
        hex 1e ff 00  ; asl $00ff,x

        bit $beef
        hex 2c ff 00  ; bit $00ff

        cmp $beef
        cmp $beef,x
        cmp $beef,y
        hex cd ff 00  ; cmp $00ff
        hex dd ff 00  ; cmp $00ff,x

        cpx $beef
        hex ec ff 00  ; cpx $00ff

        cpy $beef
        hex cc ff 00  ; cpy $00ff

        dec $beef
        dec $beef,x
        hex ce ff 00  ; dec $00ff
        hex de ff 00  ; dec $00ff,x

        eor $beef
        eor $beef,x
        eor $beef,y
        hex 4d ff 00  ; eor $00ff
        hex 5d ff 00  ; eor $00ff,x

        inc $beef
        inc $beef,x
        hex ee ff 00  ; inc $00ff
        hex fe ff 00  ; inc $00ff,x

        jmp $beef
        jmp ($beef)

        jsr $beef

        lda $beef
        lda $beef,x
        lda $beef,y
        hex ad ff 00  ; lda $00ff
        hex bd ff 00  ; lda $00ff,x

        ldx $beef
        ldx $beef,y
        hex ae ff 00  ; ldx $00ff
        hex be ff 00  ; ldx $00ff,y

        ldy $beef
        ldy $beef,x
        hex ac ff 00  ; ldy $00ff
        hex bc ff 00  ; ldy $00ff,x

        lsr $beef
        lsr $beef,x
        hex 4e ff 00  ; lsr $00ff
        hex 5e ff 00  ; lsr $00ff,x

        ora $beef
        ora $beef,x
        ora $beef,y
        hex 0d ff 00  ; ora $00ff
        hex 1d ff 00  ; ora $00ff,x

        rol $beef
        rol $beef,x
        hex 2e ff 00  ; rol $00ff
        hex 3e ff 00  ; rol $00ff,x

        ror $beef
        ror $beef,x
        hex 6e ff 00  ; ror $00ff
        hex 7e ff 00  ; ror $00ff,x

        sbc $beef
        sbc $beef,x
        sbc $beef,y
        hex ed ff 00  ; sbc $00ff
        hex fd ff 00  ; sbc $00ff,x

        sta $beef
        sta $beef,x
        sta $beef,y
        hex 8d ff 00  ; sta $00ff
        hex 9d ff 00  ; sta $00ff,x

        stx $beef
        hex 8e ff 00  ; stx $00ff

        sty $beef
        hex 8c ff 00  ; sty $00ff

; --- Undocumented opcodes ------------------------------------------------------------------------

        hex 02 03 04 07 0b 0c 0f 12 13 14 17 1a 1b 1c 1f 22
        hex 23 27 2b 2f 32 33 34 37 3a 3b 3c 3f 42 43 44 47
        hex 4b 4f 52 53 54 57 5a 5b 5c 5f 62 63 64 67 6b 6f
        hex 72 73 74 77 7a 7b 7c 7f 80 82 83 87 89 8b 8f 92
        hex 93 97 9b 9c 9e 9f a3 a7 ab af b2 b3 b7 bb bf c2
        hex c3 c7 cb cf d2 d3 d4 d7 da db dc df e2 e3 e7 eb
        hex ef f2 f3 f4 f7 fa fb fc ff

        pad $10000, $ff
