; this is a manually-written test file; assemble with ASM6 into all-instructions.prg
; note: some instructions have been written as bytes to prevent ASM6 from optimizing them

    org $fe00

; --- 1-byte instructions --------------------------------------------------------------------------

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

; --- 2-byte instructions --------------------------------------------------------------------------

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

l1  bcc l1+1

l2  bcs l2+1

l3  beq l3+1

    bit $ff

l4  bmi l4+1

l5  bne l5+1

l6  bpl l6+1

l7  bvc l7+1

l8  bvs l8+1

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

; --- 3-byte instructions --------------------------------------------------------------------------

    adc $beef
    adc $beef,x
    adc $beef,y
    db $6d, $ff, $00  ; adc $00ff
    db $7d, $ff, $00  ; adc $00ff,x

    and $beef
    and $beef,x
    and $beef,y
    db $2d, $ff, $00  ; and $00ff
    db $3d, $ff, $00  ; and $00ff,x

    asl $beef
    asl $beef,x
    db $0e, $ff, $00  ; asl $00ff
    db $1e, $ff, $00  ; asl $00ff,x

    bit $beef
    db $2c, $ff, $00  ; bit $00ff

    cmp $beef
    cmp $beef,x
    cmp $beef,y
    db $cd, $ff, $00  ; cmp $00ff
    db $dd, $ff, $00  ; cmp $00ff,x

    cpx $beef
    db $ec, $ff, $00  ; cpx $00ff

    cpy $beef
    db $cc, $ff, $00  ; cpy $00ff

    dec $beef
    dec $beef,x
    db $ce, $ff, $00  ; dec $00ff
    db $de, $ff, $00  ; dec $00ff,x

    eor $beef
    eor $beef,x
    eor $beef,y
    db $4d, $ff, $00  ; eor $00ff
    db $5d, $ff, $00  ; eor $00ff,x

    inc $beef
    inc $beef,x
    db $ee, $ff, $00  ; inc $00ff
    db $fe, $ff, $00  ; inc $00ff,x

    jmp $beef
    jmp ($beef)

    jsr $beef

    lda $beef
    lda $beef,x
    lda $beef,y
    db $ad, $ff, $00  ; lda $00ff
    db $bd, $ff, $00  ; lda $00ff,x

    ldx $beef
    ldx $beef,y
    db $ae, $ff, $00  ; ldx $00ff
    db $be, $ff, $00  ; ldx $00ff,y

    ldy $beef
    ldy $beef,x
    db $ac, $ff, $00  ; ldy $00ff
    db $bc, $ff, $00  ; ldy $00ff,x

    lsr $beef
    lsr $beef,x
    db $4e, $ff, $00  ; lsr $00ff
    db $5e, $ff, $00  ; lsr $00ff,x

    ora $beef
    ora $beef,x
    ora $beef,y
    db $0d, $ff, $00  ; ora $00ff
    db $1d, $ff, $00  ; ora $00ff,x

    rol $beef
    rol $beef,x
    db $2e, $ff, $00  ; rol $00ff
    db $3e, $ff, $00  ; rol $00ff,x

    ror $beef
    ror $beef,x
    db $6e, $ff, $00  ; ror $00ff
    db $7e, $ff, $00  ; ror $00ff,x

    sbc $beef
    sbc $beef,x
    sbc $beef,y
    db $ed, $ff, $00  ; sbc $00ff
    db $fd, $ff, $00  ; sbc $00ff,x

    sta $beef
    sta $beef,x
    sta $beef,y
    db $8d, $ff, $00  ; sta $00ff
    db $9d, $ff, $00  ; sta $00ff,x

    stx $beef
    db $8e, $ff, $00  ; stx $00ff

    sty $beef
    db $8c, $ff, $00  ; sty $00ff

    pad $10000
