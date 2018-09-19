/* radare - LGPL - Copyright 2015-2017 - pancake, condret, riq, qnix, astuder */

#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "ba_disas.h"

char *reg [] =
{
    "r0", "r1", "r2", "r3",
    "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19",
    "r20", "r21", "r22", "r23",
    "r24", "r25", "r26", "r27",
    "r28", "r29", "r30", "r31",
};

/*
 * bt: 2B inst
 * bn: 3B inst
 * bg: 4B inst
 * bw: 6B inst
 */
static const char *inst6 [] =
{
    "b.aadd",
    "b.add",
    "b.addc",
    "b.and",
    "b.cmov",
    "b.cmpxchg",
    "b.div",
    "b.divu",
    "b.flb",
    "b.nand",
    "b.or",
    "b.ror",
    "b.rori",
    "b.sll",
    "b.slli",
    "b.sra",
    "b.srai",
    "b.srl",
    "b.srli",
    "b.sub",
    "b.subb",
    "b.xor",
};

static const char *inst8 [] =
{
    "b.lbz",
    "b.ld",
    "b.lhz",
    "b.lws",
    "b.lwz",
    "b.sb",
    "b.sd",
    "b.sh",
    "b.sw",
};

static const char *inst9 [] =
{
    "b.addi",
    "b.andi",
    "b.ori",
    "b.sfeqi",
    "b.sfgesi",
    "b.sfgeui",
    "b.sfgtsi",
    "b.sfgtui",
    "b.sflesi",
    "b.sfleui",
    "b.sfltsi",
    "b.sfltui",
    "b.sfnei",
};

static const char *instc [] =
{
    "b.lbz",
    "b.ld",
    "b.lhz",
    "b.lws",
    "b.lwz",
    "b.sb",
    "b.sd",
    "b.sh",
    "b.sw",
};

/*
 * arg0: original value
 * arg1: effective bit
 */
static ut32 extend_unsigned(ut32 n, ut32 s)
{
    // 1. bit reverse
    n =  ((n >> 1) & 0x55555555) | ((n << 1) & 0xaaaaaaaa);
    n =  ((n >> 2) & 0x33333333) | ((n << 2) & 0xcccccccc);
    n =  ((n >> 4) & 0x0f0f0f0f) | ((n << 4) & 0xf0f0f0f0);
    n =  ((n >> 8) & 0x00ff00ff) | ((n << 8) & 0xff00ff00);
    n = ((n >> 16) & 0x0000ffff) | ((n << 16) & 0xffff0000);
    n>>=(32-s);

    return n;
}

/*
 * arg0: original value
 * arg1: effective bit
 */
static ut32 extend_signed(ut32 n, ut32 s)
{
    // 1. bit reverse
    n =  ((n >> 1) & 0x55555555) | ((n << 1) & 0xaaaaaaaa);
    n =  ((n >> 2) & 0x33333333) | ((n << 2) & 0xcccccccc);
    n =  ((n >> 4) & 0x0f0f0f0f) | ((n << 4) & 0xf0f0f0f0);
    n =  ((n >> 8) & 0x00ff00ff) | ((n << 8) & 0xff00ff00);
    n = ((n >> 16) & 0x0000ffff) | ((n << 16) & 0xffff0000);
    n>>=(32-s);

    // 2. sign extesion
    if (n & 1<<(s-1)) {
        n |= ~((1<<s)-1);
    }
    return n;
}

static const char *inst0 [] =
{
    "b.add",
    "b.addi",
    "b.di",
    "b.ei",
    "b.j",
    "b.mov",
    "b.movi",
    "b.nop",
    "b.rfe",
    "b.sys",
    "b.trap",
};

void disas_0(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    ut8 opc = ((*buf)&0xC)>>2; //[11:10]
    ut8 ra = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[9:5]
    ut8 rb = (*(buf+1))&0x1F; //[4:0]
    ut32 iv;

    switch (opc) {
        case 3: //j
            i = 4;
            iv = ((*buf)&0x3)<<8 | *(buf+1);
            iv = extend_signed(iv, 10);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)", inst0[i], (ut32)a->pc+iv, iv);
            break;
        case 2: //add
            i = 0;
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%s",inst0[i], reg[ra], reg[ra], reg[rb]);
            break;
        case 1:
            if (ra ==0 && rb==2) { //di
                i = 2;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
            }
            else if (ra ==0 && rb==1) { //ei
                i = 3;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
            }
            else if (ra ==0 && rb==0) { //rfe
                i = 8;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
            }
            else if (ra ==0 && rb==3) { //sys
                i = 9;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
            }
            else { //mov
                i = 5;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst0[i], reg[ra], reg[rb]);
            }
            break;
        case 0:
            if (rb&0x10) {
                if (ra==0) { //nop
                    i = 7;
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
                }
                else { //addi
                    i = 1;
                    iv = extend_signed(rb, 4);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%+d",inst0[i], reg[ra], reg[ra], iv);
                }
            }
            else {
                if (ra==0) { //trap
                    i = 10;
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
                }
                else { //movi
                    i = 6;
                    iv = extend_signed(rb, 4);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%+d",inst0[i], reg[ra], iv);
                }
            }
            break;
    }
    op->size = 2;
}

void disas_1(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "non-support";
    strcpy(op->buf_asm, str);
    op->size = 0;
}

static const char *inst2 [] =
{
    "b.lbz",
    "b.ld",
    "b.lhz",
    "b.lws",
    "b.lwz",
    "b.sb",
    "b.sd",
    "b.sh",
    "b.sw",
};

void disas_2(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    ut8 opc = ((*buf)&0xF)>>2;
    ut8 ra = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5;
    ut8 rb = (*(buf+1))&0x1F;
    ut32 iv = *(buf+2);

    switch (opc) {
        case 0: //sb
            i = 5;
            iv = extend_unsigned(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%s),%s",inst2[i], iv, reg[rb], reg[ra]);
            break;
        case 1: //lbz
            i = 0;
            iv = extend_unsigned(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%s)",inst2[i], reg[ra], iv, reg[rb]);
            break;
        case 2:
            if (iv&0x80) { //lhz
                i = 2;
                iv = extend_unsigned(iv, 7);
                iv <<= 1;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%s)",inst2[i], reg[ra], iv, reg[rb]);
            }
            else { //sh
                i = 7;
                iv = extend_unsigned(iv, 7);
                iv <<= 1;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%s),%s",inst2[i], iv, reg[rb], reg[ra]);
            }
            break;
        case 3:
            switch (iv>>6) {
                case 0: //sw
                    i = 8;
                    iv = extend_unsigned(iv, 6);
                    iv <<= 2;
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%s),%s",inst2[i], iv, reg[rb], reg[ra]);
                    break;
                case 1: //lwz
                    i = 4;
                    iv = extend_unsigned(iv, 6);
                    iv <<= 2;
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%s)",inst2[i], reg[ra], iv, reg[rb]);
                    break;
                case 2: //lws
                    i = 3;
                    iv = extend_signed(iv, 6);
                    iv <<= 2;
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%s)",inst2[i], reg[ra], iv, reg[rb]);
                    break;
                case 3:
                    if (iv&0x20) { //ld
                        i = 1;
                        iv = extend_unsigned(iv, 5);
                        iv <<= 3;
                        snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%s)",inst2[i], reg[ra], iv, reg[rb]);
                    }
                    else { //sd
                        i = 6;
                        iv = extend_unsigned(iv, 5);
                        iv <<= 3;
                        snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%s),%s",inst2[i], iv, reg[rb], reg[ra]);
                    }
                    break;
            }
            break;
    }
    op->size = 3;
}

static const char *inst3 [] =
{
    "b.addi",
    "b.andi",
    "b.bitrev",
    "b.clz",
    "b.extbs",
    "b.extbz",
    "b.exths",
    "b.exthz",
    "b.ff1",
    "b.mfspr",
    "b.mtspr",
    "b.ori",
    "b.sfeq",
    "b.sfeqi",
    "b.sfges",
    "b.sfgesi",
    "b.sfgeu",
    "b.sfgeui",
    "b.sfgts",
    "b.sfgtsi",
    "b.sfgtu",
    "b.sfgtui",
    "b.sflesi",
    "b.sfleui",
    "b.sfltsi",
    "b.sfltui",
    "b.sfne",
    "b.sfnei",
    "b.swab",
};

void disas_3(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    //bn.sfxx format
    ut8 ra = ((*(buf+1))&0x1F); //[12:8]
    ut8 rb = ((*(buf+2))&0xF8)>>3; //[7:3]
    ut32 iv = (*(buf+2)); //[7:0]

    op->size = 3;
    switch (((*buf)&0xC)>>2) { //[19:18]
        case 0: //addi
            i = 0;
            ra = ((*buf)&0x03)<<3 | ((*(buf+1))&0xE0)>>5; //[17:13]
            rb = ((*(buf+1))&0x1F); //[12:8]
            iv = extend_signed(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%+d",inst3[i], reg[ra], reg[rb], iv);
            break;
        case 1: //andi
            i = 1;
            ra = ((*buf)&0x03)<<3 | ((*(buf+1))&0xE0)>>5; //[17:13]
            rb = ((*(buf+1))&0x1F); //[12:8]
            iv = extend_unsigned(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%+d",inst3[i], reg[ra], reg[rb], iv);
            break;
        case 2: //ori
            i = 11;
            ra = ((*buf)&0x03)<<3 | ((*(buf+1))&0xE0)>>5; //[17:13]
            rb = ((*(buf+1))&0x1F); //[12:8]
            iv = extend_unsigned(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%+d",inst3[i], reg[ra], reg[rb], iv);
            break;
        case 3:
            switch ((*buf)&0x3) { //[17:16]
                case 0:
                    switch ((*(buf+1)&0xE0)>>5) { //[15:13]
                        case 0: //sfeqi
                            i = 13;
                            break;
                        case 1: //sfnei
                            i = 27;
                            break;
                        case 2: //sfgesi
                            i = 15;
                            break;
                        case 3: //sfgeui
                            i = 17;
                            break;
                        case 4: //sfgtsi
                            i = 19;
                            break;
                        case 5: //sfgtui
                            i = 21;
                            break;
                        case 6: //sflesi
                            i = 22;
                            break;
                        case 7: //sfleui
                            i = 23;
                            break;
                    }
                    iv = extend_signed(iv, 8);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%+d",inst3[i], reg[ra], iv);
                    break;
                case 1:
                    switch ((*(buf+1)&0xE0)>>5) { //[15:13]
                        case 0: //sfltsi
                            i = 24;
                            iv = extend_signed(iv, 8);
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%+d",inst3[i], reg[ra], iv);
                            break;
                        case 1: //sfltui
                            iv = extend_signed(iv, 8);
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%+d",inst3[i], reg[ra], iv);
                            i = 25;
                            break;
                        case 2: //sfeq
                            i = 12;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[ra], reg[rb]);
                            break;
                        case 3: //sfne
                            i = 26;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[ra], reg[rb]);
                            break;
                        case 4: //sfges
                            i = 14;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[ra], reg[rb]);
                            break;
                        case 5: //sfgeu
                            i = 16;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[ra], reg[rb]);
                            break;
                        case 6: //sfgts
                            i = 18;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[ra], reg[rb]);
                            break;
                        case 7: //sfgtu
                            i = 20;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[ra], reg[rb]);
                            break;
                    }
                    break;
                case 2:
                    switch ((*(buf+1)&0x60)>>5) { //[14:13]
                        case 0:
                            switch (*(buf+2)&0x7) { //[2:0]
                                case 0: //extbz
                                    i = 5;
                                    break;
                                case 1: //extbs
                                    i = 4;
                                    break;
                                case 2: //exthz
                                    i = 7;
                                    break;
                                case 3: //exths
                                    i = 6;
                                    break;
                                case 4: //ff1
                                    i = 8;
                                    break;
                                case 5: //clz
                                    i = 3;
                                    break;
                                case 6: //bitrev
                                    i = 2;
                                    break;
                                case 7: //swab
                                    i = 28;
                                    break;
                            }
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[rb], reg[ra]);
                            break;
                        case 1:
                            switch (*(buf+2)&0x7) { //[2:0]
                                case 0: //mfspr
                                    i = 9;
                                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[rb], reg[ra]);
                                    break;
                                case 1: //mtspr
                                    i = 10;
                                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s",inst3[i], reg[ra], reg[rb]);
                                    break;
                            }
                            break;
                    }
                    break;
            }
            break;
    }
}

static const char *inst4 [] =
{
    "b.bc",
    "b.beqi",
    "b.bf",
    "b.bgesi",
    "b.bgtsi",
    "b.blesi",
    "b.bltsi",
    "b.bnc",
    "b.bnei",
    "b.bnf",
    "b.bno",
    "b.bo",
    "b.entri",
    "b.j",
    "b.jal",
    "b.jalr",
    "b.jr",
    "b.reti",
    "b.return",
    "b.rtnei",
};

void disas_4(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    ut8 opc = ((*buf)&0xF);
    ut32 ia = ((*(buf+1))&0xE0)>>5; //[15:13]
    ut8 rb = (*(buf+1))&0x1F; //[12:8]
    ut32 iv = *(buf+2); //[7:0]

    switch (opc) {
        case 0: //beqi
            i = 1;
            ia = extend_unsigned(ia, 3);
            iv = extend_signed(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",inst4[i], reg[rb], ia, (ut32)a->pc+iv, iv);
            break;
        case 1: //bnei
            i = 0;
            ia = extend_unsigned(ia, 3);
            iv = extend_signed(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",inst4[i], reg[rb], ia, (ut32)a->pc+iv, iv);
            break;
        case 2: //bgesi
            i = 3;
            ia = extend_unsigned(ia, 3);
            iv = extend_signed(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",inst4[i], reg[rb], ia, (ut32)a->pc+iv, iv);
            break;
        case 3: //bgtsi
            i = 4;
            ia = extend_unsigned(ia, 3);
            iv = extend_signed(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",inst4[i], reg[rb], ia, (ut32)a->pc+iv, iv);
            break;
        case 4: //blesi
            i = 5;
            ia = extend_unsigned(ia, 3);
            iv = extend_signed(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",inst4[i], reg[rb], ia, (ut32)a->pc+iv, iv);
            break;
        case 5: //bltsi
            i = 6;
            ia = extend_unsigned(ia, 3);
            iv = extend_signed(iv, 8);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",inst4[i], reg[rb], ia, (ut32)a->pc+iv, iv);
            break;
        case 6: //j
            i = 13;
            iv |= (*(buf+1)<<8);
            iv = extend_signed(iv, 16);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",inst4[i], (ut32)a->pc+iv, iv);
            break;
        case 7:
            switch (*(buf+1)>>4) {
                case 2: //bf
                    i = 2;
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",inst4[i], (ut32)a->pc+iv, iv);
                    break;
                case 3: //bnf
                    i = 9;
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",inst4[i], (ut32)a->pc+iv, iv);
                    break;
                case 4: //bo
                    i = 11;
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",inst4[i], (ut32)a->pc+iv, iv);
                    break;
                case 5: //bno
                    i = 10;
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",inst4[i], (ut32)a->pc+iv, iv);
                    break;
                case 6: //bc
                    i = 0;
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",inst4[i], (ut32)a->pc+iv, iv);
                    break;
                case 7: //bnc
                    i = 7;
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",inst4[i], (ut32)a->pc+iv, iv);
                    break;
                case 10: //entri
                    i = 12;
                    ia = rb & 0xF;
                    ia = extend_unsigned(ia, 4);
                    iv = extend_unsigned(iv, 8);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x,%x",inst4[i], ia, iv);
                    break;
                case 11: //reti
                    i = 17;
                    ia = rb & 0xF;
                    ia = extend_unsigned(ia, 4);
                    iv = extend_unsigned(iv, 8);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x,%x",inst4[i], ia, iv);
                    break;
                case 12: //rtnei
                    i = 19;
                    ia = rb & 0xF;
                    ia = extend_unsigned(ia, 4);
                    iv = extend_unsigned(iv, 8);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x,%x",inst4[i], ia, iv);
                    break;
                case 13:
                    switch (*(buf+1)&0x3) {
                        case 0: //return
                            i = 18;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s", inst4[i]);
                            break;
                        case 1: //jalr
                            i = 15;
                            iv >>= 3;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s", inst4[i], reg[iv]);
                            break;
                        case 2: //jr
                            i = 16;
                            iv >>= 3;
                            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s", inst4[i], reg[iv]);
                            break;
                    }
                    break;
            }
            break;
    }
    if ((opc&0xc) == 0x8) { //jal
        i = 14;
        iv |= ((*(buf+1))<<8);
        iv |= ((*(buf+0)&0x3)<<16);
        iv = extend_signed(iv, 18);
        snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",inst4[i], (ut32)a->pc+iv, iv);
    }

    op->size = 3;
}

static const char *inst5 [] =
{
    "b.mlwz",
    "b.msw",
};

void disas_5(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    ut8 opc = ((*buf)&0xF)>>2; //[19:18]
    ut8 ra = ((*(buf))&0x3)<<3 | ((*(buf+1))&0xe0)>>5; //[17:13]
    ut8 rb = ((*(buf+1))&0x1F); //[12:8]
    ut32 ia = ((*(buf+2))&0xC0)>>6; //[7:6]
    ut32 iv = ((*(buf+2))&0x3F); //[5:0]
    ut8 c[] = { 2, 3, 4, 8 };

    switch (opc) {
        case 0: //mlwz
            i = 0;
            ia = extend_unsigned(ia, 2);
            iv = extend_unsigned(iv, 6);
            iv <<= 2;
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,0x%x(%s),0x%x",inst5[i], reg[ra], iv, reg[rb], c[ia]);
            break;
        case 1: //msw
            i = 1;
            ia = extend_unsigned(ia, 2);
            iv = extend_unsigned(iv, 6);
            iv <<= 2;
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s0x%x(%s),%s,0x%x",inst5[i], iv, reg[rb], reg[ra], c[ia]);
            break;
    }

    op->size = 3;
}

void disas_6(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 3;
}

static const char *inst7 [] =
{
    "b.adds",
    "b.subs",
};

void disas_7(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    ut8 opc = ((*buf)&0xF)>>2; //[19:18]
    ut8 ra = ((*(buf))&0x3)<<3 | ((*(buf+1))&0xe0)>>5; //[17:13]
    ut8 rb = ((*(buf+1))&0x1F); //[12:8]
    ut8 rc = ((*(buf+2))&0xF1)>>3; //[7:3]
    ut32 iv = ((*(buf+2))&0x07); //[2:0]

    op->size = 3;
    switch (opc) {
        case 1:
            if (iv == 0) { //bn.adds
                i = 0;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%s",inst7[i], reg[ra], reg[rb], reg[rc]);
            }
            else if (iv == 1) { //bn.subs
                i = 1;
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%s",inst7[i], reg[ra], reg[rb], reg[rc]);
            }
            break;
    }
}

void disas_8(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 6;
}

void disas_9(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 6;
}

static const char *insta [] =
{
    "b.addci",
    "b.beq",
    "b.beqi",
    "b.bf",
    "b.bges",
    "b.bgesi",
    "b.bgeu",
    "b.bgeui",
    "b.bgts",
    "b.bgtsi",
    "b.bgtu",
    "b.bgtui",
    "b.blesi",
    "b.bleui",
    "b.bltsi",
    "b.bltui",
    "b.bne",
    "b.bnei",
    "b.bnf",
    "b.j",
    "b.ja",
    "b.jal",
    "b.jma",
    "b.jmal",
    "b.lma",
    "b.mfspr",
    "b.mtspr",
    "b.sma",
    "b.xori",
};

void disas_a(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    ut8 opc = ((*buf)&0xC)>>2; //[43:42]
    ut8 ia = ((*(buf+1))&0x3E)>>1; //[37:33]
    ut8 rb = ((*(buf+1))&0x1)<<4 | ((*(buf+2))&0xF0)>>4; //[32:28]
    ut32 iv = ((*(buf+2))&0xF)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5); //[27:0]

    op->size = 6;
    switch (opc) {
        case 0:
            switch (((*buf)&0x3)<<2 | ((*(buf+1))&0xC0)>>6) { //[41:38]
                case 0: //beqi
                    i = 2;
                    break;
                case 1: //bnei
                    i = 17;
                    break;
                case 2: //bgesi
                    i = 5;
                    break;
                case 3: //bgtsi
                    i = 9;
                    break;
                case 4: //blesi
                    i = 12;
                    break;
                case 5: //bltsi
                    i = 14;
                    break;
                case 6: //bgeui
                    i = 7;
                    break;
                case 7: //bgtui
                    i = 11;
                    break;
                case 8: //bleui
                    i = 13;
                    break;
                case 9: //bltui
                    i = 15;
                    break;
                case 10: //beq
                    i = 1;
                    break;
                case 11: //bne
                    i = 16;
                    break;
                case 12: //bges
                    i = 4;
                    break;
                case 13: //bgts
                    i = 8;
                    break;
                case 14: //bgeu
                    i = 6;
                    break;
                case 15: //bgtu
                    i = 10;
                    break;
            }
            ia = extend_signed(ia, 5);
            iv = extend_signed(iv, 28);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",insta[i], reg[rb], ia, (ut32)a->pc+iv, iv);
            break;
        case 1:
            switch (((*buf)&0x3)<<2 | ((*(buf+1))&0xC0)>>6) { //[41:38]
                case 0: //jal
                    i = 21;
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",insta[i], (ut32)a->pc+iv, iv);
                    break;
                case 1: //j
                    i = 19;
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",insta[i], (ut32)a->pc+iv, iv);
                    break;
                case 2: //bf
                    i = 3;
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",insta[i], (ut32)a->pc+iv, iv);
                    break;
                case 3: //bnf
                    i = 18;
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",insta[i], (ut32)a->pc+iv, iv);
                    break;
                case 4: //ja
                    i = 20;
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",insta[i], (ut32)a->pc+iv, iv);
                    break;
                case 5:
                    if (!(*(buf+1))&0x1) { //jma
                        i = 22;
                        iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                        iv = extend_signed(iv, 32);
                        snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%+d)",insta[i], reg[ia], (ut32)a->pc+iv, iv);
                    }
                    else { //jmal
                        i = 23;
                        iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                        iv = extend_signed(iv, 32);
                        snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%+d)",insta[i], reg[ia], (ut32)a->pc+iv, iv);
                    }
                    break;
                case 6:
                    if (!(*(buf+1))&0x1) { //lma
                        i = 24;
                        iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                        iv = extend_signed(iv, 32);
                        snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%+d)",insta[i], reg[ia], (ut32)a->pc+iv, iv);
                    }
                    else { //sma
                        i = 27;
                        iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                        iv = extend_signed(iv, 32);
                        snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x(%+d)",insta[i], reg[ia], (ut32)a->pc+iv, iv);
                    }
                    break;
            }
            break;
        case 2:
            switch ((*(buf+5))&0x7) { //[2:0]
                case 0: //mfspr
                    i = 25;
                    ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[41:37]
                    rb = (*(buf+1))&0x1F; //[36:32]
                    iv = *(buf+2)<<16 | *(buf+3)<<8 | *(buf+4); //[31:8]
                    iv = extend_unsigned(iv, 24);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,0x%x",insta[i], reg[ia], reg[rb], iv);
                    break;
                case 1: //mtspr
                    i = 26;
                    ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[41:37]
                    rb = (*(buf+1))&0x1F; //[36:32]
                    iv = *(buf+2)<<16 | *(buf+3)<<8 | *(buf+4); //[31:8]
                    iv = extend_unsigned(iv, 24);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,0x%x",insta[i], reg[rb], reg[ia], iv);
                    break;
                case 2: //addci
                    i = 0;
                    ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[41:37]
                    rb = (*(buf+1))&0x1F; //[36:32]
                    iv = *(buf+2)<<16 | *(buf+3)<<8 | *(buf+4); //[31:8]
                    iv = extend_signed(iv, 24);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%+d",insta[i], reg[ia], reg[rb], iv);
                    break;
                case 6: //xori
                    i = 28;
                    ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[41:37]
                    rb = (*(buf+1))&0x1F; //[36:32]
                    iv = *(buf+2)<<16 | *(buf+3)<<8 | *(buf+4); //[31:8]
                    iv = extend_signed(iv, 24);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%+d",insta[i], reg[ia], reg[rb], iv);
                    break;
            }
            break;
    }
}

void disas_b(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "non-support";
    strcpy(op->buf_asm, str);
    op->size = 0;
}

void disas_c(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 4;
}

static const char *instd [] =
{
    "b.addi",
    "b.beq",
    "b.beqi",
    "b.bf",
    "b.bges",
    "b.bgesi",
    "b.bgeu",
    "b.bgeui",
    "b.bgts",
    "b.bgtsi",
    "b.bgtu",
    "b.bgtui",
    "b.blesi",
    "b.bleui",
    "b.bltsi",
    "b.bltui",
    "b.bne",
    "b.bnei",
    "b.bnf",
    "b.j",
    "b.jal",
};

void disas_d(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    ut8 opc = ((*buf)&0xF); //[27:24]
    ut8 ia = ((*(buf+1))&0x3E)>>1; //[21:17]
    ut8 rb = ((*(buf+1))&0x1)<<4 | ((*(buf+2))&0xF0)>>4; //[16:12]
    ut32 iv = ((*(buf+2))&0xF)<<8 | *(buf+3); //[11:0]

    switch (opc) {
        case 0:
            switch (((*(buf+1))&0xC0)>>6) {
                case 0: //beqi
                    i = 2;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 1: //bnei
                    i = 17;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 2: //bgesi
                    i = 5;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 3: //bgtsi
                    i = 9;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
            }
            break;
        case 1:
            switch (((*(buf+1))&0xC0)>>6) {
                case 0: //blesi
                    i = 12;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 1: //bltsi
                    i = 14;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 2: //bgeui
                    i = 7;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 3: //bgtui
                    i = 11;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
            }
            break;
        case 2:
            switch (((*(buf+1))&0xC0)>>6) {
                case 0: //bleui
                    i = 13;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 1: //bltui
                    i = 15;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 2: //beq
                    i = 1;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 3: //bne
                    i = 16;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
            }
            break;
        case 3:
            switch (((*(buf+1))&0xC0)>>6) {
                case 0: //bges
                    i = 4;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 1: //bgts
                    i = 8;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 2: //bgeu
                    i = 6;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
                case 3: //bgtu
                    i = 10;
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%x,%x(%+d)",instd[i], reg[rb], ia, (ut32)a->pc+iv, iv);
                    break;
            }
            break;
        case 4: //jal
            i = 20;
            iv = *(buf+1)<<16 | *(buf+2)<<8 | *(buf+3);
            iv = extend_signed(iv, 24);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",instd[i], (ut32)a->pc+iv, iv);
            break;
        case 5: //j
            i = 19;
            iv = *(buf+1)<<16 | *(buf+2)<<8 | *(buf+3);
            iv = extend_signed(iv, 24);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",instd[i], (ut32)a->pc+iv, iv);
            break;
        case 6: //bf
            i = 3;
            iv = *(buf+1)<<16 | *(buf+2)<<8 | *(buf+3);
            iv = extend_signed(iv, 24);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",instd[i], (ut32)a->pc+iv, iv);
            break;
        case 7: //bnf
            i = 18;
            iv = *(buf+1)<<16 | *(buf+2)<<8 | *(buf+3);
            iv = extend_signed(iv, 24);
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%x(%+d)",instd[i], (ut32)a->pc+iv, iv);
            break;
    }
    if ((opc&0xc) == 0x8) { //addi
        i = 0;
        ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[25:21]
        rb = (*(buf+1))&0x1F; //[20:16]
        iv = *(buf+2)<<8 | *(buf+3);
        iv = extend_signed(iv, 16);
        snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%-11s%s,%s,%+d",instd[i], reg[ia], reg[rb], iv);
    }

    op->size = 4;
}

void disas_e(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "non-support";
    strcpy(op->buf_asm, str);
    op->size = 0;
}

void disas_f(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "non-support";
    strcpy(op->buf_asm, str);
    op->size = 0;
}

void (*ba22_inst_decode[16])(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len) =
{
    disas_0,
    disas_1,
    disas_2,
    disas_3,
    disas_4,
    disas_5,
    disas_6,
    disas_7,
    disas_8,
    disas_9,
    disas_a,
    disas_b,
    disas_c,
    disas_d,
    disas_e,
    disas_f,
};

int _ba_disas (RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len) {
    int len_code = (*buf)>>4;

    ba22_inst_decode[len_code](a, op, buf, len);

    //printf("a=%x buf=%x totallen=%d\n", a, buf, len);
    return op->size;
}
