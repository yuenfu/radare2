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
char *inst2 [] =
{
    "bn.lbz",
    "bn.ld",
    "bn.lhz",
    "bn.lws",
    "bn.lwz",
    "bn.sb",
    "bn.sd",
    "bn.sh",
    "bn.sw",
};

char *inst3 [] =
{
    "bn.addi",
    "bn.andi",
    "bn.bitrev",
    "bn.clz",
    "bn.extbs",
    "bn.extbz",
    "bn.exths",
    "bn.exthz",
    "bn.ff1",
    "bn.mfspr",
    "bn.mtspr",
    "bn.ori",
    "bn.sfeq",
    "bn.sfeqi",
    "bn.sfges",
    "bn.sfgesi",
    "bn.sfgeu",
    "bn.sfgeui",
    "bn.sfgts",
    "bn.sfgtsi",
    "bn.sfgtu",
    "bn.sfgtui",
    "bn.sflesi",
    "bn.sfleui",
    "bn.sfltsi",
    "bn.sfltui",
    "bn.sfne",
    "bn.sfnei",
    "bn.swab",
};

char *inst4 [] =
{
    "bn.bc",
    "bn.beqi",
    "bn.bf",
    "bn.bgesi",
    "bn.bgtsi",
    "bn.blesi",
    "bn.bltsi",
    "bn.bnc",
    "bn.bnei",
    "bn.bnf",
    "bn.bno",
    "bn.bo",
    "bn.entri",
    "bn.j",
    "bn.jal",
    "bn.jalr",
    "bn.jr",
    "bn.reti",
    "bn.return",
    "bn.rtnei",
};

char *inst5 [] =
{
    "bn.lwza",
    "bn.mlwz",
};

char *inst6 [] =
{
    "bn.aadd",
    "bn.add",
    "bn.addc",
    "bn.and",
    "bn.cmov",
    "bn.cmpxchg",
    "bn.div",
    "bn.divu",
    "bn.flb",
    "bn.nand",
    "bn.or",
    "bn.ror",
    "bn.rori",
    "bn.sll",
    "bn.slli",
    "bn.sra",
    "bn.srai",
    "bn.srl",
    "bn.srli",
    "bn.sub",
    "bn.subb",
    "bn.xor",
};

char *inst7 [] =
{
    "bn.adds",
    "bn.subs",
};

char *inst8 [] =
{
    "bw.lbz",
    "bw.ld",
    "bw.lhz",
    "bw.lws",
    "bw.lwz",
    "bw.sb",
    "bw.sd",
    "bw.sh",
    "bw.sw",
};

char *inst9 [] =
{
    "bw.addi",
    "bw.andi",
    "bw.ori",
    "bw.sfeqi",
    "bw.sfgesi",
    "bw.sfgeui",
    "bw.sfgtsi",
    "bw.sfgtui",
    "bw.sflesi",
    "bw.sfleui",
    "bw.sfltsi",
    "bw.sfltui",
    "bw.sfnei",
};

char *insta [] =
{
    "bw.addci",
    "bw.beq",
    "bw.beqi",
    "bw.bf",
    "bw.bges",
    "bw.bgesi",
    "bw.bgeu",
    "bw.bgeui",
    "bw.bgts",
    "bw.bgtsi",
    "bw.bgtu",
    "bw.bgtui",
    "bw.blesi",
    "bw.bleui",
    "bw.bltsi",
    "bw.bltui",
    "bw.bne",
    "bw.bnei",
    "bw.bnf",
    "bw.j",
    "bw.ja",
    "bw.jal",
    "bw.jma",
    "bw.jmal",
    "bw.lma",
    "bw.mfspr",
    "bw.mtspr",
    "bw.sma",
    "bw.xori",
};

char *instc [] =
{
    "bg.lbz",
    "bg.ld",
    "bg.lhz",
    "bg.lws",
    "bg.lwz",
    "bg.sb",
    "bg.sd",
    "bg.sh",
    "bg.sw",
};

char *instd [] =
{
    "bg.addi",
    "bg.beq",
    "bg.beqi",
    "bg.bf",
    "bg.bges",
    "bg.bgesi",
    "bg.bgeu",
    "bg.bgeui",
    "bg.bgts",
    "bg.bgtsi",
    "bg.bgtu",
    "bg.bgtui",
    "bg.blesi",
    "bg.bleui",
    "bg.bltsi",
    "bg.bltui",
    "bg.bne",
    "bg.bnei",
    "bg.bnf",
    "bg.j",
    "bg.jal",
};

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

char *inst0 [] =
{
    "bt.add",
    "bt.addi",
    "bt.di",
    "bt.ei",
    "bt.j",
    "bt.mov",
    "bt.movi",
    "bt.nop",
    "bt.rfe",
    "bt.sys",
    "bt.trap",
};

void disas_0(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    int i;
    ut8 opc = (*buf)>>2;
    ut8 ra = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5;
    ut8 rb = (*(buf+1))&0x1F;
    ut32 iv;

    switch (opc) {
        case 3:
            iv = ((*buf)&0x3)<<8 | *(buf+1);
            iv = extend_signed(iv, 10);
            i = 4; //j
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s %x(%+d)", inst0[i], (ut32)a->pc+iv, iv);
            break;
        case 2:
            i = 0; //add
            snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s %s,%s,%s",inst0[i], reg[ra], reg[ra], reg[rb]);
            break;
        case 1:
            if (ra ==0 && rb==2) {
                i = 2; //di
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
            }
            else if (ra ==0 && rb==1) {
                i = 3; //ei
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
            }
            else if (ra ==0 && rb==0) {
                i = 8; //rfe
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
            }
            else if (ra ==0 && rb==3) {
                i = 9; //sys
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
            }
            else {
                i = 5; //mov
                snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s %s,%s",inst0[i], reg[ra], reg[rb]);
            }
            break;
        case 0:
            if (rb&0x10) {
                if (ra==0) {
                    i = 7; //nop
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
                }
                else {
                    i = 1; //addi
                    iv = extend_signed(rb, 4);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s %s,%s,%+d",inst0[i], reg[ra], reg[ra], iv);
                }
            }
            else {
                if (ra==0) {
                    i = 10; //trap
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s",inst0[i]);
                }
                else {
                    i = 6; //movi
                    iv = extend_signed(rb, 4);
                    snprintf(op->buf_asm, R_ASM_BUFSIZE + 1, "%s %s,%+d",inst0[i], reg[ra], iv);
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

void disas_2(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 3;
}

void disas_3(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 3;
}

void disas_4(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 3;
}

void disas_5(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 3;
}

void disas_6(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 3;
}

void disas_7(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 3;
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

void disas_a(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
    op->size = 6;
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

void disas_d(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
    char str[] = "pending";
    strcpy(op->buf_asm, str);
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
