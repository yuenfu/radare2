/* radare - LGPL - Copyright 2015-2017 - pancake, condret, riq, qnix, astuder */

#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "ba_ops.h"
#include "ba_disas.h"

char *inst0 [5][8] =
{
"bt.movi",
"bt.addi",
"bt.mov",
"bt.add",
"bt.j",
}


void disas0(RAsmOp *op)
{
    op->size = 2;
    strcpy(op->buf_asm, str);
}

void disas1(RAsmOp *op)
{
    op->size = 0;
}

void disas2(RAsmOp *op)
{
    op->size = 3;
}

void disas3(RAsmOp *op)
{
    op->size = 3;
}

void disas4(RAsmOp *op)
{
    op->size = 3;
}

void disas5(RAsmOp *op)
{
    op->size = 3;
}

void disas6(RAsmOp *op)
{
    op->size = 3;
}

void disas7(RAsmOp *op)
{
    op->size = 3;
}

void disas8(RAsmOp *op)
{
    op->size = 6;
}

void disas9(RAsmOp *op)
{
    op->size = 6;
}

void disasa(RAsmOp *op)
{
    op->size = 6;
}

void disasb(RAsmOp *op)
{
    op->size = 6;
}

void disasc(RAsmOp *op)
{
    op->size = 4;
}

void disasd(RAsmOp *op)
{
    op->size = 4;
}

void disase(RAsmOp *op)
{
    op->size = 6;
}

void disasf(RAsmOp *op)
{
    op->size = 3;
}

void (*ba22_inst_decode[16])(RAsmOp *op) = 
{
disas0,
disas1,
disas2,
disas3,
disas4,
disas5,
disas6,
disas7,
disas8,
disas9,
disasa,
disasb,
disasc,
disasd,
disase,
disasf,
};

int _ba_disas (RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len) {
    int len_code = (*buf)>>4;

    ba22_inst_decode[len_code](op);

    printf("buf=%x len=%d\n", buf, len);
    return op->size;
}
