/* radare - LGPL - Copyright 2015-2017 - pancake, condret, riq, qnix, astuder */

#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "ba_ops.h"
#include "ba_disas.h"

int _ba_disas (ut64 pc, RAsmOp *op, const ut8 *buf, ut64 len) {
    char str[] = "nop";
    printf("buf=%s len=%d\n", buf, len);
    strcpy(op->buf_asm, str);
    strcpy(op->buf, str);
    op->size = 2;
}
