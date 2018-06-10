/* radare - LGPL - Copyright 2013-2018 - pancake, dkreuter, astuder  */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int set_reg_profile(RAnal *anal) {
#if 0
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"gpr	r0	.8	0	0\n"
		"gpr	r1	.8	1	0\n"
		"gpr	r2	.8	2	0\n"
		"gpr	r3	.8	3	0\n"
		"gpr	r4	.8	4	0\n"
		"gpr	r5	.8	5	0\n"
		"gpr	r6	.8	6	0\n"
		"gpr	r7	.8	7	0\n"
		"gpr	a	.8	8	0\n"
		"gpr	b	.8	9	0\n"
		"gpr	dptr	.16	10	0\n"
		"gpr	dpl	.8	10	0\n"
		"gpr	dph	.8	11	0\n"
		"gpr	psw	.8	12	0\n"
		"gpr	p	.1	.96	0\n"
		"gpr	ov	.1	.98	0\n"
		"gpr	ac	.1	.102	0\n"
		"gpr	c	.1	.103	0\n"
		"gpr	sp	.8	13	0\n"
		"gpr	pc	.16	15	0\n"
// ---------------------------------------------------
// ba memory emulation control registers
// These registers map ba memory classes to r2's
// linear address space. Registers contain base addr
// in r2 memory space representing the memory class.
// Offsets are initialized based on asm.cpu, but can
// be updated with ar command.
//
// _code
//		program memory (CODE)
// _idata
//		internal data memory (IDATA, IRAM)
// _sfr
//		special function registers (SFR)
// _xdata
//		external data memory (XDATA, XRAM)
// _pdata
//		page accessed by movx @ri op (PDATA, XREG)
//		r2 addr = (_pdata & 0xff) << 8 + x_data
//		if 0xffffffnn, addr = ([SFRnn] << 8) + _xdata (TODO)
		"gpr	_code	.32	20 0\n"
		"gpr	_idata	.32 24 0\n"
		"gpr	_sfr	.32	28 0\n"
		"gpr	_xdata	.32 32 0\n"
		"gpr	_pdata	.32	36 0\n";

	int retval = r_reg_set_profile_string (anal->reg, p);
	if (retval) {
		// reset emulation control registers based on cpu
		set_cpu_model (anal, true);
	}

	return retval;
#endif
	return 0;
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

void anal_0(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    ut8 opc = (*buf)>>2;
    ut8 ra = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5;
    ut8 rb = (*(buf+1))&0x1F;
    ut32 iv;

    op->size = 2;
    switch (opc) {
        case 3: //bt.j
            iv = ((*buf)&0x3)<<8 | *(buf+1);
            iv = extend_signed(iv, 10);
            op->type = R_ANAL_OP_TYPE_JMP;
            op->jump = addr + (st32)iv;
            break;
        case 2: //bt.add
            op->type = R_ANAL_OP_TYPE_ADD;
            break;
        case 1: //di,ei,rfe,sys,mov
#if 0
            if (ra ==0 && rb==2) { //di
            }
            else if (ra ==0 && rb==1) { //ei
            }
            else if (ra ==0 && rb==0) { //rfe
            }
            else
#endif
            if (ra ==0 && rb==3) { //sys
                op->type = R_ANAL_OP_TYPE_SWI;
            }
            else { //mov
                op->type = R_ANAL_OP_TYPE_NOP;
            }
            break;
        case 0: //nop,addi,trap,movi
            if (rb&0x10) {
                if (ra==0) { //nop
                    op->type = R_ANAL_OP_TYPE_NOP;
                }
                else { //addi
                    op->type = R_ANAL_OP_TYPE_ADD;
                }
            }
            else {
                if (ra==0) { //trap
                    op->type = R_ANAL_OP_TYPE_TRAP;
                    op->eob = true; //? not sure
                }
                else { //movi
                    op->type = R_ANAL_OP_TYPE_MOV;
                }
            }
            break;
        default:
            puts("exception in anal_0\n");
            while(1);
            break;
    }
}

void anal_1(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 0;
}

void anal_2(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 3;
}

void anal_3(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 3;
}

void anal_4(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 3;
}

void anal_5(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 3;
}

void anal_6(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 3;
}

void anal_7(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 3;
}

void anal_8(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 6;
}

void anal_9(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 6;
}

void anal_a(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 6;
}

void anal_b(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 0;
}

void anal_c(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 4;
}

void anal_d(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 4;
}

void anal_e(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 0;
}

void anal_f(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 0;
}

void (*ba22_inst_analysis[16])(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) =
{
    anal_0,
    anal_1,
    anal_2,
    anal_3,
    anal_4,
    anal_5,
    anal_6,
    anal_7,
    anal_8,
    anal_9,
    anal_a,
    anal_b,
    anal_c,
    anal_d,
    anal_e,
    anal_f,
};

static int ba_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
    int len_code = (*buf)>>4;

    ba22_inst_analysis[len_code](anal, op, addr, buf, len);

    //printf("anal=%x op=%x\n", (void*)anal, (void *)op);
    //printf("addr=%x buf=%x totallen=%d\n", (ut32)addr, (void*)buf, len);

	return op->size;
}

RAnalPlugin r_anal_plugin_ba = {
	.name = "ba",
	.arch = "ba",
//	.esil = true,
	.bits = 32,
	.desc = "ba CPU code analysis plugin",
	.license = "PD",
	.op = &ba_op,
	.set_reg_profile = &set_reg_profile,
//	.esil_init = esil_ba_init,
//	.esil_fini = esil_ba_fini
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ba,
	.version = R2_VERSION
};
#endif
