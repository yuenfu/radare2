/* radare - LGPL - Copyright 2013-2018 - pancake, dkreuter, astuder  */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int set_reg_profile(RAnal *anal) {
#if 1
	const char *p =
//		"=PC	pc\n"
		"=LR	r9\n"
		"=SP	r1\n"
		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	20	0\n"
		"gpr	r6	.32	24	0\n"
		"gpr	r7	.32	28	0\n"
		"gpr	r8	.32	32	0\n"
		"gpr	r9	.32	36	0\n"
		"gpr	r10	.32	40	0\n"
		"gpr	r11	.32	44	0\n"
		"gpr	r12	.32	48	0\n"
		"gpr	r13	.32	52	0\n"
		"gpr	r14	.32	56	0\n"
		"gpr	r15	.32	60	0\n"
		"gpr	r16	.32	64	0\n"
		"gpr	r17	.32	68	0\n"
		"gpr	r18	.32	72	0\n"
		"gpr	r19	.32	76	0\n"
		"gpr	r20	.32	80	0\n"
		"gpr	r21	.32	84	0\n"
		"gpr	r22	.32	88	0\n"
		"gpr	r23	.32	92	0\n"
		"gpr	r24	.32	96	0\n"
		"gpr	r25	.32	100	0\n"
		"gpr	r26	.32	104	0\n"
		"gpr	r27	.32	108	0\n"
		"gpr	r28	.32	112	0\n"
		"gpr	r29	.32	116	0\n"
		"gpr	r30	.32	120	0\n"
		"gpr	r31	.32	124	0\n"
		;

	int retval = r_reg_set_profile_string (anal->reg, p);
	//if (retval) {
	//	// reset emulation control registers based on cpu
	//	set_cpu_model (anal, true);
	//}

	return retval;
#else
	return 0;
#endif
}

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

void anal_0(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    ut8 opc = ((*buf)&0xF)>>2;
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
                }
                else { //movi
                    op->type = R_ANAL_OP_TYPE_MOV;
                }
            }
            break;
    }
}

void anal_1(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 0;
}

void anal_2(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    ut8 opc = ((*buf)&0xF)>>2;
    ut8 ra = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5;
    ut8 rb = (*(buf+1))&0x1F;
    ut32 iv = *(buf+2);

    op->size = 3;
    switch (opc) {
        case 0: //sb
            op->type = R_ANAL_OP_TYPE_STORE;
            iv = extend_unsigned(iv, 8);
            break;
        case 1: //lbz
            op->type = R_ANAL_OP_TYPE_LOAD;
            iv = extend_unsigned(iv, 8);
            break;
        case 2:
            if (iv&0x80) { //lhz
                op->type = R_ANAL_OP_TYPE_LOAD;
                iv = extend_unsigned(iv, 7);
                iv <<= 1;
            }
            else { //sh
                op->type = R_ANAL_OP_TYPE_STORE;
                iv = extend_unsigned(iv, 7);
                iv <<= 1;
            }
            break;
        case 3:
            switch (iv>>6) {
                case 0: //sw
                    op->type = R_ANAL_OP_TYPE_STORE;
                    iv = extend_unsigned(iv, 6);
                    iv <<= 2;
                    break;
                case 1: //lwz
                    op->type = R_ANAL_OP_TYPE_LOAD;
                    iv = extend_unsigned(iv, 6);
                    iv <<= 2;
                    break;
                case 2: //lws
                    op->type = R_ANAL_OP_TYPE_LOAD;
                    iv = extend_signed(iv, 6);
                    iv <<= 2;
                    break;
                case 3:
                    if (iv&0x20) { //ld
                        op->type = R_ANAL_OP_TYPE_LOAD;
                        iv = extend_unsigned(iv, 5);
                        iv <<= 3;
                    }
                    else { //sd
                        op->type = R_ANAL_OP_TYPE_STORE;
                        iv = extend_unsigned(iv, 5);
                        iv <<= 3;
                    }
                    break;
            }
            break;
    }
}

void anal_3(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    op->size = 3;
}

void anal_4(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
    ut8 opc = ((*buf)&0xF);
    ut8 ia = ((*(buf+1))&0xE0)>>5;
    ut8 rb = (*(buf+1))&0x1F;
    ut32 iv = *(buf+2);

    op->size = 3;
    switch (opc) {
        case 0: //beqi
            iv = extend_signed(iv, 8);
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (st32)iv;
            op->fail = addr + op->size;
            break;
        case 1: //bnei
            iv = extend_signed(iv, 8);
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (st32)iv;
            op->fail = addr + op->size;
            break;
        case 2: //bgesi
            iv = extend_signed(iv, 8);
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (st32)iv;
            op->fail = addr + op->size;
            break;
        case 3: //bgtsi
            iv = extend_signed(iv, 8);
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (st32)iv;
            op->fail = addr + op->size;
            break;
        case 4: //blesi
            iv = extend_signed(iv, 8);
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (st32)iv;
            op->fail = addr + op->size;
            break;
        case 5: //bltsi
            iv = extend_signed(iv, 8);
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (st32)iv;
            op->fail = addr + op->size;
            break;
        case 6: //j
            iv |= (*(buf+1)<<8);
            iv = extend_signed(iv, 16);
            op->type = R_ANAL_OP_TYPE_JMP;
            op->jump = addr + (st32)iv;
            break;
        case 7:
            switch (*(buf+1)>>4) {
                case 2: //bf
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 3: //bnf
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 4: //bo
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 5: //bno
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 6: //bc
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 7: //bnc
                    iv |= ((*(buf+1)&0xF)<<8);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 10: //entri
                    ia = rb & 0xF;
                    ia = extend_unsigned(ia, 4);
                    iv = extend_unsigned(iv, 8);
                    op->type = R_ANAL_OP_TYPE_PUSH;
                    break;
                case 11: //reti
                    ia = rb & 0xF;
                    ia = extend_unsigned(ia, 4);
                    iv = extend_unsigned(iv, 8);
                    op->type = R_ANAL_OP_TYPE_RET | R_ANAL_OP_TYPE_POP;
                    break;
                case 12: //rtnei
                    ia = rb & 0xF;
                    ia = extend_unsigned(ia, 4);
                    iv = extend_unsigned(iv, 8);
                    op->type = R_ANAL_OP_TYPE_POP;
                    break;
                case 13:
                    switch (*(buf+1)&0x3) {
                        case 0: //return
                            op->type = R_ANAL_OP_TYPE_RET;
                            break;
                        case 1: //jalr
                            op->type = R_ANAL_OP_TYPE_RCALL;
                            break;
                        case 2: //jr
                            iv >>= 3;
                            if (iv == 9)
                                op->type = R_ANAL_OP_TYPE_RET;
                            else
                                op->type = R_ANAL_OP_TYPE_RJMP;
                            break;
                    }
                    break;
            }
            break;
    }
    if ((opc&0xc) == 0x8) { //jal
        iv |= ((*(buf+1))<<8);
        iv |= ((*(buf+0)&0x3)<<16);
        iv = extend_signed(iv, 18);
        op->type = R_ANAL_OP_TYPE_CALL;
        op->jump = addr + (st32)iv;
    }
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
    ut8 opc = ((*buf)&0xC); //[43:42]
    ut8 ia = ((*(buf+1))&0x3E)>>1; //[37:33]
    ut8 rb = ((*(buf+1))&0x1)<<4 | ((*(buf+2))&0xF0)>>4; //[32:28]
    ut32 iv = ((*(buf+2))&0xF)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5); //[27:0]

    op->size = 6;
    switch (opc) {
        case 0:
            switch (((*buf)&0x3)<<2 | ((*(buf+1))&0xC0)>>6) { //[41:38]
                case 0: //beqi
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 1: //bnei
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 2: //bgesi
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 3: //bgtsi
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 4: //blesi
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 5: //bltsi
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 6: //bgeui
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 7: //bgtui
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 8: //bleui
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 9: //bltui
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 10: //beq
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 11: //bne
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 12: //bges
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 13: //bgts
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 14: //bgeu
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 15: //bgtu
                    iv = extend_signed(iv, 28);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
            }
            break;
        case 1:
            switch (((*buf)&0x3)<<2 | ((*(buf+1))&0xC0)>>6) { //[41:38]
                case 0: //jal
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    op->type = R_ANAL_OP_TYPE_CALL;
                    op->jump = addr + (st32)iv;
                    break;
                case 1: //j
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    op->type = R_ANAL_OP_TYPE_JMP;
                    op->jump = addr + (st32)iv;
                    break;
                case 2: //bf
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 3: //bnf
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 4: //ja
                    iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                    iv = extend_signed(iv, 32);
                    op->type = R_ANAL_OP_TYPE_JMP;
                    op->jump = (st32)iv;
                    break;
                case 5:
                    if (!(*(buf+1))&0x1) { //jma
                        iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                        iv = extend_signed(iv, 32);
                        op->type = R_ANAL_OP_TYPE_JMP;
                        op->jump = addr + (st32)iv;
                    }
                    else { //jmal
                        iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                        iv = extend_signed(iv, 32);
                        op->type = R_ANAL_OP_TYPE_CALL;
                        op->jump = addr + (st32)iv;
                    }
                    break;
                case 6:
                    if (!(*(buf+1))&0x1) { //lma
                        iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                        iv = extend_signed(iv, 32);
                    }
                    else { //sma
                        iv = *(buf+2)<<24 | *(buf+3)<<16 | *(buf+4)<<8 | *(buf+5);
                        iv = extend_signed(iv, 32);
                    }
                    break;
            }
            break;
        case 2:
            switch ((*(buf+5))&0x3) { //[2:0]
                case 0: //mfspr
                    ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[41:37]
                    rb = (*(buf+1))&0x1F; //[36:32]
                    iv = *(buf+2)<<16 | *(buf+3)<<8 | *(buf+4); //[31:8]
                    iv = extend_unsigned(iv, 24);
                    break;
                case 1: //mtspr
                    ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[41:37]
                    rb = (*(buf+1))&0x1F; //[36:32]
                    iv = *(buf+2)<<16 | *(buf+3)<<8 | *(buf+4); //[31:8]
                    iv = extend_unsigned(iv, 24);
                    break;
                case 2: //addci
                    ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[41:37]
                    rb = (*(buf+1))&0x1F; //[36:32]
                    iv = *(buf+2)<<16 | *(buf+3)<<8 | *(buf+4); //[31:8]
                    iv = extend_signed(iv, 24);
                    break;
                case 6: //xori
                    ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[41:37]
                    rb = (*(buf+1))&0x1F; //[36:32]
                    iv = *(buf+2)<<16 | *(buf+3)<<8 | *(buf+4); //[31:8]
                    iv = extend_signed(iv, 24);
                    break;
            }
            break;
    }
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
    ut8 opc = ((*buf)&0xF); //[27:24]
    ut8 ia = ((*(buf+1))&0x3E)>>1; //[21:17]
    ut8 rb = ((*(buf+1))&0x1)<<4 | ((*(buf+2))&0xF0)>>4; //[16:12]
    ut32 iv = ((*(buf+2))&0xF)<<8 | *(buf+3); //[11:0]

    op->size = 4;
    switch (opc) {
        case 0:
            switch (((*(buf+1))&0xC0)>>6) {
                case 0: //beqi
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 1: //bnei
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 2: //bgesi
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 3: //bgtsi
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
            }
            break;
        case 1:
            switch (((*(buf+1))&0xC0)>>6) {
                case 0: //blesi
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 1: //bltsi
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 2: //bgeui
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 3: //bgtui
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
            }
            break;
        case 2:
            switch (((*(buf+1))&0xC0)>>6) {
                case 0: //bleui
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 1: //bltui
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 2: //beq
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 3: //bne
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
            }
            break;
        case 3:
            switch (((*(buf+1))&0xC0)>>6) {
                case 0: //bges
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 1: //bgts
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 2: //bgeu
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
                case 3: //bgtu
                    ia = extend_signed(ia, 5);
                    iv = extend_signed(iv, 12);
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->jump = addr + (st32)iv;
                    op->fail = addr + op->size;
                    break;
            }
            break;
        case 4: //jal
            iv = *(buf+1)<<16 | *(buf+2)<<8 | *(buf+3);
            iv = extend_signed(iv, 24);
            op->type = R_ANAL_OP_TYPE_CALL;
            op->jump = addr + (st32)iv;
            break;
        case 5: //j
            iv = *(buf+1)<<16 | *(buf+2)<<8 | *(buf+3);
            iv = extend_signed(iv, 24);
            op->type = R_ANAL_OP_TYPE_JMP;
            op->jump = addr + (st32)iv;
            break;
        case 6: //bf
            iv = *(buf+1)<<16 | *(buf+2)<<8 | *(buf+3);
            iv = extend_signed(iv, 24);
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (st32)iv;
            op->fail = addr + op->size;
            break;
        case 7: //bnf
            iv = *(buf+1)<<16 | *(buf+2)<<8 | *(buf+3);
            iv = extend_signed(iv, 24);
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (st32)iv;
            op->fail = addr + op->size;
            break;
    }
    if ((opc&0xc) == 0x8) { //addi
        ia = ((*buf)&0x3)<<3 | ((*(buf+1))&0xE0)>>5; //[25:21]
        rb = (*(buf+1))&0x1F; //[20:16]
        iv = *(buf+2)<<8 | *(buf+3);
        iv = extend_signed(iv, 16);
        op->type = R_ANAL_OP_TYPE_ADD;
    }
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
	.esil = false,//true,
	.bits = 32,
	.desc = "ba CPU code analysis plugin",
	.license = "PD",
	.op = &ba_op,
	.set_reg_profile = &set_reg_profile,
	.esil_init = NULL,//esil_ba_init,
	.esil_fini = NULL//esil_ba_fini
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ba,
	.version = R2_VERSION
};
#endif
