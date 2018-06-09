#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <ba_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return  _ba_disas (a, op, buf, len);
}

RAsmPlugin r_asm_plugin_ba = {
	.name = "ba",
	.arch = "ba",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BI,
	.desc = "Beyond Achitecture plugin",
	.disassemble = &disassemble,
	.license = "PD",
	.cpus =
		"ba22-de" // First one is default
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ba,
	.version = R2_VERSION
};
#endif
