OBJ_BA=asm_ba.o
OBJ_BA+=../arch/ba/ba_disas.o
CFLAGS+=-I./arch/ba/

STATIC_OBJ+=${OBJ_BA}
TARGET_BA=asm_ba.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_BA}

${TARGET_BA}: ${OBJ_BA}
	${CC} $(call libname,asm_ba) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_BA} ${OBJ_BA}
endif
