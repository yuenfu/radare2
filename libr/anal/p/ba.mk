OBJ_BA=anal_ba.o

STATIC_OBJ+=${OBJ_BA}
TARGET_BA=anal_ba.${EXT_SO}

ALL_TARGETS+=${TARGET_BA}

${TARGET_BA}: ${OBJ_BA}
	${CC} $(call libname,anal_ba) ${LDFLAGS} \
		${CFLAGS} -o anal_ba.${EXT_SO} ${OBJ_BA}
