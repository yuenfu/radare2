/* radare - LGPL - Copyright 2013-2018 - pancake, oddcoder, sivaramaaa */

#include <r_util.h>

R_API int r_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val) {
	const char *kind;
	char var[128];
	sprintf (var, "link.%08"PFMT64x, at);
	kind = sdb_const_get (TDB, var, NULL);
	if (kind) {
		const char *p = sdb_const_get (TDB, kind, NULL);
		if (p) {
			snprintf (var, sizeof (var), "%s.%s.%s", p, kind, field);
			int off = sdb_array_get_num (TDB, var, 1, NULL);
			//int siz = sdb_array_get_num (DB, var, 2, NULL);
			eprintf ("wv 0x%08"PFMT64x" @ 0x%08"PFMT64x, val, at+off);
			return true;
		}
		eprintf ("Invalid kind of type\n");
	}
	return false;
}

R_API int r_type_kind(Sdb *TDB, const char *name) {
	if (!name) {
		return -1;
	}
	const char *type = sdb_const_get (TDB, name, 0);
	if (!type) {
		return -1;
	}
	if (!strcmp (type, "enum")) {
		return R_TYPE_ENUM;
	}
	if (!strcmp (type, "struct")) {
		return R_TYPE_STRUCT;
	}
	if (!strcmp (type, "union")) {
		return R_TYPE_UNION;
	}
	if (!strcmp (type, "type")) {
		return R_TYPE_BASIC;
	}
	return -1;
}

R_API RList* r_type_get_enum (Sdb *TDB, const char *name) {
	char *p, *val, var[130], var2[130];
	int n;

	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	RList *res = r_list_new ();
	snprintf (var, sizeof (var), "enum.%s", name);
	for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
		RTypeEnum *member = R_NEW0 (RTypeEnum);
		snprintf (var2, sizeof (var2), "%s.%s", var, p);
		val = sdb_array_get (TDB, var2, 0, NULL);
		member->name = p;
		member->val = val;
		r_list_append (res, member);
	}
	return res;
}

R_API char *r_type_enum_member(Sdb *TDB, const char *name, const char *member, ut64 val) {
	const char *q;
	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	if (member) {
		q = sdb_fmt ("enum.%s.%s", name, member);
	} else {
		q = sdb_fmt ("enum.%s.0x%"PFMT64x, name, val);
	}
	return sdb_get (TDB, q, 0);
}

R_API char *r_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val) {
	char *q, *ret = NULL;
	const char *res;
	int i;

	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	bool isFirst = true;
	ret = r_str_appendf (ret, "0x%08"PFMT64x" : ", val);
	for (i = 0; i < 32; i++) {
		if (!(val & (1 << i))) {
			continue;
		}
		q = sdb_fmt ("enum.%s.0x%x", name, (1<<i));
                res = sdb_const_get (TDB, q, 0);
                if (isFirst) {
			isFirst = false;
                } else {
			ret = r_str_append (ret, " | ");
                }
                if (res) {
			ret = r_str_append (ret, res);
                } else {
			ret = r_str_appendf (ret, "0x%x", (1<<i));
                }
	}
	return ret;
}

R_API int r_type_get_bitsize(Sdb *TDB, const char *type) {
	char *query;
	/* Filter out the structure keyword if type looks like "struct mystruc" */
	const char *tmptype;
	if (!strncmp (type, "struct ", 7)) {
		tmptype = type + 7;
	} else {
		tmptype = type;
	}
	if ((strstr (type, "*(") || strstr (type, " *")) &&
			strncmp (type, "char *", 7)) {
		return 32;
	}
	const char *t = sdb_const_get (TDB, tmptype, 0);
	if (!t) {
		if (!strncmp (tmptype, "enum ", 5)) {
			//XXX: Need a proper way to determine size of enum
			return 32;
		}
		return 0;
	}
	if (!strcmp (t, "type")){
		query = sdb_fmt ("type.%s.size", tmptype);
		return sdb_num_get (TDB, query, 0); // returns size in bits
	}
	if (!strcmp (t, "struct")) {
		query = sdb_fmt ("struct.%s", tmptype);
		char *members = sdb_get (TDB, query, 0);
		char *next, *ptr = members;
		int ret = 0;
		if (members) {
			do {
				char *name = sdb_anext (ptr, &next);
				if (!name) {
					break;
				}
				query = sdb_fmt ("struct.%s.%s", tmptype, name);
				char *subtype = sdb_get (TDB, query, 0);
				if (!subtype) {
					break;
				}
				char *tmp = strchr (subtype, ',');
				if (tmp) {
					*tmp++ = 0;
					tmp = strchr (tmp, ',');
					if (tmp) {
						*tmp++ = 0;
					}
					int elements = r_num_math (NULL, tmp);
					if (elements == 0) {
						elements = 1;
					}
					ret += r_type_get_bitsize (TDB, subtype) * elements;
				}
				free (subtype);
				ptr = next;
			} while (next);
			free (members);
		}
		return ret;
	}
	return 0;
}

R_API char *r_type_get_struct_memb(Sdb *TDB, const char *type, int offset) {
	int i, typesize = 0;
	char *res = NULL;

	if (offset < 0) {
		return NULL;
	}
	char* query = sdb_fmt ("struct.%s", type);
	char *members = sdb_get (TDB, query, 0);
	if (!members) {
		//eprintf ("%s is not a struct\n", type);
		return NULL;
	}
	int nargs = r_str_split (members, ',');
	for (i = 0; i < nargs ; i++) {
		const char *name = r_str_word_get0 (members, i);
		if (!name) {
			break;
		}
		query = sdb_fmt ("struct.%s.%s", type, name);
		char *subtype = sdb_get (TDB, query, 0);
		if (!subtype) {
			break;
		}
		int len = r_str_split (subtype, ',');
		if (len < 3) {
			free (subtype);
			break;
		}
		int val = r_num_math (NULL, r_str_word_get0 (subtype, len - 1));
		int arrsz = val ? val : 1;
		if ((typesize / 8) == offset) {
			res = r_str_newf ("%s.%s", type, name);
			free (subtype);
			break;
		}
		typesize += r_type_get_bitsize (TDB, subtype) * arrsz;
		free (subtype);
	}
	free (members);
	return res;
}

R_API RList* r_type_get_by_offset(Sdb *TDB, ut64 offset) {
	RList *offtypes = r_list_new ();
	SdbList *ls = sdb_foreach_list (TDB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		// TODO: Add unions support
		if (!strncmp (kv->value, "struct", 6) && strncmp (kv->key, "struct.", 7)) {
			char *res = r_type_get_struct_memb (TDB, kv->key, offset);
			if (res) {
				r_list_append (offtypes, res);
			}
		}
	}
	ls_free (ls);
	return offtypes;
}

R_API char *r_type_link_at (Sdb *TDB, ut64 addr) {
	char* res = NULL;

	if (addr == UT64_MAX) {
		return NULL;
	}
	char* query = sdb_fmt ("link.%08"PFMT64x, addr);
	res = sdb_get (TDB, query, 0);
	if (!res) { // resolve struct memb if possible for given addr
		SdbKv *kv;
		SdbListIter *sdb_iter;
		SdbList *sdb_list = sdb_foreach_list (TDB, true);
		ls_foreach (sdb_list, sdb_iter, kv) {
			if (strncmp (kv->key, "link.", strlen ("link."))) {
				continue;
			}
			const char *linkptr = sdb_fmt ("0x%s", kv->key + strlen ("link."));
			ut64 baseaddr = r_num_math (NULL, linkptr);
			int delta = (addr > baseaddr)? addr - baseaddr: -1;
			res = r_type_get_struct_memb (TDB, kv->value, delta);
			if (res) {
				break;
			}
		}
		ls_free (sdb_list);
	}
	return res;
}

R_API int r_type_set_link(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get (TDB, type, 0)) {
		char *laddr = r_str_newf ("link.%08"PFMT64x, addr);
		sdb_set (TDB, laddr, type, 0);
		free (laddr);
		return true;
	}
	// eprintf ("Cannot find type\n");
	return false;
}

R_API int r_type_link_offset(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get (TDB, type, 0)) {
		char *laddr = r_str_newf ("offset.%08"PFMT64x, addr);
		sdb_set (TDB, laddr, type, 0);
		free (laddr);
		return true;
	}
	// eprintf ("Cannot find type\n");
	return false;
}

R_API int r_type_unlink(Sdb *TDB, ut64 addr) {
	char *laddr = sdb_fmt ("link.%08"PFMT64x, addr);
	sdb_unset (TDB, laddr, 0);
	return true;
}

static void filter_type(char *t) {
        for (;*t; t++) {
                if (*t == ' ') {
                        *t = '_';
                }
                // memmove (t, t+1, strlen (t));
        }
}

R_API char *r_type_format(Sdb *TDB, const char *t) {
	int n;
	char *p, var[130], var2[132];
	char *fmt = NULL;
	char *vars = NULL;
	const char *kind = sdb_const_get (TDB, t, NULL);
	if (!kind) {
		return NULL;
	}
	// only supports struct atm
	snprintf (var, sizeof (var), "%s.%s", kind, t);
	if (!strcmp (kind, "type")) {
		const char *fmt = sdb_const_get (TDB, var, NULL);
		if (fmt) {
			return strdup (fmt);
		}
	} else if (!strcmp (kind, "struct") || !strcmp (kind, "union")) {
		// assumes var list is sorted by offset.. should do more checks here
		for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
			char *type;
			char *struct_name;
			const char *tfmt = NULL;
			bool isStruct = false;
			bool isEnum = false;
			bool isfp = false;
			snprintf (var2, sizeof (var2), "%s.%s", var, p);
			type = sdb_array_get (TDB, var2, 0, NULL);
			int alen = sdb_array_size (TDB, var2);
			int elements = sdb_array_get_num (TDB, var2, alen - 1, NULL);
			if (type) {
				char var3[128] = {0};
				// Handle general pointers except for char *
				if ((strstr (type, "*(") || strstr (type, " *")) &&
						strncmp (type, "char *", 7)) {
					isfp = true;
				} else if (!strncmp (type, "struct ", 7)) {
					struct_name = type + 7;
					// TODO: iterate over all the struct fields, and format the format and vars
					snprintf (var3, sizeof (var3), "struct.%s", struct_name);
					tfmt = sdb_const_get (TDB, var3, NULL);
					isStruct = true;
				} else {
					// special case for char[]. Use char* format type without *
					if (!strncmp (type, "char", 5) && elements > 0) {
						tfmt = sdb_const_get (TDB, "type.char *", NULL);
						if (tfmt && *tfmt == '*') {
							tfmt++;
						}
					} else {
						if (!strncmp (type, "enum ", 5)) {
							snprintf (var3, sizeof (var3), "%s", type + 5);
							isEnum = true;
						} else {
							snprintf (var3, sizeof (var3), "type.%s", type);
						}
						tfmt = sdb_const_get (TDB, var3, NULL);
					}

				}
				if (isfp) {
					// consider function pointer as void * for printing
					fmt = r_str_append (fmt, "p");
					vars = r_str_append (vars, p);
					vars = r_str_append (vars, " ");
				} else if (tfmt) {
					filter_type (type);
					if (elements > 0) {
						fmt = r_str_appendf (fmt, "[%d]", elements);
					}
					if (isStruct) {
						fmt = r_str_append (fmt, "?");
						vars = r_str_appendf (vars, "(%s)%s", struct_name, p);
						vars = r_str_append (vars, " ");
					} else if (isEnum) {
						fmt = r_str_append (fmt, "E");
						vars = r_str_appendf (vars, "(%s)%s", type + 5, p);
						vars = r_str_append (vars, " ");
					} else {
						fmt = r_str_append (fmt, tfmt);
						vars = r_str_append (vars, p);
						vars = r_str_append (vars, " ");
					}
				} else {
					eprintf ("Cannot resolve type '%s'\n", var3);
				}
			}
			free (type);
			free (p);
		}
		fmt = r_str_append (fmt, " ");
		fmt = r_str_append (fmt, vars);
		free (vars);
		return fmt;
	}
	return NULL;
}

R_API void r_type_del(Sdb *TDB, const char *name) {
	const char *kind = sdb_const_get (TDB, name, 0);
	if (!kind) {
		return;
	}
	if (!strcmp (kind, "type")) {
		sdb_unset (TDB, sdb_fmt ("type.%s", name), 0);
		sdb_unset (TDB, sdb_fmt ("type.%s.size", name), 0);
		sdb_unset (TDB, sdb_fmt ("type.%s.meta", name), 0);
		sdb_unset (TDB, name, 0);
	} else if (!strcmp (kind, "struct") || !strcmp (kind, "union")) {
		int i, n = sdb_array_length(TDB, sdb_fmt ("%s.%s", kind, name));
		char *elements_key = r_str_newf ("%s.%s", kind, name);
		for (i = 0; i< n; i++) {
			char *p = sdb_array_get (TDB, elements_key, i, NULL);
			sdb_unset (TDB, sdb_fmt ("%s.%s", elements_key, p), 0);
			free (p);
		}
		sdb_unset (TDB, elements_key, 0);
		sdb_unset (TDB, name, 0);
		free (elements_key);
	} else if (!strcmp (kind, "func")) {
		int i, n = sdb_num_get (TDB, sdb_fmt ("func.%s.args", name), 0);
		for (i = 0; i < n; i++) {
			sdb_unset (TDB, sdb_fmt ("func.%s.arg.%d", name, i), 0);
		}
		sdb_unset (TDB, sdb_fmt ("func.%s.ret", name), 0);
		sdb_unset (TDB, sdb_fmt ("func.%s.cc", name), 0);
		sdb_unset (TDB, sdb_fmt ("func.%s.noreturn", name), 0);
		sdb_unset (TDB, sdb_fmt ("func.%s.args", name), 0);
		sdb_unset (TDB, name, 0);
	} else if (!strcmp (kind, "enum")) {
		RList *list = r_type_get_enum (TDB, name);
		RTypeEnum *member;
		RListIter *iter;
		r_list_foreach (list, iter, member) {
			sdb_unset (TDB, sdb_fmt ("enum.%s.%s", name, member->name), 0);
			sdb_unset (TDB, sdb_fmt ("enum.%s.0x%x", name, member->val), 0);
		}
		sdb_unset (TDB, name, 0);
	} else {
		eprintf ("Unrecognized type \"%s\"\n", kind);
	}
}

// Function prototypes api
R_API int r_type_func_exist(Sdb *TDB, const char *func_name) {
	const char *fcn = sdb_const_get (TDB, func_name, 0);
	return fcn && !strcmp (fcn, "func");
}

R_API const char *r_type_func_ret(Sdb *TDB, const char *func_name){
	const char *query = sdb_fmt ("func.%s.ret", func_name);
	return sdb_const_get (TDB, query, 0);
}

R_API int r_type_func_args_count(Sdb *TDB, const char *func_name) {
	const char *query = sdb_fmt ("func.%s.args", func_name);
	return sdb_num_get (TDB, query, 0);
}

R_API R_OWN char *r_type_func_args_type(Sdb *TDB, R_NONNULL const char *func_name, int i) {
	const char *query = sdb_fmt ("func.%s.arg.%d", func_name, i);
	char *ret = sdb_get (TDB, query, 0);
	if (ret) {
		char *comma = strchr (ret, ',');
		if (comma) {
			*comma = 0;
			return ret;
		}
		free (ret);
	}
	return NULL;
}

R_API const char *r_type_func_args_name(Sdb *TDB, R_NONNULL const char *func_name, int i) {
	const char *query = sdb_fmt ("func.%s.arg.%d", func_name, i);
	const char *get = sdb_const_get (TDB, query, 0);
	if (get) {
		char *ret = strchr (get, ',');
		return ret == 0 ? ret : ret + 1;
	}
	return NULL;
}

#define MIN_MATCH_LEN 4

static R_OWN char *type_func_try_guess(Sdb *TDB, R_NONNULL char *name) {
	const char *res;
	if (r_str_nlen (name, MIN_MATCH_LEN) < MIN_MATCH_LEN) {
		return NULL;
	}
	if ((res = sdb_const_get (TDB, name, NULL))) {
		bool is_func = res && !strcmp ("func", res);
		if (is_func) {
			return strdup (name);
		}
	}
	return NULL;
}

// TODO:
// - symbol names are long and noisy, some of them might not be matched due
//   to additional information added around name
R_API R_OWN char *r_type_func_guess(Sdb *TDB, R_NONNULL char *func_name) {
	int offset = 0;
	char *str = func_name;
	char *result = NULL;
	char *first, *last;
	r_return_val_if_fail (TDB, false);
	r_return_val_if_fail (func_name, false);

	size_t slen = strlen (str);
	if (slen < MIN_MATCH_LEN) {
		return NULL;
	}

	if (slen > 4) { // were name-matching so ignore autonamed
		if (!strncmp (str, "fcn.", 4) || !strncmp (str, "loc.", 4)) {
			return NULL;
		}
	}
	// strip r2 prefixes (sym, sym.imp, etc')
	while (slen > 4 && (offset + 3 < slen) && str[offset + 3] == '.') {
		offset += 4;
	}
	slen -= offset;
	str += offset;
	if (!strncmp (str, "__isoc99_", 9)) {
		str += 9;
	}
	if ((result = type_func_try_guess (TDB, str))) {
		return result;
	}

	if (*str == '_' && (result = type_func_try_guess (TDB, str + 1))) {
		return result;
	}

	str = strdup (str);
	// some names are in format module.dll_function_number, try to remove those
	// also try module.dll_function and function_number
	if ((first = strchr (str, '_'))) {
		// check if the prefix is actually "dll_" otherwise don't try to
		// interpret the name
		const char *dll = "dll";
		char *dll_ptr = first - strlen (dll);
		if (dll_ptr < str || strncmp (dll_ptr, dll, strlen (dll))) {
			goto out;
		}

		last = (char *)r_str_lchr (first, '_');
		if (!last) {
			goto out;
		}
		// middle + suffix or right half
		if ((result = type_func_try_guess (TDB, first + 1))) {
			goto out;
		}
		last[0] = 0;
		// prefix + middle or left
		if ((result = type_func_try_guess (TDB, str))) {
			goto out;
		}
		if (last != first) {
			// middle
			if ((result = type_func_try_guess (TDB, first + 1))) {
				goto out;
			}
		}
		result = NULL;
	}
out:
	free (str);
	return result;
}
