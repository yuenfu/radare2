/* radare - LGPL - Copyright 2015-2016 nodepad, pancake */

#include "mz.h"
#include <btree.h>

static ut64 r_bin_mz_seg_to_paddr (const struct r_bin_mz_obj_t *bin, const ut16 segment) {
	return (bin->dos_header->header_paragraphs + segment) << 4;
}

int r_bin_mz_get_entrypoint (const struct r_bin_mz_obj_t *bin) {
#if 0
	ut16 cs = r_read_ble16 (buf + 0x16, false);
	ut16 ip = r_read_ble16 (buf + 0x14, false);
	ut16 pa = ((r_read_ble16 (buf + 8 , false) + cs) << 4) + ip;
#endif
	/* Value of CS in DOS header may be negative */
	const short cs = bin->dos_header->cs;
	ut32 pa = bin->dos_header->header_paragraphs + cs;
	const ut32 paddr = (pa<<4) + bin->dos_header->ip;
	if (paddr < bin->dos_file_size) {
		return paddr;
	}
	return -1;
}

// This function reads from the file buffer,
// thus using endian-agnostic functions
int cmp_segs(const void *a, const void *b) {
	const ut16 * const ma = (const ut16 * const)a;
	const ut16 * const mb = (const ut16 * const)b;
	if (!ma || !mb) {
		return 0;
	}
	return (int)(r_read_le16 (ma) - r_read_le16 (mb));
}

// This function reads from the file buffer,
// thus using endian-agnostic functions
static void trv_segs (const void *seg, const void *segs) {
	const ut8 * const mseg = (const ut8 * const)seg;
	ut16 ** const msegs = (ut16 **)segs;
	if (mseg && msegs && *msegs) {
		r_write_le16(*msegs, r_read_le16(mseg));
		*msegs = *msegs + 1;
	}
}

struct r_bin_mz_segment_t * r_bin_mz_get_segments(const struct r_bin_mz_obj_t *bin) {
#if 0
	int i;
	struct r_bin_mz_segment_t *ret;

	const MZ_image_relocation_entry * const relocs = bin->relocation_entries;
	const int num_relocs = bin->dos_header->num_relocs;

	eprintf ("cs 0x%x\n", bin->dos_header->cs);
	eprintf ("ss 0x%x\n", bin->dos_header->ss);
	for (i = 0; i < num_relocs; i++) {
		eprintf ("0x%08x segment 0x%08lx\n", relocs[i].offset, relocs[i].segment);
		// ut65 paddr = r_bin_mz_seg_to_paddr (bin, relocs[i].segment) + relocs[i].offset;
		// eprintf ("pa 0x%08llx\n", paddr);
	}
	btree_add (&tree, (void *)&first_segment, cmp_segs);
	/* Add segment address of stack segment if it's resides inside dos
	executable.
	*/
	if (r_bin_mz_seg_to_paddr (bin, stack_segment) < bin->dos_file_size) {
		btree_add (&tree, (void *)&stack_segment, cmp_segs);
	}
	return NULL;
#endif
#if 1
	struct btree_node *tree;
	struct r_bin_mz_segment_t *ret;
	// ut16 *segments, 
	int i, num_segs;
	ut64 paddr;
	const ut16 first_segment = 0;
	const ut16 stack_segment = bin->dos_header->ss;
	const MZ_image_relocation_entry * const relocs = bin->relocation_entries;
	const int num_relocs = bin->dos_header->num_relocs;
	const ut64 last_parag = ((bin->dos_file_size + 0xF) >> 4) - \
		bin->dos_header->header_paragraphs;

	btree_init (&tree);
	for (i = 0; i < num_relocs; i++) {
		paddr = r_bin_mz_seg_to_paddr (bin, relocs[i].segment) + relocs[i].offset;
		if ((paddr + 2) < bin->dos_file_size) {
			int left;
			ut16 *curr_seg = (ut16 *)r_buf_get_at (bin->b, paddr, &left);
			/* Add segment only if it's located inside dos executable data */
			if (left >= 2 && r_read_le16 (curr_seg) <= last_parag) {
				btree_add (&tree, curr_seg, cmp_segs);
			}
		}
	}

	/* Add segment address of first segment to make sure that it will be
	added. If relocations empty or there isn't first segment in relocations.) */
	btree_add (&tree, (void *)&first_segment, cmp_segs);
	/* Add segment address of stack segment if it's resides inside dos executable. */
	if (r_bin_mz_seg_to_paddr (bin, stack_segment) < bin->dos_file_size) {
		btree_add (&tree, (void *)&stack_segment, cmp_segs);
	}

	if (!num_relocs) {
		btree_cleartree (tree, NULL);
		return NULL;
	}
	ut16 *segments = calloc (2 + num_relocs, sizeof (*segments));
	if (!segments) {
		eprintf ("Error: calloc (segments)\n");
		btree_cleartree (tree, NULL);
		return NULL;
	}
	ut16 *curr_seg = segments;
	btree_traverse (tree, 0, &curr_seg, trv_segs);
	num_segs = curr_seg - segments;
	ret = calloc (num_segs + 1, sizeof (struct r_bin_mz_segment_t));
	if (!ret) {
		free (segments);
		btree_cleartree (tree, NULL);
		eprintf ("Error: calloc (struct r_bin_mz_segment_t)\n");
		return NULL;
	}

	btree_cleartree (tree, NULL);

	ret[0].paddr = r_bin_mz_seg_to_paddr (bin, segments[0]);
	for (i = 1; i < num_segs; i++) {
		ret[i].paddr = r_bin_mz_seg_to_paddr (bin, segments[i]);
		ret[i - 1].size = ret[i].paddr - ret[i - 1].paddr;
	}
	ret[i - 1].size = bin->dos_file_size - ret[i - 1].paddr;
	ret[i].last = 1;
	free (segments);
	return ret;
#endif
}

struct r_bin_mz_reloc_t *r_bin_mz_get_relocs(const struct r_bin_mz_obj_t *bin) {
	int i, j;
	struct r_bin_mz_reloc_t *relocs;
	const int num_relocs = bin->dos_header->num_relocs;
	const MZ_image_relocation_entry * const rel_entry = \
		bin->relocation_entries;

	relocs = calloc (num_relocs + 1, sizeof (*relocs));
	if (!relocs) {
		eprintf ("Error: calloc (struct r_bin_mz_reloc_t)\n");
		return NULL;
	}

	for (i = 0, j = 0; i < num_relocs; i++) {
		relocs[j].paddr =
			r_bin_mz_seg_to_paddr (bin, rel_entry[i].segment) +
			rel_entry[i].offset;
		/* Add only relocations which resides inside dos executable */
		if (relocs[j].paddr < bin->dos_file_size) {
			j++;
		}
	}
	relocs[j].last = 1;

	return relocs;
}

void *r_bin_mz_free(struct r_bin_mz_obj_t* bin) {
	if (!bin) {
		return NULL;
	}
	free ((void *)bin->dos_header);
	free ((void *)bin->dos_extended_header);
	free ((void *)bin->relocation_entries);
	r_buf_free (bin->b);
	bin->b = NULL;
	free (bin);
	return NULL;
}

static int r_bin_mz_init_hdr(struct r_bin_mz_obj_t* bin) {
	int relocations_size, dos_file_size;
	if (!(bin->dos_header = R_NEW0 (MZ_image_dos_header))) {
		r_sys_perror ("malloc (MZ_image_dos_header)");
		return false;
	}
	// TODO: read field by field to avoid endian and alignment issues
	if (r_buf_read_at (bin->b, 0, (ut8*)bin->dos_header,
			sizeof (*bin->dos_header)) == -1) {
		eprintf ("Error: read (MZ_image_dos_header)\n");
		return false;
	}

	if (bin->dos_header->blocks_in_file < 1) {
		return false;
	}
	dos_file_size = ((bin->dos_header->blocks_in_file - 1) << 9) + \
			bin->dos_header->bytes_in_last_block;

	bin->dos_file_size = dos_file_size;
	if (dos_file_size > bin->size) {
		return false;
	}
	relocations_size = bin->dos_header->num_relocs * sizeof (MZ_image_relocation_entry);
	if ((bin->dos_header->reloc_table_offset + relocations_size) > bin->size) {
		return false;
	}

	sdb_num_set (bin->kv, "mz.initial.cs", bin->dos_header->cs, 0);
	sdb_num_set (bin->kv, "mz.initial.ip", bin->dos_header->ip, 0);
	sdb_num_set (bin->kv, "mz.initial.ss", bin->dos_header->ss, 0);
	sdb_num_set (bin->kv, "mz.initial.sp", bin->dos_header->sp, 0);
	sdb_num_set (bin->kv, "mz.overlay_number", bin->dos_header->overlay_number, 0);
	sdb_num_set (bin->kv, "mz.dos_header.offset", 0, 0);
	sdb_set (bin->kv, "mz.dos_header.format", "[2]zwwwwwwwwwwwww"
			" signature bytes_in_last_block blocks_in_file num_relocs "
			" header_paragraphs min_extra_paragraphs max_extra_paragraphs "
			" ss sp checksum ip cs reloc_table_offset overlay_number ", 0);

	bin->dos_extended_header_size = bin->dos_header->reloc_table_offset - \
		sizeof (MZ_image_dos_header);

	if (bin->dos_extended_header_size > 0) {
		if (!(bin->dos_extended_header =
			      malloc (bin->dos_extended_header_size))) {
			r_sys_perror ("malloc (dos extended header)");
			return false;
		}
		if (r_buf_read_at (bin->b, sizeof (MZ_image_dos_header),
				(ut8*)bin->dos_extended_header,
				bin->dos_extended_header_size) == -1) {
			eprintf ("Error: read (dos extended header)\n");
			return false;
		}
	}

	if (relocations_size > 0) {
		if (!(bin->relocation_entries = malloc (relocations_size))) {
			r_sys_perror ("malloc (dos relocation entries)");
			return false;
		}
		if (r_buf_read_at (bin->b, bin->dos_header->reloc_table_offset,
				(ut8*)bin->relocation_entries, relocations_size) == -1) {
			eprintf ("Error: read (dos relocation entries)\n");
			R_FREE (bin->relocation_entries);
			return false;
		}
	}
	return true;
}

static int r_bin_mz_init(struct r_bin_mz_obj_t* bin) {
	bin->dos_header = NULL;
	bin->dos_extended_header = NULL;
	bin->relocation_entries = NULL;
	bin->kv = sdb_new0 ();

	if (!r_bin_mz_init_hdr (bin)) {
		eprintf ("Warning: File is not MZ\n");
		return false;
	}

	return true;
}

struct r_bin_mz_obj_t* r_bin_mz_new(const char* file) {
	const ut8 *buf;
	struct r_bin_mz_obj_t *bin = R_NEW0 (struct r_bin_mz_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &bin->size))) {
		return r_bin_mz_free (bin);
	}
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free ((void *)buf);
		return r_bin_mz_free (bin);
	}
	free ((void *)buf);
	if (!r_bin_mz_init (bin)) {
		return r_bin_mz_free (bin);
	}
	return bin;
}

struct r_bin_mz_obj_t* r_bin_mz_new_buf(const struct r_buf_t *buf) {
	struct r_bin_mz_obj_t *bin = R_NEW0 (struct r_bin_mz_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		return r_bin_mz_free (bin);
	}
	return r_bin_mz_init (bin) ? bin : r_bin_mz_free (bin);
}

ut64 r_bin_mz_get_main_vaddr(struct r_bin_mz_obj_t *bin) {
	int entry;
	int n;
	ut8 b[512];
	if (!bin || !bin->b) {
		return 0LL;
	}
	entry = r_bin_mz_get_entrypoint (bin);
	ZERO_FILL (b);
	if (r_buf_read_at (bin->b, entry, b, sizeof (b)) < 0) {
		eprintf ("Warning: Cannot read entry at 0x%08"PFMT32x "\n", (ut32) entry);
		return 0LL;
	}
	// MSVC
	if (b[0] == 0xb4 && b[1] == 0x30) {
		// ff 36 XX XX			push	XXXX
		// ff 36 XX XX			push	argv
		// ff 36 XX XX			push	argc
		// 9a XX XX XX XX		lcall	_main
		// 50				push	ax
		for (n = 0; n < sizeof (b) - 18; n++) {
			if (b[n] == 0xff && b[n + 4] == 0xff && b[n + 8] == 0xff && b[n + 12] == 0x9a && b[n + 17] == 0x50) {
				const ut16 call_addr = r_read_ble16 (b + n + 13, 0);;
				const ut16 call_seg = r_read_ble16 (b + n + 15, 0);;
				const ut64 call_dst = r_bin_mz_seg_to_paddr (bin, call_seg) + call_addr;
				return call_dst;
			}
		}
	}

	return 0LL;
}
