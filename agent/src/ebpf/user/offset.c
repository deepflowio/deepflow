/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Reference:
// https://github.com/davea42/libdwarf-code/blob/master/src/bin/dwarfexample/simplereader.c
// https://github.com/davea42/libdwarf-code/blob/master/src/bin/dwarfexample/findfuncbypc.c

#include "offset.h"
#include "common.h"
#include "log.h"
#include <fcntl.h>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static const int FOUND_TARGET = 12;
static const int LEVEL_MAX = 3;

struct target_data_s {
	const char *structure;
	const char *member;
	unsigned long long int offset;
};

static int examine_die_data(Dwarf_Debug dbg, struct target_data_s *td,
			    Dwarf_Die die, int in_level)
{
	Dwarf_Error err = NULL;
	Dwarf_Die child = NULL;
	Dwarf_Half tag = 0;
	Dwarf_Attribute attr = NULL;
	char *name = NULL;
	int rc = 0;

	rc = dwarf_tag(die, &tag, &err);
	if (rc != DW_DLV_OK) {
		return DW_DLV_ERROR;
	}

	if (tag != DW_TAG_structure_type)
		return DW_DLV_OK;

	rc = dwarf_die_text(die, DW_AT_name, &name, &err);
	if (rc == DW_DLV_ERROR) {
		return DW_DLV_ERROR;
	}

	if (!name || strcmp(name, td->structure))
		return DW_DLV_OK;

	rc = dwarf_child(die, &child, &err);
	if (rc == DW_DLV_ERROR) {
		return DW_DLV_ERROR;
	}

	for (;;) {
		rc = dwarf_die_text(child, DW_AT_name, &name, &err);
		if (rc == DW_DLV_ERROR) {
			return DW_DLV_ERROR;
		}
		if (!strcmp(name, td->member)) {
			rc = dwarf_attr(child, DW_AT_data_member_location,
					&attr, &err);
			if (rc == DW_DLV_ERROR) {
				return DW_DLV_ERROR;
			}

			rc = dwarf_formudata(attr, &td->offset, &err);
			if (rc == DW_DLV_ERROR) {
				return DW_DLV_ERROR;
			}
			return FOUND_TARGET;
		}

		rc = dwarf_siblingof_b(dbg, child, true, &child, &err);
		if (rc == DW_DLV_ERROR) {
			return DW_DLV_ERROR;
		}
		if (rc == DW_DLV_NO_ENTRY) {
			return DW_DLV_OK;
		}
	}

	return DW_DLV_OK;
}

static int get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die, int is_info,
				int in_level, int cu_number,
				struct target_data_s *td, Dwarf_Error *errp)
{
	int res = DW_DLV_ERROR;
	Dwarf_Die cur_die = in_die;
	Dwarf_Die child = 0;

	// Limit recursion depth to no more than 3 levels.
	// Avoid segfaults caused by deep recursion
	if (in_level > LEVEL_MAX) {
		return DW_DLV_OK;
	}

	res = examine_die_data(dbg, td, in_die, in_level);
	if (res == DW_DLV_ERROR) {
		return DW_DLV_ERROR;
	}
	if (res == FOUND_TARGET) {
		return FOUND_TARGET;
	}

	/*  Now look at the children of the incoming DIE */
	for (;;) {
		Dwarf_Die sib_die = 0;
		res = dwarf_child(cur_die, &child, errp);
		if (res == DW_DLV_ERROR) {
			return DW_DLV_ERROR;
		}
		if (res == DW_DLV_OK) {
			int res2 = 0;

			res2 = get_die_and_siblings(dbg, child, is_info,
						    in_level + 1, cu_number, td,
						    errp);
			if (res2 == DW_DLV_ERROR) {
				return DW_DLV_ERROR;
			}
			if (res2 == FOUND_TARGET) {
				return FOUND_TARGET;
			}
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			child = 0;
		}
		res = dwarf_siblingof_b(dbg, cur_die, is_info, &sib_die, errp);
		if (res == DW_DLV_ERROR) {
			return DW_DLV_ERROR;
		}
		if (res == DW_DLV_NO_ENTRY) {
			/* Done at this level. */
			break;
		}
		/* res == DW_DLV_OK */
		cur_die = sib_die;
		res = examine_die_data(dbg, td, cur_die, in_level);
		if (res == DW_DLV_ERROR) {
			return DW_DLV_ERROR;
		}
		if (res == FOUND_TARGET) {
			return FOUND_TARGET;
		}
	}
	return DW_DLV_OK;
}

static int look_for_our_target(Dwarf_Debug dbg, struct target_data_s *td,
			       Dwarf_Error *errp)
{
	Dwarf_Bool is_info = 1;
	int cu_number = 0;

	for (;; ++cu_number) {
		Dwarf_Die no_die = 0;
		Dwarf_Die cu_die = 0;
		int res = DW_DLV_ERROR;
		res = dwarf_next_cu_header_d(dbg, is_info, NULL, NULL, NULL,
					     NULL, NULL, NULL, NULL, NULL, NULL,
					     NULL, errp);
		if (res == DW_DLV_ERROR) {
			return DW_DLV_NO_ENTRY;
		}
		if (res == DW_DLV_NO_ENTRY) {
			return DW_DLV_NO_ENTRY;
		}
		/* The CU will have a single sibling, a cu_die. */
		res = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, errp);
		if (res == DW_DLV_ERROR) {
			return DW_DLV_NO_ENTRY;
		}
		if (res == DW_DLV_NO_ENTRY) {
			return DW_DLV_NO_ENTRY;
		}

		res = get_die_and_siblings(dbg, cu_die, is_info, 0, cu_number,
					   td, errp);
		if (res == FOUND_TARGET) {
			return DW_DLV_OK;
		}
	}
	return DW_DLV_NO_ENTRY;
}

int struct_member_offset_analyze(const char *bin, const char *structure,
				 const char *member)
{
	Dwarf_Error err = NULL;
	Dwarf_Debug dbg = NULL;
	int fd = 0;
	int rc = 0;

	struct target_data_s td = {
		.structure = structure,
		.member = member,
		.offset = -1,
	};

	fd = open(bin, O_RDONLY, 0);
	if (fd < 0)
		goto out;

	rc = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err);
	if (rc != DW_DLV_OK)
		goto out_file;

	look_for_our_target(dbg, &td, &err);

	dwarf_finish(dbg);
out_file:
	close(fd);
out:
	return (int)td.offset;
}
