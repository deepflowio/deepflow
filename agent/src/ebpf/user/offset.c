#include "offset.h"
#include "common.h"
#include <fcntl.h>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static const int OFFSET_ERROR = -1;

struct member_offset {
	const char *bin;
	const char *structure;
	const char *member;
	unsigned long long int offset;
};

static int member_offset_die(struct member_offset *offset, Dwarf_Debug dbg,
			     Dwarf_Die die)
{
	Dwarf_Error err = NULL;
	Dwarf_Die child = NULL;
	Dwarf_Half tag = 0;
	Dwarf_Attribute attr = NULL;
	char *name = NULL;
	int rc = 0;

	rc = dwarf_tag(die, &tag, &err);
	if (rc != DW_DLV_OK) {
		return OFFSET_ERROR;
	}

	if (tag != DW_TAG_structure_type)
		return 0;

	rc = dwarf_die_text(die, DW_AT_name, &name, &err);
	if (rc == DW_DLV_ERROR) {
		return OFFSET_ERROR;
	}

	if (!name || strcmp(name, offset->structure))
		return 0;

	rc = dwarf_child(die, &child, &err);
	if (rc == DW_DLV_ERROR) {
		return OFFSET_ERROR;
	}

	while (1) {
		rc = dwarf_die_text(child, DW_AT_name, &name, &err);
		if (rc == DW_DLV_ERROR) {
			return OFFSET_ERROR;
		}
		if (!strcmp(name, offset->member)) {
			rc = dwarf_attr(child, DW_AT_data_member_location,
					&attr, &err);
			if (rc == DW_DLV_ERROR) {
				return OFFSET_ERROR;
			}

			rc = dwarf_formudata(attr, &offset->offset, &err);
			if (rc == DW_DLV_ERROR) {
				return OFFSET_ERROR;
			}
		}

		rc = dwarf_siblingof_b(dbg, child, true, &child, &err);
		if (rc == DW_DLV_ERROR) {
			return OFFSET_ERROR;
		}

		if (rc == DW_DLV_NO_ENTRY)
			return 0;
	}

	return 0;
}

static int member_offset_dfs(struct member_offset *offset, Dwarf_Debug dbg,
			     Dwarf_Die die)
{
	Dwarf_Error err = NULL;
	Dwarf_Die child = NULL;
	int rc = 0;

	if (offset->offset != ULLONG_MAX)
		return 0;

	member_offset_die(offset, dbg, die);

	rc = dwarf_child(die, &child, &err);
	if (rc == DW_DLV_ERROR) {
		return OFFSET_ERROR;
	}
	if (rc == DW_DLV_OK)
		member_offset_dfs(offset, dbg, child);

	rc = dwarf_siblingof_b(dbg, die, true, &die, &err);
	if (rc == DW_DLV_ERROR) {
		return OFFSET_ERROR;
	}
	if (rc == DW_DLV_OK)
		member_offset_dfs(offset, dbg, die);

	return 0;
}

static int member_offset_analyze_internal(struct member_offset *offset)
{
	Dwarf_Error err = NULL;
	Dwarf_Debug dbg = NULL;
	Dwarf_Die die = NULL;
	int fd = 0;
	int rc = 0;
	int error = 0;

	offset->offset = ULLONG_MAX;

	fd = open(offset->bin, O_RDONLY, 0);
	if (fd < 0) {
		error = OFFSET_ERROR;
		goto out;
	}

	rc = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err);
	if (rc != DW_DLV_OK) {
		error = OFFSET_ERROR;
		goto out_file;
	}

	while (1) {
		rc = dwarf_next_cu_header_d(dbg, true, NULL, NULL, NULL, NULL,
					    NULL, NULL, NULL, NULL, NULL, NULL,
					    &err);
		if (rc == DW_DLV_ERROR) {
			error = OFFSET_ERROR;
			goto out_dwarf;
		}
		if (rc == DW_DLV_NO_ENTRY)
			break;
		rc = dwarf_siblingof_b(dbg, 0, true, &die, &err);
		if (rc == DW_DLV_ERROR) {
			error = OFFSET_ERROR;
			goto out_dwarf;
		}

		member_offset_dfs(offset, dbg, die);
	}

	if (offset->offset == ULLONG_MAX) {
		error = OFFSET_ERROR;
	}

out_dwarf:
	rc = dwarf_finish(dbg);
	if (rc != DW_DLV_OK) {
		error = OFFSET_ERROR;
		goto out_file;
	}

out_file:
	close(fd);
out:
	return error;
}

int struct_member_offset_analyze(const char *bin, const char *structure,
				 const char *member)
{
	struct member_offset offset = { .bin = bin,
					.structure = structure,
					.member = member };
	if (member_offset_analyze_internal(&offset))
		return ETR_INVAL;
	else
		return (int)offset.offset;
}
