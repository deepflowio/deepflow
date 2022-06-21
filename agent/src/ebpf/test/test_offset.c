#include "../user/offset.h"
#include <stdio.h>

const char *test_go_file = "../../../resources/test/ebpf/go-elf";

int main(void)
{

	int offset = struct_member_offset_analyze(test_go_file, "runtime.g", "goid");

	// 偏移量预期输出 152
	if (offset != 152)
	{
		printf("[FAIL]\n");
		return -1;
	}

	printf("[OK]\n");

	return 0;
}
