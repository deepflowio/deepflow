#include <fcntl.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "bcc/bcc_syms.h"

int _a_test_function(const char *a_string)
{
	int i;
	for (i = 0; a_string[i]; ++i);
	return i;
}

int symbol_test(void)
{
	struct bcc_symbol sym;
	struct bcc_symbol lazy_sym;
	static struct bcc_symbol_option lazy_opt = {
		.use_debug_file = 1,
		.check_debug_file_crc = 1,
		.lazy_symbolize = 1,
#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
		.use_symbol_type =
		    BCC_SYM_ALL_TYPES | (1 << STT_PPC64_ELFV2_SYM_LEP),
#else
		.use_symbol_type = BCC_SYM_ALL_TYPES,
#endif
	};

	void *resolver = bcc_symcache_new(getpid(), NULL);
	void *lazy_resolver = bcc_symcache_new(getpid(), &lazy_opt);

	bcc_symcache_resolve(resolver, (uint64_t) & _a_test_function, &sym);

	printf("sym ### %s - %s\n", sym.module, sym.name);

	bcc_symcache_resolve(lazy_resolver, (uint64_t) & _a_test_function,
			     &lazy_sym);

	printf("lazy_sym ### %s - %s\n", lazy_sym.module, lazy_sym.name);

	bcc_free_symcache(resolver, getpid());
	bcc_free_symcache(lazy_resolver, getpid());

	return 0;
}
