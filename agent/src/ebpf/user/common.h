#ifndef __COMMON_H__
#define __COMMON_H__
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <emmintrin.h>
#include <time.h>

#define NS_IN_SEC       1000000000ULL
#define TIME_TYPE_NAN   1
#define TIME_TYPE_SEC   0

#define OPEN_FILES_MAX 65536
#define KPROBE_EVENTS_FILE "/sys/kernel/debug/tracing/kprobe_events"
#define UPROBE_EVENTS_FILE "/sys/kernel/debug/tracing/uprobe_events"

#ifndef NELEMS
#define NELEMS(a) (sizeof(a) / sizeof((a)[0]))
#endif

struct sysinfo {
	long uptime;
	unsigned long loads[3];
	unsigned long totalram;
	unsigned long freeram;
	unsigned long sharedram;
	unsigned long bufferram;
	unsigned long totalswap;
	unsigned long freeswap;
	uint16_t procs;
	uint16_t pad;
	unsigned long totalhigh;
	unsigned long freehigh;
	uint32_t mem_unit;
	char _f[20-2*sizeof(unsigned long)-sizeof(uint32_t)];
};

extern int sysinfo (struct sysinfo *__info);

/**
 * Check if a branch is likely to be taken.
 *
 * This compiler builtin allows the developer to indicate if a branch is
 * likely to be taken. Example:
 *
 *   if (likely(x > 1))
 *      do_stuff();
 *
 */
#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif /* likely */

/**
 * Check if a branch is unlikely to be taken.
 *
 * This compiler builtin allows the developer to indicate if a branch is
 * unlikely to be taken. Example:
 *
 *   if (unlikely(x < 1))
 *      do_stuff();
 *
 */
#ifndef unlikely
#define unlikely(x)  __builtin_expect((x),0)
#endif /* unlikely */

#ifndef offsetof
/** Return the offset of a field in a structure. */
#define offsetof(TYPE, MEMBER)  __builtin_offsetof (TYPE, MEMBER)
#endif

/**
 * Force a function to be inlined
 */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define CACHE_LINE_SIZE   64
#define CACHE_LINE_MASK (CACHE_LINE_SIZE-1) /**< Cache line mask. */

static inline void __pause(void)
{
	_mm_pause();
}

#define CACHE_LINE_ROUNDUP(size) \
         (CACHE_LINE_SIZE * ((size + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE))

/**
 * Aligns input parameter to the next power of 2
 *
 * @param x
 *   The integer value to algin
 *
 * @return
 *   Input parameter aligned to the next power of 2
 */
static inline uint32_t align32pow2(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}

/**
 * Force alignment to cache line.
 */
#define __cache_aligned __aligned(CACHE_LINE_SIZE)

/**
 * short definition to mark a function parameter unused
 */
#define __unused __attribute__((__unused__))

#ifndef min
#define min(x,y) ({		\
    typeof(x) _x = (x);		\
    typeof(y) _y = (y);		\
    (void) (&_x == &_y);	\
    _x < _y ? _x : _y; })
#endif

#ifndef max
#define max(x,y) ({		\
    typeof(x) _x = (x);		\
    typeof(y) _y = (y);		\
    (void) (&_x == &_y);	\
    _x > _y ? _x : _y; })
#endif

#define __maybe_unused __attribute__((__unused__))

#ifndef min_t
#define min_t(type, a, b) min(((type) a), ((type) b))
#endif
#ifndef max_t
#define max_t(type, a, b) max(((type) a), ((type) b))
#endif

#ifndef __be32
typedef uint32_t __be32;
#endif

#ifndef __be16
typedef uint16_t __be16;
#endif

typedef pid_t tr_pid_t;
#define tr_getpid   getpid

/* File related definitions */
#define tr_open_file(name, access, create)   \
   open((const char *) name, access|create, 0644)

#define tr_open_file_n    "open()"
#define TR_FILE_RDONLY    O_RDONLY
#define TR_FILE_RDWR      O_RDWR
#define TR_FILE_CREATE_OR_OPEN  O_CREAT
#define TR_FILE_OPEN0
#define TR_FILE_TRUNCATE  O_TRUNC
#define TR_FILE_APPEND    O_APPEND

#define tr_close_file     close
#define tr_close_file_n   "close()"

#define tr_delete_file(name)    unlink((const char *) name)
#define tr_delete_file_n  "unlink()"

#define TR_INVALID_FILE          -1
#define TR_FILE_ERROR            -1

enum {
	ETR_OK = 0,
	ETR_INVAL = -1,		/* invalid parameter */
	ETR_NOMEM = -2,		/* no memory */
	ETR_EXIST = -3,		/* already exist */
	ETR_NOTEXIST = -4,	/* not exist */
	ETR_NOTGOELF = -5,      /* not go elf */
	ETR_NOPROT = -7,	/* no protocol */
	ETR_NOSYMBOL = -8,	/* no uprobe symbols */
	ETR_UPDATE_MAP_FAILD = -9, /* update map faild */
	ETR_IDLE = -12,		/* nothing to do */
	ETR_BUSY = -13,		/* resource busy */
	ETR_NOTSUPP = -14,	/* not support */
	ETR_RESOURCE = -15,	/* no resource */
	ETR_OVERLOAD = -16,	/* overloaded */
	ETR_NOSERV = -17,	/* no service */
	ETR_DISABLED = -18,	/* disabled */
	ETR_NOROOM = -19,	/* no room */
	ETR_NONEALCORE = -20,	/* non-eal thread lcore */
	ETR_CALLBACKFAIL = -21,	/* callbacks fail */
	ETR_IO = -22,		/* I/O error */
	ETR_MSG_FAIL = -23,	/* msg callback failed */
	ETR_MSG_DROP = -24,	/* msg callback dropped */
	ETR_SYSCALL = -26,	/* system call failed */
	ETR_PROC_FAIL = -27,    /* procfs failed */
	ETR_NOHANDLE = -28,     /* not find event handle */

	/* positive code for non-error */
	ETR_INPROGRESS = 2,	/* in progress */
	ETR_CONTINUE = 4,
	ETR_NEWBUF = 5,
};

struct trace_err_tab {
	int errcode;
	const char *errmsg;
};

static struct trace_err_tab err_tab[] = {
	{ETR_OK, "OK"},
	{ETR_INVAL, "invalid parameter"},
	{ETR_NOMEM, "no memory"},
	{ETR_EXIST, "already exist"},
	{ETR_NOTEXIST, "not exist"},
	{ETR_NOTGOELF, "not go elf"},
	{ETR_NOPROT, "no protocol"},
	{ETR_NOSYMBOL, "no uprobe symbols"},
	{ETR_UPDATE_MAP_FAILD, "update map faild"},
	{ETR_IDLE, "nothing to do"},
	{ETR_BUSY, "resource busy"},
	{ETR_NOTSUPP, "not support"},
	{ETR_RESOURCE, "no resource"},
	{ETR_OVERLOAD, "overloaded"},
	{ETR_NOSERV, "no service"},
	{ETR_DISABLED, "disabled"},
	{ETR_NOROOM, "no room"},
	{ETR_NONEALCORE, "non-EAL thread lcore"},
	{ETR_CALLBACKFAIL, "callback failed"},
	{ETR_IO, "I/O error"},
	{ETR_MSG_FAIL, "msg callback failed"},
	{ETR_MSG_DROP, "msg dropped"},
	{ETR_SYSCALL, "system call failed"},
	{ETR_PROC_FAIL, "procfs failed"},
	{ETR_NOHANDLE, "not find event handle"},

	{ETR_INPROGRESS, "in progress"},
};

static inline const char *trace_strerror(int err)
{
	int i;

	for (i = 0; i < NELEMS(err_tab); i++) {
		if (err == err_tab[i].errcode)
			return err_tab[i].errmsg;
	}

	return "<unknow>";
}

#define RUN_ONCE(condition, f, arg) ({          \
        int __ret_warn_once = !!(condition);    \
                                                \
        if (unlikely(__ret_warn_once)) {        \
                f(arg);                         \
                condition = !(__ret_warn_once); \
        }                                       \
})

/**
 * Returns true if n is a power of 2
 * @param n
 *     Number to check
 * @return 1 if true, 0 otherwise
 */
static inline int
is_power_of_2(uint32_t n)
{
	return n && !(n & (n - 1));
}

bool is_core_kernel(void);
int get_cpus_count(bool **mask);
void clear_residual_probes();
int max_locked_memory_set_unlimited(void);
int sysfs_write(char *file_name, char *v);
uint64_t gettime(clockid_t clk_id, int flag);
uint32_t get_sys_uptime(void);
unsigned long long get_process_starttime(int pid);
int max_rlim_open_files_set(int num);
#endif /* __COMMON_H__ */
