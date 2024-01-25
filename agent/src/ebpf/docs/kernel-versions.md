# BPF Features by Linux Kernel Version

## eBPF support

Kernel version | Commit
---------------|-------
3.15 | [`bd4cf0ed331a`](https://github.com/torvalds/linux/commit/bd4cf0ed331a275e9bf5a49e6d0fd55dffc551b8)

## JIT compiling

The list of supported architectures for your kernel can be retrieved with:

    git grep HAVE_EBPF_JIT arch/

Feature / Architecture | Kernel version | Commit
-----------------------|----------------|-------
x86\_64                            | 3.16 | [`622582786c9e`](https://github.com/torvalds/linux/commit/622582786c9e041d0bd52bde201787adeab249f8)
ARM64                              | 3.18 | [`e54bcde3d69d`](https://github.com/torvalds/linux/commit/e54bcde3d69d40023ae77727213d14f920eb264a)

## Main features

Several (but not all) of these _main features_ translate to an eBPF program type.
The list of such program types supported in your kernel can be found in file
[`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h):

    git grep -W 'bpf_prog_type {' include/uapi/linux/bpf.h

Feature | Kernel version | Commit
--------|----------------|-------
Kernel helpers | 3.15 | [`bd4cf0ed331a`](https://github.com/torvalds/linux/commit/bd4cf0ed331a275e9bf5a49e6d0fd55dffc551b8)
`bpf()` syscall | 3.18 | [`99c55f7d47c0`](https://github.com/torvalds/linux/commit/99c55f7d47c0dc6fc64729f37bf435abf43f4c60)
Maps | 3.18 | [`99c55f7d47c0`](https://github.com/torvalds/linux/commit/99c55f7d47c0dc6fc64729f37bf435abf43f4c60)
BPF attached to `kprobes` | 4.1 | [`2541517c32be`](https://github.com/torvalds/linux/commit/2541517c32be2531e0da59dfd7efc1ce844644f5)
Tail calls | 4.2 | [`04fd61ab36ec`](https://github.com/torvalds/linux/commit/04fd61ab36ec065e194ab5e74ae34a5240d992bb)
Persistent maps and programs (virtual FS) | 4.4 | [`b2197755b263`](https://github.com/torvalds/linux/commit/b2197755b2633e164a439682fb05a9b5ea48f706)
BPF attached to tracepoints | 4.7 | [`98b5c2c65c29`](https://github.com/torvalds/linux/commit/98b5c2c65c2951772a8fc661f50d675e450e8bce)
BPF attached to perf events | 4.9 | [`0515e5999a46`](https://github.com/torvalds/linux/commit/0515e5999a466dfe6e1924f460da599bb6821487)
Verifier exposure and internal hooks | 4.9 | [`13a27dfc6697`](https://github.com/torvalds/linux/commit/13a27dfc669724564aafa2699976ee756029fed2)
BPF program tag | 4.10 | [`7bd509e311f4`](https://github.com/torvalds/linux/commit/7bd509e311f408f7a5132fcdde2069af65fa05ae)
Tracepoints to debug BPF | 4.11 (removed in 4.18) | [`a67edbf4fb6d`](https://github.com/torvalds/linux/commit/a67edbf4fb6deadcfe57a04a134abed4a5ba3bb5) [`4d220ed0f814`](https://github.com/torvalds/linux/commit/4d220ed0f8140c478ab7b0a14d96821da639b646)
Testing / benchmarking BPF programs | 4.12 | [`1cf1cae963c2`](https://github.com/torvalds/linux/commit/1cf1cae963c2e6032aebe1637e995bc2f5d330f4)
BPF programs and maps IDs | 4.13 | [`dc4bb0e23561`](https://github.com/torvalds/linux/commit/dc4bb0e2356149aee4cdae061936f3bbdd45595c)

### Program types

Program type | Kernel version | Commit | Enum
-------------|----------------|--------|-----
Kprobe                         | 4.1  | [`2541517c32be`](https://github.com/torvalds/linux/commit/2541517c32be2531e0da59dfd7efc1ce844644f5) | BPF_PROG_TYPE_KPROBE
Tracepoint                     | 4.7  | [`98b5c2c65c29`](https://github.com/torvalds/linux/commit/98b5c2c65c2951772a8fc661f50d675e450e8bce) | BPF_PROG_TYPE_TRACEPOINT
Perf event                     | 4.9  | [`0515e5999a46`](https://github.com/torvalds/linux/commit/0515e5999a466dfe6e1924f460da599bb6821487) | BPF_PROG_TYPE_PERF_EVENT

## Maps

### Map types

The list of map types supported in your kernel can be found in file
[`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h):

    git grep -W 'bpf_map_type {' include/uapi/linux/bpf.h

 Map type | Kernel version | Commit | Enum
----------|----------------|--------|------
Hash                            | 3.19 | [`0f8e4bd8a1fc`](https://github.com/torvalds/linux/commit/0f8e4bd8a1fc8c4185f1630061d0a1f2d197a475) | BPF_MAP_TYPE_HASH
Array                           | 3.19 | [`28fbcfa08d8e`](https://github.com/torvalds/linux/commit/28fbcfa08d8ed7c5a50d41a0433aad222835e8e3) | BPF_MAP_TYPE_ARRAY
Prog array                      | 4.2  | [`04fd61ab36ec`](https://github.com/torvalds/linux/commit/04fd61ab36ec065e194ab5e74ae34a5240d992bb) | BPF_MAP_TYPE_PROG_ARRAY
Perf events                     | 4.3  | [`ea317b267e9d`](https://github.com/torvalds/linux/commit/ea317b267e9d03a8241893aa176fba7661d07579) | BPF_MAP_TYPE_PERF_EVENT_ARRAY
Per-CPU hash                    | 4.6  | [`824bd0ce6c7c`](https://github.com/torvalds/linux/commit/824bd0ce6c7c43a9e1e210abf124958e54d88342) | BPF_MAP_TYPE_PERCPU_HASH
Per-CPU array                   | 4.6  | [`a10423b87a7e`](https://github.com/torvalds/linux/commit/a10423b87a7eae75da79ce80a8d9475047a674ee) | BPF_MAP_TYPE_PERCPU_ARRAY
Stack trace                     | 4.6  | [`d5a3b1f69186`](https://github.com/torvalds/linux/commit/d5a3b1f691865be576c2bffa708549b8cdccda19) | BPF_MAP_TYPE_STACK_TRACE
LRU hash                        | 4.10 | [`29ba732acbee`](https://github.com/torvalds/linux/commit/29ba732acbeece1e34c68483d1ec1f3720fa1bb3) [`3a08c2fd7634`](https://github.com/torvalds/linux/commit/3a08c2fd763450a927d1130de078d6f9e74944fb) | BPF_MAP_TYPE_LRU_HASH
LRU per-CPU hash                | 4.10 | [`8f8449384ec3`](https://github.com/torvalds/linux/commit/8f8449384ec364ba2a654f11f94e754e4ff719e0) [`961578b63474`](https://github.com/torvalds/linux/commit/961578b63474d13ad0e2f615fcc2901c5197dda6) | BPF_MAP_TYPE_LRU_PERCPU_HASH
LPM trie (longest-prefix match) | 4.11 | [`b95a5c4db09b`](https://github.com/torvalds/linux/commit/b95a5c4db09bc7c253636cb84dc9b12c577fd5a0) | BPF_MAP_TYPE_LPM_TRIE
Array of maps                   | 4.12 | [`56f668dfe00d`](https://github.com/torvalds/linux/commit/56f668dfe00dcf086734f1c42ea999398fad6572) | BPF_MAP_TYPE_ARRAY_OF_MAPS
Hash of maps                    | 4.12 | [`bcc6b1b7ebf8`](https://github.com/torvalds/linux/commit/bcc6b1b7ebf857a9fe56202e2be3361131588c15) | BPF_MAP_TYPE_HASH_OF_MAPS

### Map userspace API

Some (but not all) of these *API features* translate to a subcommand beginning with `BPF_MAP_`.
The list of subcommands supported in your kernel can be found in file
[`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h):

    git grep -W 'bpf_cmd {' include/uapi/linux/bpf.h

Feature | Kernel version | Commit
--------|----------------|-------
Basic operations (lookup, update, delete, `GET_NEXT_KEY`) | 3.18 | [`db20fd2b0108`](https://github.com/torvalds/linux/commit/db20fd2b01087bdfbe30bce314a198eefedcc42e)
Pass flags to `UPDATE_ELEM` | 3.19 | [`3274f52073d8`](https://github.com/torvalds/linux/commit/3274f52073d88b62f3c5ace82ae9d48546232e72)
Pre-alloc map memory by default | 4.6 | [`6c9059817432`](https://github.com/torvalds/linux/commit/6c90598174322b8888029e40dd84a4eb01f56afe)
Pass `NULL` to `GET_NEXT_KEY` | 4.12 | [`8fe45924387b`](https://github.com/torvalds/linux/commit/8fe45924387be6b5c1be59a7eb330790c61d5d10)
Creation: select NUMA node | 4.14 | [`96eabe7a40aa`](https://github.com/torvalds/linux/commit/96eabe7a40aa17e613cf3db2c742ee8b1fc764d0)


## Helpers

The list of helpers supported in your kernel can be found in file
[`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h):

    git grep '	FN(' include/uapi/linux/bpf.h

Alphabetical order

Helper | Kernel version | License | Commit |
-------|----------------|---------|--------|
`BPF_FUNC_get_smp_processor_id()` | 4.1 |  | [`c04167ce2ca0`](https://github.com/torvalds/linux/commit/c04167ce2ca0ecaeaafef006cb0d65cf01b68e42)
`BPF_FUNC_get_stack()` | 4.18 | GPL | [`de2ff05f48af`](https://github.com/torvalds/linux/commit/de2ff05f48afcde816ff4edb217417f62f624ab5)
`BPF_FUNC_get_stackid()` | 4.6 | GPL | [`d5a3b1f69186`](https://github.com/torvalds/linux/commit/d5a3b1f691865be576c2bffa708549b8cdccda19)
`BPF_FUNC_ktime_get_ns()` | 4.1 | | [`d9847d310ab4`](https://github.com/torvalds/linux/commit/d9847d310ab4003725e6ed1822682e24bd406908)
`BPF_FUNC_map_delete_elem()` | 3.19 |  | [`d0003ec01c66`](https://github.com/torvalds/linux/commit/d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_map_lookup_elem()` | 3.19 |  | [`d0003ec01c66`](https://github.com/torvalds/linux/commit/d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_map_update_elem()` | 3.19 |  | [`d0003ec01c66`](https://github.com/torvalds/linux/commit/d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_perf_event_output()` | 4.4 | GPL | [`a43eec304259`](https://github.com/torvalds/linux/commit/a43eec304259a6c637f4014a6d4767159b6a3aa3)
`BPF_FUNC_perf_event_read()` | 4.3 | GPL | [`35578d798400`](https://github.com/torvalds/linux/commit/35578d7984003097af2b1e34502bc943d40c1804)
`BPF_FUNC_probe_read()` | 4.1 | GPL | [`2541517c32be`](https://github.com/torvalds/linux/commit/2541517c32be2531e0da59dfd7efc1ce844644f5)
`BPF_FUNC_probe_read_str()` | 4.11 | GPL | [`a5e8c07059d0`](https://github.com/torvalds/linux/commit/a5e8c07059d0f0b31737408711d44794928ac218)
`BPF_FUNC_probe_write_user()` | 4.8 | GPL | [`96ae52279594`](https://github.com/torvalds/linux/commit/96ae52279594470622ff0585621a13e96b700600)
`BPF_FUNC_set_hash()` | 4.13 |  | [`ded092cd73c2`](https://github.com/torvalds/linux/commit/ded092cd73c2c56a394b936f86897f29b2e131c0)
`BPF_FUNC_set_hash_invalid()` | 4.9 |  | [`7a4b28c6cc9f`](https://github.com/torvalds/linux/commit/7a4b28c6cc9ffac50f791b99cc7e46106436e5d8)
`BPF_FUNC_tail_call()` | 4.2 |  | [`04fd61ab36ec`](https://github.com/torvalds/linux/commit/04fd61ab36ec065e194ab5e74ae34a5240d992bb)
`BPF_FUNC_trace_printk()` | 4.1 | GPL | [`9c959c863f82`](https://github.com/torvalds/linux/commit/9c959c863f8217a2ff3d7c296e8223654d240569)

Note: GPL-only BPF helpers require a GPL-compatible license. The current licenses considered GPL-compatible by the kernel are:

* GPL
* GPL v2
* GPL and additional rights
* Dual BSD/GPL
* Dual MIT/GPL
* Dual MPL/GPL

Check the list of GPL-compatible licenses in your [kernel source code](https://github.com/torvalds/linux/blob/master/include/linux/license.h).

## Program Types
The list of program types and supported helper functions can be retrieved with:

    git grep -W 'func_proto(enum bpf_func_id func_id' kernel/ net/ drivers/

|Program Type| Helper Functions|
|------------|-----------------|
|`BPF_PROG_TYPE_KPROBE`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_perf_event_read_value()` <br> `BPF_FUNC_override_return()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_TRACEPOINT`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_d_path()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_PERF_EVENT`| `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_perf_prog_read_value()` <br> `Tracing functions`|

|Function Group| Functions|
|------------------|-------|
|`Base functions`| `BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_map_peek_elem()` <br> `BPF_FUNC_map_pop_elem()` <br> `BPF_FUNC_map_push_elem()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_get_numa_node_id()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_ktime_get_boot_ns()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_trace_printk()` <br> `BPF_FUNC_spin_lock()` <br> `BPF_FUNC_spin_unlock()` |
|`Tracing functions`|`BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_probe_read()` <br> `BPF_FUNC_ktime_get_boot_ns()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_get_current_pid_tgid()` <br> `BPF_FUNC_get_current_task()` <br> `BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_get_current_comm()` <br> `BPF_FUNC_trace_printk()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_get_numa_node_id()` <br> `BPF_FUNC_perf_event_read()` <br> `BPF_FUNC_probe_write_user()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_probe_read_str()` <br> `BPF_FUNC_send_signal()` <br> `BPF_FUNC_probe_read_kernel()` <br> `BPF_FUNC_probe_read_kernel_str()` <br> `BPF_FUNC_probe_read_user()` <br> `BPF_FUNC_probe_read_user_str()` <br> `BPF_FUNC_send_signal_thread()` <br> `BPF_FUNC_get_ns_current_pid_tgid()` <br> `BPF_FUNC_get_task_stack()`|

## Kernel Compilation Configuration Options
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_FTRACE_SYSCALLS=y (/sys/kernel/debug/tracing/events/syscalls/)
CONFIG_KPROBES=y
CONFIG_HAVE_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBES=y
CONFIG_UPROBE_EVENTS=y
```
