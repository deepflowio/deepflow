# How to profile agent

## Prerequisites

Always use agent compiled with debug on to profile if possible, because it will provide more info in stack trace.

Use the following command to compile agent:

	CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release

Optional: Compress the binary for smaller size.

## CPU

[Perf](https://man7.org/linux/man-pages/man1/perf.1.html) is used to profile agent cpu usage.

Use the following commands to record agent cpu usage. If agent is running as a container, run these commands in the same container.

	pid=`ps -ef | grep deepflow-agent | grep -v grep | awk '{print $2}'`
	perf record -F97 --call-graph=dwarf -g -p $pid -- sleep 60

It will generate a `perf.data` in current directory. Use `perf report -g` to view call stack.

Additionally, a flame graph can be generated with [FlameGraph](https://github.com/brendangregg/FlameGraph).

	git clone https://github.com/brendangregg/FlameGraph
	perf script | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl > perf.svg

## Memory

[Valgrind Massif](https://valgrind.org/docs/manual/ms-manual.html) is used to monitor agent heap usage.

Agent binary must be compiled with glibc to use valgrind. Start agent with the following command:

	valgrind --tool=massif deepflow-agent

Wait for memory consumption to increase, and use these commands to capture heap usage.
- `vgdb snapshot`
- `vgdb detailed_snapshot`
- `vgdb all_snapshots`

Use `ms_print` to view captured snapshots.
