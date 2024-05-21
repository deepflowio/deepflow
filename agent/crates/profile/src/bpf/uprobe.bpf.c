#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
    void **address;
    size_t size;
    u64 call_time;
} malloc_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32);
    __type(key, u64);
    __type(value, malloc_data_t);
} malloc_info SEC(".maps");

typedef struct {
    u32 pid;
    u32 size;
    u64 address;
    u64 duration;
} meminfo_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} memperf_output SEC(".maps");

SEC("uprobe//usr/lib/jvm/java-1.8.0-openjdk-1.8.0.402.b06-1.el7_9.x86_64/jre/lib/amd64/server/libjvm.so:_ZN11AllocTracer33send_allocation_in_new_tlab_eventE11KlassHandleP8HeapWordmmP6Thread")
int BPF_KPROBE(alloc_in_new_tlab, void *klass, void *obj, size_t tlab_size, size_t alloc_size)
{
    u64 id = bpf_get_current_pid_tgid();
    bpf_printk("pid: %lu alloc_in_new_tlab t_size=%lu a_size=%lu\n", id >> 32, tlab_size, alloc_size);
    return 0;
}

#if 0
SEC("uprobe//usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12:cudaMalloc")
int BPF_KPROBE(cuda_malloc_hook, void **address, size_t size)
{
    u64 id = bpf_get_current_pid_tgid();
    malloc_data_t *data = bpf_map_lookup_elem(&malloc_info, &id);
    u64 call_time = bpf_ktime_get_ns();
    if (data) {
        data->address = address;
        data->size = size;
        data->call_time = call_time;
    } else {
        malloc_data_t newdata = { .address = address, .size = size, .call_time = call_time };
        bpf_map_update_elem(&malloc_info, &id, &newdata, BPF_NOEXIST);
    }

    return 0;
}

SEC("uretprobe//usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12:cudaMalloc")
int BPF_KRETPROBE(cuda_malloc_ret_hook, long ret)
{
    if (ret != 0) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    malloc_data_t *data = bpf_map_lookup_elem(&malloc_info, &id);
    if (!data) {
        return 0;
    }

    meminfo_t info = { .pid = id >> 32, .size = data->size, .duration = bpf_ktime_get_ns() - data->call_time };

    bpf_probe_read_user(&info.address, sizeof(info.address), data->address);
    bpf_ringbuf_output(&memperf_output, &info, sizeof(info), 0);

    return 0;
}

SEC("uprobe//usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12:cudaFree")
int BPF_KPROBE(cuda_free_hook, void *address)
{
    u64 id = bpf_get_current_pid_tgid();
    meminfo_t info = { .pid = id >> 32, .address = (u64) address };
    bpf_ringbuf_output(&memperf_output, &info, sizeof(info), 0);
    return 0;
}

SEC("uprobe//usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12:cudaMemcpyAsync")
int BPF_KPROBE(cuda_memcpy_async_hook, void *dst, void *src, size_t count, int kind, void *stream)
{
    char *kind_str = NULL;
    switch (kind) {
    case 0:
        kind_str = "host2host";
        break;
    case 1:
        kind_str = "host2device";
        break;
    case 2:
        kind_str = "device2host";
        break;
    case 3:
        kind_str = "device2device";
        break;
    case 4:
        kind_str = "default";
        break;
    default:
        kind_str = "invalid";
        break;
    }
    // bpf_printk("cudaMemcpyAsync copy %d bytes %lx -> %lx", count, src, dst);
    // bpf_printk("cudaMemcpyAsync type %s stream %lx", kind_str, stream);
    return 0;
}

SEC("uprobe//usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12:cudaStreamSynchronize")
int BPF_KPROBE(cuda_stream_sync_hook, void *stream)
{
    // bpf_printk("cudaStreamSynchronize called stream=%lx", stream);
    return 0;
}

SEC("uretprobe//usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12:cudaStreamSynchronize")
int BPF_KRETPROBE(cuda_stream_sync_ret_hook)
{
    u64 stream = PT_REGS_PARM1(ctx);
    // bpf_printk("cudaStreamSynchronize returned stream=%lx", stream);
    return 0;
}
#endif
