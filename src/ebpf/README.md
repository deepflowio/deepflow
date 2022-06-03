# libebpf

这是一个利用eBPF技术来获取数据的支持库项目，它可以利用非常简洁接口调用来从内核或应用程序中获取的任何有价值的数据。

提供Rust语言接口。

内核版本支持: `Linux 4.14+`

## 如何使用

### 编译与测试

```bash
#! /bin/bash

# 生成libebpf.a，ebpf kernel elf文件，命令行工具metaflow-ebpfctl
make clean && make --no-print-directory && make tools --no-print-directory

# rust 样例
make install && make rust-sample # 安装ebpf kernel elf文件，并生成rust样例
./samples/rust/target/release/rust_sample # 运行rust样例
```

### rust如何调用？

- 修改Cargo.toml (参考：samples/rust/Cargo.toml)

```toml
[package]
...
build = "build.rs" # build.rs文件路径

[build-dependencies]
dunce = "0.1.1" # build.rs引用

[dependencies]
libc = "0.2" # src/libebpf.rs使用
``` 
- 添加build.rs

```rust
// 参考: samples/rust/build.rs
use std::error::Error;
extern crate dunce;
use std::{env, path::PathBuf};

// 用于在rust编译时指定libebpf.a进行连接
fn set_build_libebpf() -> Result<(), Box<dyn Error>> {
    let library_name = "ebpf";
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let library_dir = dunce::canonicalize(root.join("../../")).unwrap(); // 填写libebpf.a所在目录
    println!("cargo:rustc-link-lib=static={}", library_name);
    println!(
        "cargo:rustc-link-search=native={}",
        env::join_paths(&[library_dir]).unwrap().to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=elf");
    println!("cargo:rustc-link-lib=dylib=z");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    set_build_libebpf()?;
    Ok(())
}
```
- Rust FFI接口(把文件samples/rust/src/ebpf.rs.sample拷贝到项目相应目录更改名称为ebpf.rs)
```rust
// samples/rust/src/ebpf.rs.sample
extern crate libc;
pub use libc::c_char;
pub use libc::c_int;
pub use libc::c_uchar; //u8
pub use libc::c_uint;
pub use std::ffi::{CStr, CString}; //u32

//方向
#[allow(dead_code)]
pub const SOCK_DIR_SND: u8 = 0;
#[allow(dead_code)]
pub const SOCK_DIR_RCV: u8 = 1;

//socket协议类型
#[allow(dead_code)]
pub const SOCK_DATA_UNKNOWN: u16 = 0;
#[allow(dead_code)]
pub const SOCK_DATA_HTTP1: u16 = 20;
#[allow(dead_code)]
pub const SOCK_DATA_HTTP2: u16 = 21;
#[allow(dead_code)]
pub const SOCK_DATA_MYSQL: u16 = 60;
#[allow(dead_code)]
pub const SOCK_DATA_DNS: u16 = 120;
#[allow(dead_code)]
pub const SOCK_DATA_REDIS: u16 = 80;
#[allow(dead_code)]
pub const SOCK_DATA_KAFKA: u16 = 100;
#[allow(dead_code)]
pub const SOCK_DATA_DUBBO: u16 = 40;

//消息类型
#[allow(dead_code)]
pub const MSG_REQUEST: u8 = 1;
#[allow(dead_code)]
pub const MSG_RESPONSE: u8 = 2;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tuple_t {
    pub raddr: [u8; 16usize], // 远端IP地址
    pub laddr: [u8; 16usize], // 本地IP地址
    pub addr_len: u8,         // IP地址长度，4：IPV4地址，6：IPV6地址
    pub protocol: u8,         // 协议
    pub rport: u16,           // 远端端口
    pub lport: u16,           // 本地端口
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SK_BPF_DATA {
    /* session info */
    pub process_id: u32,       // 进程ID，对应内核tgid
    pub thread_id: u32,        // 线程ID，对应内核pid
                               // 如果process_id等于thread_id说明是一个进程，否则是一个线程
    pub process_name: [u8; 16usize], //进程名字，占用16bytes

    pub tuple: tuple_t,        // Socket五元组信息
    pub socket_id: u64,        // Socket的唯一标识，从启动时的时钟开始自增1，可用此做hash key代替五元组。
    pub l7_protocal_hint: u16, // 应用数据（cap_data）的协议，取值：SOCK_DATA_*（在上面定义）
                               // 存在一定误判性（例如标识为A协议但实际上是未知协议，或标识为多种协议），上层应用应继续深入判断
    pub msg_type: u8,          // 信息类型，值为MSG_REQUEST(1), MSG_RESPONSE(2), 需要应用层分析进一步确认。
    pub need_reconfirm: bool,  // true: 表示eBPF程序对L7协议类型的判断并不确定需要上层重新核实。
                               // false: 表示eBPF程序对L7协议类型的判断是有把握的不需要上层重新核实。
    /* trace info */
    pub tcp_seq: u64, // 收发cap_data数据时TCP协议栈将会用到的TCP SEQ，可用于关联eBPF DATA与网络中的TCP Packet
    /*
     * 应用数据的追踪ID，应用于数据转发，L7代理、应用层负载均衡等场景。
     * 值：
     *     从启动时的时钟开始自增1
     * 实现原理：
     *     当应用程序从socket读取数据（Ingress）时，会在hash中做记录
     *       key: 线程ID/进程ID，
     *       Value: UID（追踪的唯一标识ID）
     *     而当向socket写数据（Egress），使用key（线程ID/进程ID）进行查询，从而获得一个先前记录的UID
     *     这样就会和先前的socket ingress的数据关联起来了，从而对同一协程（线程/进程）在不同socket
     *     间的数据转发进行追踪。
     *
     * 注意：
     *     上层经过协议分析得到数据的具体类型：请求/回应，
     *     请求/回应都有各自不同的syscall_trace_id_call。
     */
    pub syscall_trace_id_call: u64,

    /* data info */
    pub timestamp: u64,        // cap_data获取的时间戳（从1970.1.1开始到数据捕获时的时间间隔，精度为微妙）
    pub direction: u8,         // 数据的收发方向，值是 SOCK_DIR_SND/SOCK_DIR_RCV

    /*
     * 说明：
     *
     * 当syscall读写数据过大时，eBPF并不会读取所有数据而是有一个最大读取数据大小的限制，
     * 这个长度限制是512字节。
     */
    pub syscall_len: u64,      // 本次系统调用读、写数据的总长度
    pub cap_len: u32,          // 返回的cap_data长度
    pub cap_seq: u64,          // cap_data在Socket中的相对顺序号，在所在socket下从0开始自增，用于数据乱序排序
    pub cap_data: *mut c_char, // 内核送到用户空间的数据地址
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SK_TRACE_STATS {
    /*
     * 每一次系统调用向socket读/写数据，都会被eBPF获取，并把此次的
     * 数据传递给用户态接收程序
     * 约定: 把通过eBPF获取一次socket读/写的数据称作'SockData'，
     * 一个‘SockData’包含描述头和数据两部分。
     */

    /*
     * eBPF统计
     */
     pub perf_pages_count: u32,     // perf buffer内存占用的页数量
     pub kern_lost: u64,            // perf buffer数据用户态程序来不及接收数据，造成的SockData丢失数量
     pub kern_socket_map_max: u32,  // socket追踪的hash表项最大值
     pub kern_socket_map_used: u32, // socket追踪的hash表项当前值
     pub kern_trace_map_max: u32,  // 线程/协程追踪会话的hash表项最大值
     pub kern_trace_map_used: u32, // 线程/协程追踪会话的hash表项当前值

     /*
      * 数据处理统计
      */
     pub worker_num: u16,           // 处理数据的工作线程数量
     pub queue_capacity: u32,       // 单队列容量
     pub mem_alloc_fail_count: u64, // 内存申请（用于为burst-SockDatas申请一块内存）失败次数统计
     pub user_enqueue_count: u64,   // 用户态程序收到内核传过来的入队列的SockData数量
     pub user_dequeue_count: u64,   // 用户态程序处理的SockData数量
     pub user_enqueue_lost: u64,    // 由于队列没有空闲空间使得入队列失败而造成的SockData丢失数量
     pub queue_burst_count: u64,    // 通过burst方式进行入队列和出队列，这里统计burst（16个SockData）的次数。
     pub socket_map_max_reclaim: u32, // socket map表项进行清理的最大阈值，
                                      // 当前map的表项数量超过这个值进行map清理操作。
     /*
      * tracer 当前状态
      */
     pub is_adapt_success: bool,    // 适配状态：内核适配成功为true，否则为false
     pub tracer_state: u8           // 追踪器当前状态。值：TRACER_INIT, TRACER_STOP，TRACER_RUNNING
}

extern "C" {
    // 初始化tracer用于设置eBPF环境初始化。
    // 参数：
    //   log_file  日志文件路径，如果是传递一个空指针将不会有日志写到文件。
    //   is_stdout 日志是否输出到标准输出，true 写到标准输出，false 不写到标准输出。
    // 返回值：
    //   成功返回0，否则返回非0
    pub fn bpf_tracer_init(log_file: *const i8, is_stdout: bool) -> c_int;

    // 所有trace启动完毕后，最后显示调用bpf_tracer_finish()来通知主程序。
    pub fn bpf_tracer_finish();

    // 获取socket_tracer的这种统计数据的接口
    pub fn socket_tracer_stats() -> SK_TRACE_STATS;

    // 参数说明：
    // callback: 回调接口 rust -> C
    // thread_nr: 工作线程数，是指用户态有多少线程参与数据处理。
    // perf_pages_cnt: 和内核共享内存占用的页框数量, 值为2的次幂。
    // ring_size: 环形缓存队列大小，值为2的次幂。
    // max_socket_entries: 设置用于socket追踪的hash表项最大值，取决于实际场景中并发请求数量。
    // max_trace_entries: 设置用于线程/协程追踪会话的hash表项最大值。
    // socket_map_max_reclaim: socket map表项进行清理的最大阈值，当前map的表项数量超过这个值进行map清理操作。
    // log_file: 日志文件路径
    // 返回值：成功返回0，否则返回非0
    pub fn running_socket_tracer(
        callback: extern "C" fn(sd: *mut SK_BPF_DATA),
        thread_nr: c_int,
        perf_pages_cnt: c_uint,
        ring_size: c_uint,
        max_socket_entries: c_uint,
        max_trace_entries: c_uint,
        socket_map_max_reclaim: c_uint,
        log_file: *const i8
    ) -> c_int;

    // 停止 tracer运行
    // 返回值：成功返回0，否则返回非0
    pub fn tracer_stop() -> c_int;

    // 启动 tracer运行
    // 返回值：成功返回0，否则返回非0
    pub fn tracer_start() -> c_int;

    // 注意：eBPF tracer初始化加载运行后进行内核适配，
    // 适配完成后马上进入stop状态，需调用tracer_start()才开始工作。
}
```
- 在samples/rust/src/lib.rs中添加
```rust
pub mod ebpf;
```
- 调用样例代码(参考：samples/rust/src/main.rs)
```rust
use rust_sample::ebpf::*; // 注意这个地方的rust_sample换成实际项目Cargo.toml中[package]项配置的name的内容。 

extern "C" fn socket_trace_callback(sd: *mut SK_BPF_DATA) {
	unsafe {
		... ...	
	}
}

fn main() {
	let log_file = CString::new("/var/log/metaflow-ebpf.log".as_bytes()).unwrap();
	let log_file_c = log_file.as_c_str();
	unsafe {
            // 第一个参数空指针传递可以填写std::ptr::null()
            if bpf_tracer_init(log_file_c.as_ptr(), true) != 0 {
           	println!("bpf_tracer_init() file:{:?} error", log_file);
           	::std::process::exit(1);
       	    }

            if running_socket_tracer(
                socket_trace_callback, /* 回调接口 rust -> C */
                1,                     /* 工作线程数，是指用户态有多少线程参与数据处理 */
                128,                    /* 内核共享内存占用的页框数量, 值为2的次幂。用于perf数据传递 */
                65536,                 /* 环形缓存队列大小，值为2的次幂。e.g: 2,4,8,16,32,64,128 */
                524288, /* 设置用于socket追踪的hash表项最大值，取决于实际场景中并发请求数量 */
                524288, /* 设置用于线程/协程追踪会话的hash表项最大值。*/
                520000 /* socket map表项进行清理的最大阈值，当前map的表项数量超过这个值进行map清理操作 */
            ) != 0 {
                println!("running_socket_tracer() error.");
                ::std::process::exit(1);
            }

            // 完成所有bpf tracer调用bpf_tracer_finish()
            bpf_tracer_finish();
	}

	... ...
}
```
![image](https://gitlab.yunshan.net/platform/ebpf-http/-/wikis/uploads/c0771d31c016173ad47d3a3cda3f02c3/image.png)

## 管理工具

`metaflow-ebpfctl` 命令行工具用于管理bpf tracer。

```bash
$metaflow-ebpfctl
Usage:
    metaflow-ebpfctl [OPTIONS] OBJECT { COMMAND | help }
Parameters:
    OBJECT  := { tracer socktrace }
    COMMAND := { show }
Options:
    -v, --verbose
    -h, --help
    -V, --version
    -C, --color
```

例如：

```bash
./metaflow-ebpfctl tracer show
Tracer         socket-tracer
Bpf File       /usr/share/metaflow-agent//linux-common/socket_trace.elf
Workers        4 # 标识有几个线程处理
Events Lost    0 # 事件丢失标识应用没有来得及接收而丢失的事件数量。

-------------------- Queue ---------------------------
worker 0 for queue, de 9095 en 9095 lost 0 alloc faild 0 burst 4 queue size 0 cap 16383
worker 1 for queue, de 9254 en 9254 lost 0 alloc faild 0 burst 3 queue size 0 cap 16383
worker 2 for queue, de 9291 en 9291 lost 0 alloc faild 0 burst 4 queue size 0 cap 16383
worker 3 for queue, de 9165 en 9165 lost 0 alloc faild 0 burst 0 queue size 0 cap 16383

SUM dequeue 36805 enqueue 36805, lost 0, alloc faild 0 burst count 11

-------------------- Protocol ------------------------
- HTTP       11421
- DNS        25274
- Redis      110


./metaflow-ebpfctl socktrace show # 列出内核自动推断的偏移量

Linux Version: 4.15.15-1.el7.x86_64

kern_socket_map_max:	524288
kern_socket_map_used:	6
kern_trace_map_max:	524288
kern_trace_map_used:	6

CPUs: 24
----------------------------------
cpu: 	23
ready: 	1
task__files_offset: 	0xb00
sock__flags_offset: 	0x1f0
socket__has_wq_ptr: 	0x0(no use)
tcp_sock__copied_seq_offset: 	0x514
tcp_sock__write_seq_offset: 	0x674
```
## Event Profiling

You can check the total number of probe hits and probe miss-hits via

`/sys/kernel/debug/tracing/kprobe_profile`.

The first column is event name, the second is the number of probe hits,the third is the number of probe miss-hits.

## 资源消耗和影响

### 环境

**测试目标机器**

双路CPU Intel(R) Xeon(R) CPU E5-2630 0 @ 2.30GHz

每颗CPU 6 core，CPU线程数为2，一共24个逻辑核心。

### 基线

基线是在没有eBPF tracer的情况下运行基准测试。

- CPU: 运行机器的百分比
- RPS: 每秒能处理的请求数目
- 响应时间 单位: 毫秒

### 运行eBPF tracer

使用基线收集相同的指标。

### 资源消耗

Cost = Running with tracer - Baseline

### 监控工具

prometheus + grafana

### Benchmarks

Benchmark-1


目标机器运行Nginx，使用

` wrk -t10 -c100 -d 600s http://测试目标IP/`

> 为了达到稳定的请求数量，对测试出接口进行了限速。

![image](https://gitlab.yunshan.net/platform/ebpf-http/-/wikis/uploads/f969a24f3d69932c9c00020b787dd54a/image.png)

- 基线测试数据

![image](https://gitlab.yunshan.net/platform/ebpf-http/-/wikis/uploads/fa5459b6ff32fc4047f68832a40216b1/image.png)
```
# wrk -t10 -c100 -d 600s http://2.2.2.25/
Running 10m test @ http://2.2.2.25/
  10 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    34.79ms   80.34ms   1.70s    86.97%
    Req/Sec     5.09k     1.16k   26.01k    68.15%
  30358967 requests in 10.00m, 143.43GB read
  Socket errors: connect 0, read 0, write 0, timeout 1
Requests/sec:  50589.85
Transfer/sec:    244.75MB
```

- 运行eBPF测试数据

![image](https://gitlab.yunshan.net/platform/ebpf-http/-/wikis/uploads/5a36e76b46ec0480dcc935dc88401ca5/image.png)
```
# wrk -t10 -c100 -d 600s http://2.2.2.25/
Running 10m test @ http://2.2.2.25/
  10 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    33.53ms   77.37ms   1.70s    86.80%
    Req/Sec     5.08k     1.14k    9.06k    67.30%
  30331892 requests in 10.00m, 143.31GB read
  Socket errors: connect 0, read 0, write 0, timeout 1
Requests/sec:  50544.73
Transfer/sec:    244.53MB
```

请求数量达到50000时，CPU消耗在70%左右, 在我们的测试机器（24逻辑核心）上消耗占比在`3%`左右。

## eBPF与内核版本

|eBPF特性|值|内核版本|备注|
|-------|-------|--|-|
|指令数量限制|98304|< 4.14|BPF_COMPLEXITY_LIMIT_INSNS|
||131072|4.14 ~ 5.2||
||1000000|5.2+|1M insns|
|全局变量||5.5+||
|BPF ring buffer||5.8+||
|BTF, CO-RE||5.3+||

- BPF Features by Linux Kernel Version
  https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md

## 已测试内核版本
- 4.14.x
  - 4.14.0, 4.14.10, 4.14.11, 4.14.1, 4.14.12, 4.14.13, 4.14.14, 4.14.15, 4.14.2, 4.14.3, 4.14.4, 4.14.5, 4.14.6, 4.14.7, 4.14.8, 4.14.9
- 4.15.x
  - 4.15.0, 4.15.1, 4.15.10, 4.15.11, 4.15.12, 4.15.13, 4.15.14, 4.15.15, 4.15.2, 4.15.3, 4.15.4, 4.15.5, 4.15.6, 4.15.7, 4.15.8, 4.15.9
- 4.16.x
  - 4.16.0, 4.16.1, 4.16.10, 4.16.11, 4.16.12,4.16.13, 4.16.2, 4.16.3, 4.16.4, 4.16.5, 4.16.6, 4.16.7, 4.16.8, 4.16.9
- 4.17.x
  - 4.17.0, 4.17.1, 4.17.10, 4.17.11,4.17.12, 4.17.13, 4.17.14, 4.17.2, 4.17.3, 4.17.4, 4.17.5, 4.17.6, 4.17.8, 4.17.9 
- 4.18.x
  - 4.18.0, 4.18.1, 4.18.10,4.18.11, 4.18.12, 4.18.13, 4.18.14, 4.18.15, 4.18.16, 4.18.3, 4.18.4, 4.18.5, 4.18.6, 4.18.7, 4.18.8, 4.18.9
- 4.19.x
  - 4.19.0, 4.19.1, 4.19.10, 4.19.11, 4.19.12, 4.19.2, 4.19.3, 4.19.4, 4.19.5, 4.19.6, 4.19.7, 4.19.8, 4.19.9 
- 4.20.x
  - 4.20.0,4.20.1, 4.20.10, 4.20.11, 4.20.12, 4.20.13, 4.20.2, 4.20.3, 4.20.4, 4.20.5, 4.20.6, 4.20.7, 4.20.8
- 5.0.x
  - 5.0.0, 5.0.0,5.0.1, 5.0.10, 5.0.11, 5.0.12, 5.0.13, 5.0.2, 5.0.3, 5.0.4, 5.0.5, 5.0.6, 5.0.7, 5.0.8, 5.0.9
- 5.1.x
  - 5.1.0, 5.1.1, 5.1.1,5.1.10, 5.1.11, 5.1.12, 5.1.14, 5.1.15, 5.1.16, 5.1.2, 5.1.3, 5.1.4, 5.1.5, 5.1.6, 5.1.7, 5.1.8, 5.1.9
- 5.2.x
  - 5.2.0, 5.2.1, 5.2.1, 5.2.10, 5.2.11, 5.2.12, 5.2.13, 5.2.14, 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9
- 5.3.x
  - 5.3.0, 5.3.1, 5.3.1, 5.3.10, 5.3.11, 5.3.12, 5.3.13, 5.3.2, 5.3.4, 5.3.5, 5.3.6, 5.3.7, 5.3.8, 5.3.9
- 5.4.x
  - 5.4.0, 5.4.1, 5.4.1, 5.4.10, 5.4.11, 5.4.12, 5.4.13, 5.4.14, 5.4.15, 5.4.2, 5.4.3, 5.4.4, 5.4.5, 5.4.6, 5.4.7, 5.4.8
- 5.5.x
  - 5.5.0, 5.5.1, 5.5.10, 5.5.11, 5.5.12, 5.5.13, 5.5.2, 5.5.3, 5.5.4, 5.5.5, 5.5.6, 5.5.6, 5.5.7, 5.5.8, 5.5.9
- 5.6.x
  - 5.6.0, 5.6.1, 5.6.10, 5.6.11, 5.6.12, 5.6.13, 5.6.14, 5.6.15, 5.6.2, 5.6.3, 5.6.4, 5.6.5, 5.6.6, 5.6.7, 5.6.8, 5.6.9
- 5.7.x
  - 5.7.0, 5.7.1, 5.7.10, 5.7.11, 5.7.12, 5.7.2, 5.7.3, 5.7.4, 5.7.5, 5.7.6, 5.7.7, 5.7.8, 5.7.9
- 5.8.x
  - 5.8.0, 5.8.1, 5.8.10, 5.8.11, 5.8.12, 5.8.13, 5.8.14, 5.8.2, 5.8.3, 5.8.4, 5.8.5, 5.8.6, 5.8.7, 5.8.8, 5.8.9
- 5.9.x
  - 5.9.0, 5.9.1, 5.9.10, 5.9.11, 5.9.12, 5.9.13, 5.9.14, 5.9.2, 5.9.3, 5.9.5, 5.9.6, 5.9.7, 5.9.8, 5.9.9
- 5.10.x
  - 5.10.0, 5.10.1, 5.10.10, 5.10.11, 5.10.12, 5.10.13, 5.10.14, 5.10.15, 5.10.16, 5.10.2, 5.10.3, 5.10.4, 5.10.5, 5.10.6, 5.10.7, 5.10.8, 5.10.9
- 5.11.x
  - 5.11.0, 5.11.1, 5.11.10, 5.11.11, 5.11.12, 5.11.13, 5.11.14, 5.11.15, 5.11.16, 5.11.2, 5.11.3, 5.11.4, 5.11.5, 5.11.6, 5.11.7, 5.11.8, 5.11.9
- 5.12.x
  - 5.12.0, 5.12.1, 5.12.10, 5.12.11, 5.12.12, 5.12.13, 5.12.2, 5.12.3, 5.12.4, 5.12.9
- 5.13.x
  - 5.13.0, 5.13.1, 5.13.2, 5.13.3, 5.13.4, 5.13.5, 5.13.6, 5.13.7, 5.13.8
- 5.14.x
  - 5.14.0, 5.14.1, 5.14.2, 5.14.3, 5.14.4, 5.14.5, 5.14.6, 5.14.7, 5.14.8, 5.14.9, 5.14.9, 5.14.10, 5.14.11, 5.14.12, 5.14.13, 5.14.14, 5.14.15
- 5.15.x
  - 5.15.0, 5.15.1, 5.15.2, 5.15.3, 5.15.4, 5.15.5, 5.15.6, 5.15.7, 5.15.8, 5.15.10, 5.15.11, 5.15.12, 5.15.13
- 5.16.x
  - 5.16.0, 5.16.1, 5.16.2, 5.16.4, 5.16.5, 5.16.6, 5.16.7 
