# OFF-CPU Profiler
## eBPF prog
### hooks

整体上使用了两个hook点：

```
schedule() -> trace_sched_switch -> switch_to() -> finish_task_switch()
               (oncpu old task)    stack switch      (oncpu new task)

```

- trace_sched_switch
  - 过滤
    - idle调度任务过滤
    - 只关心TASK_INTERRUPTIBLE (0x01) or TASK_UNINTERRUPTIBLE (0x02)
  - 记录
    - 记录prev task的信息，offcpu开始时间
- finish_task_switch
  - 计算offcpu的时间
  - offCPU的时间检查
    - 'MINBLOCK_US' offCPU的时间太短我们可以过滤掉，这个时间可配置，用于降低消耗。
    - 'MAXBLOCK_US' 作用类似最小值也是起到过滤掉较长的堵塞事件，进一步降低开销。默认值是1小时
       实际上如果一个任务超过一个小时还没有调度回来，极大可能他永远也调度不回来了（我们获取的是能调度回来的任务的数据)，实际上我们分析1小时之内的调度任务已经可以说明问题，超过一小时可能永远得不到这样的数据。
  - 调用栈等信息获取并推送给用户态程序。

## 性能优化

为了减少事件数量，降低对系统性能的影响，进行了下面优化:

- idle调度任务过滤
- 只处理状态为`TASK_INTERRUPTIBLE (0x01)` 和 `TASK_UNINTERRUPTIBLE (0x02)`进程
- 只处理匹配的进程
  - 用户态程序会依据进程名字的正则匹配结果，利用进程信息的管理模块通知Off-cpu eBPF Prog进行进程过滤。
- 使用`MINBLOCK_US`和`MAXBLOCK_US`配置

## 配置信息
```
    ## Java compliant update latency time
    ## Default: 600s. Range: [5, 3600]s
    ## Note:
    ##   When deepflow-agent finds that an unresolved function name appears in the function call stack
    ##   of a Java process, it will trigger the regeneration of the symbol file of the process.
    ##   Because Java utilizes the Just-In-Time (JIT) compilation mechanism, to obtain more symbols for
    ##   Java processes, the regeneration will be deferred for a period of time.
    #java-symbol-file-refresh-defer-interval: 600s

    ## on-cpu profile configuration
    #on-cpu-profile:
      ## eBPF on-cpu Profile Switch
      ## Default: false
      #disabled: false

      ## Sampling frequency
      ## Default: 99
      #frequency: 99

      ## Whether to obtain the value of CPUID and decide whether to participate in aggregation.
      ## Set to 1:
      ##    Obtain the value of CPUID and will be included in the aggregation of stack trace data.
      ## Set to 0:
      ##    It will not be included in the aggregation. Any other value is considered invalid,
      ##    the CPU value for stack trace data reporting is a special value (CPU_INVALID:0xfff)
      ##    used to indicate that it is an invalid value.
      ## Default: 0
      #cpu: 0

      ## Sampling process name
      ## Default: ^deepflow-.*
      #regex: ^deepflow-.*

    ## off-cpu profile configuration
    #off-cpu-profile:
      ## eBPF off-cpu Profile Switch
      ## Default: false
      #disabled: false

      ## Sampling process name
      ## Default: ^deepflow-.*
      #regex: ^deepflow-.*

      ## Configure the minimum blocking event time
      ## Default: 50us. Range: [1, 2^32-1)us
      ## Note:
      ##   Scheduler events are still high-frequency events, as their rate may exceed 1 million events
      ##   per second, so caution should still be exercised.
      ##   If overhead remains an issue, you can configure the 'minblock' tunable parameter here.
      ##   If the off-CPU time is less than the value configured in this item, the data will be discarded.
      ##   If your goal is to trace longer blocking events, increasing this parameter can filter out shorter
      ##   blocking events, further reducing overhead. Additionally, we will not collect events with a block
      ##   time exceeding 1 hour.
      #minblock: 50us
```
- 具体差异可以看[这里](https://github.com/deepflowio/deepflow/pull/5943/files)
- 开放接口
  ```
    pub fn enable_offcpu_profiler() -> c_int;
    pub fn disable_offcpu_profiler() -> c_int;
    pub fn enable_oncpu_profiler() -> c_int;
    pub fn disable_oncpu_profiler() -> c_int;
    pub fn set_offcpu_minblock_time(
        block_time: c_uint,
    ) -> c_int;

  ```
  - 返回值：
    - 上所有接口的返回值 0为成功，非0为错误。
- 配置和接口调用
  - `java-symbol-file-refresh-defer-interval` 配置项位置从`on-cpu-profile`拿出来放在外层了。因为它对`on-cpu profiler`和`off-cpu profiler`都起作用。
  - 之前的`on-cpu-profile`下面的`disabled: true`时会关闭整个可持续剖析（即：不会调用任何开放的`C`接口），添加`off-cpu profiler`之后，条件需要变动一下，只有`on-cpu`和`on-cpu`同时配置了`disabled: true`时才关闭整个可持续剖析。
  - 配置项对应的调用接口
    - `on-cpu-profile` > `disabled`
      - true : 调用接口`enable_oncpu_profiler()`
      - false : 调用接口`disable_oncpu_profiler()`
      - 上面两个接口调用位置先于`start_continuous_profiler()`的调用
    - `off-cpu-profile` > `disabled`
      - true : 调用接口`enable_offcpu_profiler()`
      - false : 调用接口`disable_offcpu_profiler()`
      - 上面两个接口调用位置先于`start_continuous_profiler()`的调用
    - `off-cpu-profile` > `minblock`
      - 调用`set_offcpu_minblock_time()`
- 数据结构调整
  - `on-cpu profiler`和`off-cpu profiler`使用同一个结构存放数据。
    ```rust
    pub struct stack_profile_data {
        pub profiler_type : u8, // Profiler type, such as 1(PROFILER_TYPE_ONCPU).
        pub timestamp: u64, // Timestamp of the stack trace data(unit: nanoseconds).
        pub pid: u32,       // User-space process-ID.
        /*
         * Identified within the eBPF program in kernel space.
         * If the current is a process and not a thread this field(tid) is filled
         * with the ID of the process.
         */
        pub tid: u32,
        pub stime: u64,      // The start time of the process is measured in milliseconds.
        pub netns_id: u64,   // Fetch from /proc/<PID>/ns/net
        pub u_stack_id: u32, // User space stackID.
        pub k_stack_id: u32, // Kernel space stackID.
        pub cpu: u32,        // The captured stack trace data is generated on which CPU?
        /*
         * The profiler captures the sum of durations of occurrences of the same
         * data by querying with the quadruple
         * "<pid + stime + u_stack_id + k_stack_id + tid + cpu>" as the key.
         * In microseconds as the unit of time.
         */
        pub count: u32,
        /*
         * comm in task_struct(linux kernel), always 16 bytes
         * If the capture is a process, fill in the process name here.
         * If the capture is a thread, fill in the thread name.
         */
        pub comm: [u8; PACKET_KNAME_MAX_PADDING + 1],
        pub process_name: [u8; PACKET_KNAME_MAX_PADDING + 1], // process name
        pub container_id: [u8; CONTAINER_ID_SIZE],            // container id
        pub stack_data_len: u32,                              // stack data length
    
        /*
         * Example of a folded stack trace string (taken from a perf profiler test):
         * main;xxx();yyy()
         * It is a list of symbols corresponding to addresses in the underlying stack trace,
         * separated by ';'.
         *
         * The merged folded stack trace string style for user space and kernel space would be:
         * <user space folded stack trace string> + ";" + <kernel space folded stack trace string>
         */
        pub stack_data: *mut c_char,
    }
    
    ```
  - 新增了`profiler_type`来表示数据类型, 它的值：
    - 0 PROFILER_TYPE_UNKNOWN
    - 1 PROFILER_TYPE_ONCPU
    - 2 PROFILER_TYPE_OFFCPU
  - 扩充了`count`的含义
    - 如果是`on-cpu profiler` 表示采样的个数
    - 如果是`off-cpu profiler` 表示脱离cpu的时间，单位是微秒

## 配置项测试
earth上测试数据参考：
- 系统负载
```
 load average: 8.00, 7.74, 8.11
Tasks: 803 total,   1 running, 686 sleeping,   1 stopped,   2 zombie
```
- 条件：
（1）过滤idle数据  
（2）只采集状态是可中断睡眠和中断睡眠的 
（3）必须拥有用户态栈数据
- 采集时间 ：418秒
- minblock设置值对应采集数量表
```
minblock    total count    count/s
-----------------------------------
10us         2725944          6530
50us         2539749          6084
100us        2086731          4996
200us        1717429          4110
500us        1516044          3624
1ms          1406533          3365
2ms          1017952          2436
3ms          891649           2134
5ms          780035           1868
10ms         563226           1349
20ms         228008           545
50ms         182473           437
100ms        118454           283
1s           40945            98
10s          7683             18
```

- off-cpu时间对应数据数量（前50）：
```
     数量     off-cpu时间(us)      
--------------------
   12721      89
   12633      88
   12623      90
   12509      87
   12260      86
   11983      91
   11719      92
   11614      85
   11557      93
   11187      94
   11163      84
   10836      95
   10728      82
   10675      83
   10639      81
   10376      68
   10244      96
   10042      69
    9934      97
    9859      80
    9800      77
    9785      76
    9758      75
    9716      78
    9607      98
    9604      79
    9568      74
    9377      67
    9348      70
    9295      73
    9141      99
    9001      71
    8994      72
    8917     100
    8537     101
    8493      66
    8155     102
    7991      65
    7874     103
    7666      64
    7543     105
    7521     104
    7357     106
    7356      63
    7015     107
    6938     108
    6914      62
    6794     109
    6744     110
    6630      61
```
## 性能消耗
- minblock设置为10us
- oncpu regex : `^(profiler|socket_tracer|java|deepflow-.*)$`
- offcpu regex : `^(profiler|socket_tracer|java|deepflow-.*)$`
- `profiler`为运行的自身程序
### cpu消耗 

```
top - 08:04:34 up 3 days,  8:59, 23 users,  load average: 13.95, 12.07, 10.49
Threads:  15 total,   0 running,  15 sleeping,   0 stopped,   0 zombie
%Cpu(s): 22.2 us, 19.4 sy,  3.8 ni, 53.2 id,  0.7 wa,  0.0 hi,  0.8 si,  0.0 st
KiB Mem : 65866528 total,   624656 free, 41419796 used, 23822076 buff/cache
KiB Swap:        0 total,        0 free,        0 used. 23958764 avail Mem 

  PID USER      PR  NI    VIRT    RES    SHR S %CPU %MEM     TIME+ COMMAND                                                                                                                                        
13467 root      20   0   13.7g 165556  16460 S  6.0  0.3   0:15.09 sk-reader-0                                                                                                                                    
13584 root      20   0   13.7g 165556  16460 S  3.3  0.3   0:42.79 oncpu_reader-0                                                                                                                                 
13585 root      20   0   13.7g 165556  16460 S  3.0  0.3   0:28.88 offcpu_reader-1                                                                                                                                
12433 root      20   0   13.7g 165556  16460 S  0.3  0.3   0:01.16 period-process                                                                                                                                 
12428 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:02.88 profiler                                                                                                                                       
12429 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.00 profiler                                                                                                                                       
12430 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.00 profiler                                                                                                                                       
12431 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.00 ctrl-main                                                                                                                                      
12432 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.00 profiler                                                                                                                                       
12434 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.00 profiler                                                                                                                                       
12435 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.00 profiler                                                                                                                                       
12438 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.00 profiler                                                                                                                                       
13466 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.00 queue-worker                                                                                                                                   
13468 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.08 proc-events                                                                                                                                    
13580 root      20   0   13.7g 165556  16460 S  0.0  0.3   0:00.18 java_update 
```

上面的`oncpu_reader-0`和`offcpu_reader-1`在稳定运行之后大于消耗都在`5%`以内。

### 内存消耗
- offcpu & oncpu 都启用
```
cat /proc/22279/status | grep RSS
VmRSS:    162364 kB
```
- 只启用ofcpu
```
# cat /proc/28651/status | grep RSS
VmRSS:    159032 kB
```

内存方面offcpu & oncpu profiler会共享符号cache，所以内存增加会很少。

### offcpu 程序验证测试

off-cpu.c

```c
#include <stdio.h>
#include <time.h>

extern void delay_100_microseconds();
extern void delay_10_seconds();

int main() {
    delay_10_seconds();
    delay_10_seconds();
    delay_10_seconds();
    delay_10_seconds();
    delay_10_seconds();
    delay_10_seconds();
    printf("Start\n");
    delay_10_seconds();
    delay_10_seconds();
    int i;
    for(i = 0; i < 10; i++) {
        delay_100_microseconds();
    }
    delay_10_seconds();
    printf("End\n");
    return 0;
}
```

offcpu_lib.c

```c
#include <stdio.h>
#include <time.h>

// 定义一个延迟 100 微秒的函数
void __delay_100_microseconds()
{
    struct timespec ts;
    ts.tv_sec = 0;            // 秒
    ts.tv_nsec = 100000;      // 纳秒（100 微秒 = 100,000 纳秒）

    nanosleep(&ts, NULL);
    printf("delay 100us finish\n");
}

void delay_100_microseconds() {
        __delay_100_microseconds();
}

void delay_10_seconds() {
    struct timespec ts;
    ts.tv_sec = 10;            // 秒
    ts.tv_nsec = 0;      // 纳秒（100 微秒 = 100,000 纳秒）

    nanosleep(&ts, NULL);
    printf("delay 10s finish\n");
}
```

编译：

`gcc -fno-omit-frame-pointer -g -O0 off-cpu.c offcpu_lib.c -o off-cpu`

观察：

```
timestamp 1085396384446018 tgid 13129 pid 13129 comm off-cpu duration_us 151
timestamp 1085396384446018 tgid 13129 pid 13129 comm off-cpu duration_us 152
+ 152 , sum 303

timestamp 1085396384615326 tgid 13129 pid 13129 comm off-cpu duration_us 152
+ 152 , sum 455

timestamp 1085396384783169 tgid 13129 pid 13129 comm off-cpu duration_us 152
+ 152 , sum 607

timestamp 1085396384951017 tgid 13129 pid 13129 comm off-cpu duration_us 151
+ 151 , sum 758

timestamp 1085396385116295 tgid 13129 pid 13129 comm off-cpu duration_us 151
+ 151 , sum 909

timestamp 1085396385281010 tgid 13129 pid 13129 comm off-cpu duration_us 151
+ 151 , sum 1060

timestamp 1085396385446306 tgid 13129 pid 13129 comm off-cpu duration_us 151
+ 151 , sum 1211

timestamp 1085396385610970 tgid 13129 pid 13129 comm off-cpu duration_us 151
+ 151 , sum 1362

timestamp 1085396385776111 tgid 13129 pid 13129 comm off-cpu duration_us 152
+ 152 , sum 1514

```
+ --------------------------------- +

2024-05-21 00:42:43.278 [cpdbg] type 2 netns_id 4026532008 container_id null pid 13129 tid 13129 process_name off-cpu comm off-cpu stime 1716223281380 u_stack_id 23764 k_statck_id 50662 cpu 4095 count 1514 tiemstamp 1085396384275426 datalen 253 data [p] off-cpu;[l] __libc_start_main;main;delay_100_microseconds;[l] __nanosleep_nocancel;[k] entry_SYSCALL_64_after_hwframe;[k] do_syscall_64;[k] __x64_sys_nanosleep;[k] hrtimer_nanosleep;[k] do_nanosleep;[k] schedule;[k] __schedule;[k] finish_task_switch
+ --------------------------------- +

`count 1514` 即为聚合后的等待时间，单位为微秒。


另外需要注意的是：假如sleep 100us，得到是延迟值会比100us大，因为他有调度上的消耗，这个消耗大约在50us。
golang的程序很奇怪，假如sleep 100us, 总是照着1000us作为最小sleep单位，这可能是 golang本身实现有关，这个不好控制。


## 日志
- On-cpu profiler启用或关闭
  - `[eBPF] INFO [CP] === oncpu profiler enabled ===`
  - `[eBPF] INFO [CP] === oncpu profiler disabled ===`
- Off-cpu profiler启用或关闭
  - `[eBPF] INFO [OFFCPU] === offcpu profiler enabled ===`
  - `[eBPF] INFO [OFFCPU] === offcpu profiler disabled ===`
- Off-cpu `minblock` 设置
  - `[eBPF] INFO [OFFCPU] set_offcpu_minblock_time() success, g_min_block_us: 50`
- 进程符号表cache建立
  - ` [eBPF] INFO cache update PID 40609 NAME off-cpu`
- 把进程PID通知eBPF Prog,让其捕获数据
  - `[eBPF] INFO [OFFCPU] PID 40609 Process name 'off-cpu', successfully added to table '__offcpu_proc_filter_map'.`
- 取消eBPF对某个进程的数据获取
  - `[eBPF] INFO [OFFCPU] PID 40609 Process name 'off-cpu', successfully delete from table '__offcpu_proc_filter_map'.`

