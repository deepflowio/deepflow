# Golang Trace

## uretprobe

[Go 不支持 uretprobe](https://github.com/golang/go/issues/22008),
使用 uretprobe 会导致被 attach 的进程 crash,
使用普通的 uprobe 并 attach 到函数返回指令地址可以解决这个问题.

### 函数返回地址获取

函数返回地址的计算依赖:

1. 函数起始地址
2. 函数结束地址(或函数长度)
3. x86 字节流到指令的翻译

重点在于字节流到指令的翻译,在文件中读出的函数本质上是一个字节流,
需要将字节流翻译成对应的指令,才能确定函数返回指令,
如果不这样做可能导致其他指令中的一部分被误识别成返回指令.
因此当前实现仅支持 x86 架构.

## eBPF 中获取当前 Go 线程的协程号

### Hook 点

`runtime.casgstatus`

## Go TLS HTTP1

HTTP1 存在多个 hook 点, 一部分存在版本变化导致 hook 点失效的问题,又或者是不能拿到需要的原始报文.
结合已有的 HTTP1 解析实现,选择相对稳定的 TLS 加解密作为 hook 点,同时未来也可以支持 TLS 加密的其他协议(目前已经屏蔽,仅处理HTTP1)

### Go TLS HTTP1 Hook

* `crypto/tls.(*Conn).Write`
* `crypto/tls.(*Conn).Read`

这两个符号名在目前支持的 Go (1.13-1.18) 版本都有效.

## Go HTTP2

参考[uprobetracer](https://01.org/linuxgraphics/gfx-docs/drm/trace/uprobetracer.html)测试

没有导出符号,符号表里找不到,需要读调试信息

* `net/http.(*http2serverConn).writeHeaders`(new) <- `golang.org/x/net/http2.(*serverConn).writeHeaders`(old)
* `net/http.(*http2serverConn).processHeaders`(new) <- `golang.org/x/net/http2.(*serverConn).processHeaders`(old)
* `net/http.(*http2clientConnReadLoop).handleResponse`(new) <- `golang.org/x/net/http2.(*clientConnReadLoop).handleResponse`(old)
* `net/http.(*http2ClientConn).writeHeaders`(new) <- `golang.org/x/net/http2.(*ClientConn).writeHeaders`(old)
* `net/http.(*http2ClientConn).writeHeader`(new) <- `golang.org/x/net/http2.(*ClientConn).writeHeader`(old)
* `google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader`
* `google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders`
* `google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders`

### 从 net.Conn 到 net.TCPConn 或 crypto/tls.Conn

http2 和 grpc 都存在使用 tls (tls->tcp) 和不使用 tls (直接使用tcp)的情况,
在 golang 实现里, 他们的差异是 interface 对应的 struct 类型不同, 因此需要判断 interface 对应的 struct.

[深入研究 Go interface 底层实现](https://halfrost.com/go_interface/)介绍了 go interface 的内存布局,以及 go interface 到 struct 映射的方法.

```go
type iface struct {
	tab  *itab
	data unsafe.Pointer
}
```

简而言之,当确定了 tab 的值就可以确定某个 interface 对应的类型.
在 eBPF 中,可以从 uprobe 获取到 interface 的地址,再根据 iface 的结构获取到 tab.
由于 tab 在编译时确定, 所以所需类型(net.TCPConn,crypto/tls.Conn)对应的 tab 值要由上层应用下发到 eBPF.

上层应用可以读可执行文件的符号表获取 tab 值.

### 从 uprobe 获取 socket 信息

从进行操作的对象(对于go来说是函数的第一个结构体参数)中, 获取 socket 信息.
由于 interface 和继承 (对于go来说组合一个匿名结构体)的存在,这个过程会很复杂(可能会根据不同版本进行调整),
但本质上是从函数参数开始调整指针最终获取到需要的内存的过程.

0 到 4 是一组 http2 web 请求响应.
5 到 8 是一组 grpc 的请求响应.

需要注意,这里发送和接收的 tcp seq 对应不上,通过 tcpdump 抓包确认,
实际上在进入 read 类的函数的时候,已经完成了从 socket 读数据的步骤,
因此此时读到的序列号都是靠后的,或者说,向后偏移了原始 tcp 报文的长度.

```txt
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
1. http2ClientConn writeHeaders fd=[10] tcp_seq=[878799606]
2. http2serverConn processHeaders fd=[11] tcp_seq=[878799643]
3. http2serverConn writeHeaders fd=[11] tcp_seq=[2149142185]
4. http2clientConnReadLoop handleResponse fd=[10] tcp_seq=[2149142243]
5. grpc client write fd=[8] tcp_seq=[1539219396]
6. grpc server read fd=[9] tcp_seq=[1539219473]
7. grpc server write fd=[9] tcp_seq=[3867751365]
7. grpc server write fd=[9] tcp_seq=[3867751365]
8. grpc client read fd=[8] tcp_seq=[3867751502]
8. grpc client read fd=[8] tcp_seq=[3867751502]
```

上面已经解释了读写的 tcp seq 为什么无法匹配,接下来要做的是找到某个读操作对应的读之前的 tcp seq.
对于使用了TLS加密的报文来说,发现解密操作后的 tcp seq 是 http2 读前的 tcp seq,
解密操作前的 tcp seq 刚好对应发送方写入时的 tcp seq.
在解密操作完成时保存 (进程号,文件描述符,解密后TCP序列号) => (解密前TCP序列号) 的映射,
http2 读操作时,读 (进程号,文件描述符,HTTP2读操作开始时的TCP序列号) => (本次读操作处理的缓存对应的TCP序列号) 映射即可恢复应该显示的序列号.

测试发现存在多次读相同key的情况,即多次http2的读操作对应了同一个tcp报文,因此不能在读操作后立刻删除映射关系.
因此不存在一个可以确定回收映射占用内存资源的点,同时映射关系有非常强的时效性,一段时间(毫秒级别)不使用的数据将不会再被使用.
如果 eBPF 存在一个根据超时时间移除元素的数据结构应该选用这个数据结构,看上去没有.
目前选择用 LRU ,还需要根据极限情况计算 LRU 中需要保留的元素个数.

下面是几组数据,分别是用 eBPF 获取的 TCP 序列号和从 tcpdump 中抓包拿到的 tcp 序列号.

```txt
============================================== HTTP2 ===========================================

main-2731  [008] .... 1221019.861527: 0: http2 client write fd=[10] tcp_seq=[2046342762] // 这里有多条类似的日志,在发送tcp报文前多次写header
main-6135  [001] .... 1221019.862577: 0: http2 server read fd=[11] tcp_seq=[2046342762]
main-6135  [001] .... 1221019.863075: 0: http2 server write fd=[11] tcp_seq=[3424589742]
main-2731  [008] .... 1221019.864195: 0: http2 client read fd=[10] tcp_seq=[3424589742]


// tcpdump 抓到的包,序列号与uprobe获取的可以匹配

02:33:44.277239 IP 127.0.0.1.36456 > 127.0.0.1.443: Flags [P.], seq 2046342762:2046342843, ack 3424589742, win 1365, options [nop,nop,TS val 1461294619 ecr 1461284613], length 81
02:33:44.279043 IP 127.0.0.1.443 > 127.0.0.1.36456: Flags [P.], seq 3424589742:3424589800, ack 2046342843, win 350, options [nop,nop,TS val 1461294621 ecr 1461294619], length 58


============================================== gRPC ===========================================

main-8639  [008] .... 1221338.499235: 0: grpc client write fd=[8] tcp_seq=[3550833865]
main-8642  [012] .... 1221338.500151: 0: grpc server read fd=[9] tcp_seq=[3550833865]
main-8641  [009] .... 1221338.501042: 0: grpc server write fd=[9] tcp_seq=[2761620625]
main-8641  [009] .... 1221338.501127: 0: grpc server write fd=[9] tcp_seq=[2761620625] // 原因同上,发送前多次写 header
main-8642  [012] .... 1221338.501778: 0: grpc client read fd=[8] tcp_seq=[2761620625]
main-8642  [012] .... 1221338.501940: 0: grpc client read fd=[8] tcp_seq=[2761620625] // 原因同上,接收后多次读 header

// tcpdump 抓到的包,序列号与uprobe获取的可以匹配

02:39:02.922879 IP 127.0.0.1.38694 > 127.0.0.1.50051: Flags [P.], seq 3550833865:3550833942, ack 2761620573, win 1467, options [nop,nop,TS val 1461613257 ecr 1461603257], length 77
02:39:02.923989 IP 127.0.0.1.50051 > 127.0.0.1.38694: Flags [P.], seq 2761620573:2761620625, ack 3550833942, win 350, options [nop,nop,TS val 1461613258 ecr 1461613257], length 52
02:39:02.924045 IP 127.0.0.1.38694 > 127.0.0.1.50051: Flags [.], ack 2761620625, win 1467, options [nop,nop,TS val 1461613258 ecr 1461613258], length 0
02:39:02.924443 IP 127.0.0.1.50051 > 127.0.0.1.38694: Flags [P.], seq 2761620625:2761620762, ack 3550833942, win 350, options [nop,nop,TS val 1461613258 ecr 1461613258], length 137
02:39:02.924538 IP 127.0.0.1.38694 > 127.0.0.1.50051: Flags [.], ack 2761620762, win 1501, options [nop,nop,TS val 1461613258 ecr 1461613258], length 0
02:39:02.924669 IP 127.0.0.1.38694 > 127.0.0.1.50051: Flags [P.], seq 3550833942:3550833981, ack 2761620762, win 1501, options [nop,nop,TS val 1461613259 ecr 1461613258], length 39
02:39:02.925423 IP 127.0.0.1.38694 > 127.0.0.1.50051: Flags [P.], seq 3550833981:3550834033, ack 2761620762, win 1501, options [nop,nop,TS val 1461613259 ecr 1461613258], length 52
02:39:02.925641 IP 127.0.0.1.50051 > 127.0.0.1.38694: Flags [.], ack 3550834033, win 350, options [nop,nop,TS val 1461613260 ecr 1461613259], length 0
02:39:02.926129 IP 127.0.0.1.50051 > 127.0.0.1.38694: Flags [P.], seq 2761620762:2761620801, ack 3550834033, win 350, options [nop,nop,TS val 1461613260 ecr 1461613259], length 39
02:39:02.966547 IP 127.0.0.1.38694 > 127.0.0.1.50051: Flags [.], ack 2761620801, win 1501, options [nop,nop,TS val 1461613300 ecr 1461613260], length 0
02:39:07.299817 IP 127.0.0.1.50051 > 127.0.0.1.38694: Flags [F.], seq 2761620801, ack 3550834033, win 350, options [nop,nop,TS val 1461617634 ecr 1461613300], length 0
02:39:07.299884 IP 127.0.0.1.38694 > 127.0.0.1.50051: Flags [F.], seq 3550834033, ack 2761620802, win 1501, options [nop,nop,TS val 1461617634 ecr 1461617634], length 0
02:39:07.299940 IP 127.0.0.1.50051 > 127.0.0.1.38694: Flags [.], ack 3550834034, win 350, options [nop,nop,TS val 1461617634 ecr 1461617634], length 0
```
