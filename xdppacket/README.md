xdppacket库
-----------

使用golang语言，实现基于linux XDP特性的收、发包库。

xdp-socket的收发包过程大致是：

- 首先申请一大段用户态内存，称为UMEM, UMEM逻辑上被等分为
  n个block, 每个block用于存放一个数据包；
- 同时有Fill, Completion, RX and TX四个ring，
  简称fq, cq, rx, tx, UMEM使用fq和cq, socket使用rx和tx。
- 收包时：
  - 网卡驱动把包直接DMA到UMEM，然后把包的描述信息(包所在block地址，包长)填充到rx队列；
  - socket从rx队列获取包描述信息，然后从UMEM中取出包数据，然后将包所在block的地址
    (即block在UMEM中的偏移地址)写入fq队列，以告知内核包已被成功接收。
- 发包时：
  - socket把包数据放入UMEM的某个block中，然后将包的描述信息写入tx队列；
    并调用sendmsg()告知内核，有数据包需要发送；
  - 内核驱动从tx队列拿到包描述信息，然后将UMEM中的包发送出去，
    并将包所在block的地址写入cq队列，socket通过读取cq队列获悉已被成功发送。
- 关于linux xdp-socket收发包原理，请参考
  https://github.com/torvalds/linux/tree/master/Documentation/networking/af_xdp.rst

option说明
----------

提供6个对外可配置选项，详细说明如下：
1. OptNumFrames: 设置创建UMEM的大小，即上述的n，默认值1024, 因此Size(UMEM) = NumFrames * 2048 * 2；
   - 2048是block的大小，即每个包的最大长度，但由于内核保留了256B，因此每个包最长(2048-256)B；
   - 2的含义是，前n个block供发包使用，后n个block供收包使用。
2. OptRingSize: 设置fq，cq, rx, tx四个ring的长度，每个ring的长度相同，默认1024
3. OptXDPMode: 设置xdp的模式，支持XDP_MODE_DRV(默认)和XDP_MODE_SKB这两种模式；
   - XDP_MODE_DRV需网卡支持，目前仅支持驱动为ixgbe的网卡
4. OptQueueCount: 设置使用的网卡队列，范围[0, queueCount)，默认值1，对于非多队列socket，queueCount只能设置为1
5. OptPollTimeout: 设置poll系统调用的超时时间，仅在nonblock模式下生效，默认值100us
6. OptIoMode: 设置socket的I/O模式，支持IO_MODE_BLOCK(默认)和IO_MODE_NONBLOCK这两种模式，
   - IO_MODE_BLOCK模式下，收发包API一直等待，直到有包到达或包发送完成后返回；
   - IO_MODE_NONBLOCK模式下，若超过PollTimeout时间，仍没有包到达或包无法完成发送，立即返回。

代码结构
--------

整个代码分为4部分，Makefile，用户态代码，内核态代码, 示例程序。目录树：

```
├── af_xdp.go               ---对外提供单队列收发包函数接口
├── af_xdp_multi_queue.go   ---对外提供多队列收发包函数接口
├── af_xdp_test.go
├── cmd                     ---示例程序, 可以用于性能测试
│   ├── main.go
│   └── Makefile
├── ebpf                    ---内核部分功能实现
│   ├── bpf_helpers.h
│   ├── Makefile        
│   ├── remote-make         ---远程编译脚本, 使用10.30.200.9编译环境
│   └── xdpsock_kern.c
├── README
├── xdp_options.go         ---option参数解析
├── xdp_queue.go           ---实现rx,tx,fq,cq队列操作
├── xdp_socket.go          ---实现XDP socket创建，配置和初始化
└── xdpsock_kern.o         ---xdpsock_kern.c编译后的ebpf字节码
```

编译方法
-------

* 因xdp特性需要内核版本的支持，特增加了go编译tags限制,
* 默认情况下，不会编译xdp库；
* 如需编译，请增加如下tags选项``go build -tags="xdp"``

API说明
-------

1. 创建单队列xdp-socket接口
   * `func NewXDPPacket(name string, opts ...interface{}) (*XDPPacket, error)`
   * 在指定网卡上，根据opts参数，创建单队列xdp-socket，并完成所有配置。创建成功后，即可进行收、发包
   * 仅能使用网卡的queue 0, 因此queueCount只是1
   * 主要做的工作：
     1. 解析并校验option, 未指定的option均使用默认值
     2. 申请包缓存，用于存放将被接收或发送的包
     3. 注册UMEM结构，即向内核告知包缓存地址
     4. 设置rx,tx,fq,cq队列大小
     5. 获取rx,tx,fq,cq队列内核地址，并初始化用户态队列结构
     6. 将ebpf程序装载到内核，并更新map，即告知内核将哪个网卡上的包发给指定socket
     7. 将socket绑定到网卡的指定队列

2. 单队列收包接口
   * `func (x *XDPPacket) ZeroCopyReadPacketData() ([]byte, error)`
   * `func (x *XDPPacket) ReadPacketData() ([]byte, error)`
   * `func (x *XDPPacket) ZeroCopyReadMultiPackets() ([][]byte, []CaptureInfo, error)`
   * 收包接口，区别是:
     * ReadPacketData内部有一次包拷贝，包已存入新的buffer；
     * ZeroCopyReadMultiPackets每次尽最大努力收包，最多一次收16个包，
     函数返回后，请使用``len([]CaptureInfo)``获取收包数量
   * 主要做的工作
     1. 在非阻塞模式下，首先调用poll
     2. 调用ReleaseOneReadPacket将上一个包的地址返还给内核
     3. 从rx队列获取包的地址，长度
     4. 根据地址，长度信息，从包缓存读取包数据
     5. 将地址返还给内核，写入fq队列

3. 单队列发包接口
   * `func (x *XDPPacket) WritePacket(pkt []byte) error`
   * `func (x *XDPPacket) WriteMultiPackets(pkts [][]byte) (int, error)`
   * 发包接口, 区别是WriteMultiPackets每次调用可发送多个包，并返回成功发送包数量
   * 主要做的工作
     1. 在非阻塞模式下，首先调用poll
     2. 将包的地址，长度信息写入tx队列
     3. 将包数据写入到包缓存对应的地址
     4. 从cq队列将包地址读出

4. 创建多队列xdp-socket接口, 获取各队列socket
   * `func NewXDPMultiQueue(name string, opts ...interface{}) (*XDPMultiQueue, error)`
     * 在网卡的前[0, queueCount)个queue上创建多队列xdp-socket，并完成所有配置。创建成功后，即可进行收、发包
     * 与NewXDPPacket的区别在于，NewXDPPacket仅在queue 0上创建xdp-socket
   * `func GetXDPSocketFromMultiQueue(multiQueue *XDPMultiQueue) []*XDPPacket`
     * 在创建多队列xdp-socket后，可调用此函数，用以返回各个队列各自的socket
     * 可视获取的socket为单队列xdp-socket, 使用单队列的收发包API处理各自队列的数据包收发

5. 多队列收包接口
   * `func (m *XDPMultiQueue) ReadPacket() ([][]byte, []CaptureInfo, error)`
   * `func (m *XDPMultiQueue) ZeroCopyReadPacket() ([][]byte, []CaptureInfo, error)`
   * 尝试从xdp-socket的每个队列收一个包，返回实际收到的数据包, 具体收包数量可通过``len([]CaptureInfo)``或
   ``len([][]byte)``获取
   * 在nonblock模式下，若某个队列无包，需等待pollTimeout；因此，极限情况下需`queueCount*pollTimeout`后返回

6. 多队列发包接口
   * `func (m *XDPMutiQueue) WritePacket(pkts [][]byte) (int, error)`
   * 把len(pkts)个包顺序分给每个队列发送
   * 若某个队列发送失败，立即返回成功发送的包数量，且``error!=nil``
   * 发送成功，返回功发送的包数量，且``error == nil``

7. 收、发包，错误统计
   * `func (x *XDPPacket) GetStats() *XDPStats`
   * `func (m *XDPMultiQueue) GetStats() *XDPMultiQueueStats`
   * xdp-socket收、发包，错误统计
   * 多队列情况下，包含各个队列的统计信息及其总和；总和存在slice的第一个，即Stats[0]

8. 常量说明
   * 内核代码存放路径        "/usr/sbin/xdpsock_kern.o"
   * bpffs文件系统挂载目录   "/sys/fs/bpf"
   * bpf map文件路径         "/sys/fs/bpf/xsks_map"

9. 说明：
    1. 要求linux kernel版本>=4.19
    2. 使用示例程序时，需将xdpsock_kern.o拷贝到/usr/sbin/目录下
    3. 最多支持同时64个队列收包
    4. 不支持收发jumbo帧, 原因：因内核限制UMEM的block大小范围是: `[2048, PAGE_SIZE]&&is_power_of_2`，
       故一般取值2048或4096，同时需预留256B的保留头部；因此无法支持对jumbo帧的处理
    5. 不支持多个socket共享UMEM，即每个收发包函数只能处于一个线程
    6. 支持全双工同时收发, 但不能是在同一网卡

10. FIXME
    1. 动态加载ebpf程序，或直接用指令实现bpf功能
    2. 用golang实现libbpf库
    3. 队列大小，包缓存大小关系
    4. cq队列可能存在无法完成的情况
    5. 提供一次Read多个包的接口
    6. Counter避免使用atomic

11. 性能，当前的测试结果：
    1. 测试环境 
       * CPU: Intel(R) Xeon(R) CPU E5-2630 v4 @ 2.20GHz (40核)
       * 内存: 256G 
       * 网卡: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ (驱动ixgbe)
    2. 单队列单包发送
    3. 单队列多包发送
    4. 单队列单包接收
    5. 单队列多包接收
    6. 多队列发送
    7. 多队列接收
    8. 多队列单包发送
    9. 多队列多包发送
    10. 多队列单包接收
    11. 多队列多包接收
