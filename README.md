简介
====

此工程包含的是droplet所需的公有的、抽象的数据结构和函数

queue队列
---------

虽然Golang已经在`github.com/golang-collections/go-datastructures的PriorityQueue`
提供了`Queue`和`PriorityQueue`，但是在这些方面它们不能够满足我们的需求：

1. 我们需要的是一个固定长度的queue，虽然这可以通过外部代码判断当前queue长度解决
2. 当超出queue尺寸时，我们希望直接覆盖掉queue中较旧的数据
3. 它们入队和出队的机制恐怕会导致较为频繁的内存申请，而我们更期望使用环形数组来减少内存申请
4. 我们希望Queue能够通过statsd上报当前的队列长度，以方便分析组件间的性能瓶颈

从性能数据上看，queue单次入队需要耗费73.7 ns/op，单次出队需要耗费24.8 ns/op，而如果8个协程同时出队，
开销则会上升到235 ns/op。因此在接收处应当尽可能通过Gets来单次获取尽可能多的数据，
此时如果性能瓶颈在于接收端，单个消息的时间开销将会接近1 ns/op，想来已经足够的高效了。

segmenttree线段树
-----------------

这里的线段树实现的是一个不可变的多维线段树，用于合并交叠数据并提供查询。一个典型示例如下：

假设存在如下的数据需要生成线段树
```
10.30.1.0/24 => 1
10.30.0.0/16 => 2
```

那么生成的树将会是
```mermaid
graph TD;
    tree("(-INF, +INF) => nil")
    tree-1("(-INF, 10.30.1.0) => nil")
    tree-2("[10.30.1.0, +INF) => nil")
    tree --- tree-1
    tree --- tree-2

    tree-1-1("(-INF, 10.30.0.0) => nil")
    tree-1-2("[10.30.0.0, 10.30.1.0) => [2]")
    tree-1 --- tree-1-1
    tree-1 --- tree-1-2

    tree-2-1("[10.30.1.0, 10.30.1.255] => [1, 2]")
    tree-2-2("(10.30.1.255, 10.30.255.255] => [2]")
    tree-2 --- tree-2-1
    tree-2 --- tree-2-2
```

那么我想要查询10.30.1.128/23所对应的数据集时，便能够得到[1, 2]的结果

fastpath内存占用
----------------
ACL是依据AclId和AclActionType进行划分，FastPolicyData保存ACL切片是动态变化的，
一个ACL是(40 + N * 6)，N是策略的个数。
FastPolicyData = 4byte + M * (40 + N * 6)byte, 取M = 5个ACL, N = 5个policyInfo, 进行如下估算： 
1. 平台数据(key(8byte) + FastPlatformData(96byte)) * 2 * policy-map-size
2. 策略数据(key(32byte) + FastPolicyData(354byte))  * 2 * policy-map-size

比如policy-map-size = 1024则：
1. 平台数据 = 104 * 2 * 1024 byte
2. 策略数据 = 386 * 2 * 1024 byte

flowgen+flowperf内存占用估计
----------------------------

每生成一条流，需要申请的一个新的FlowExtra结构体，其中包含MetaFlowPerf+TaggedFlow两个指针。
对于flowgen，输出TaggedFlow时还需申请TcpPerfStats；对于flowperf，每条流的MetaFlowPerf
结构体中还包含两个TcpSessionPeer链表，限制链表最大长度16。

可通过配置文件对最大流数量进行限制，其中flow-count-limit的默认值为1M。

1. 主要结构体及size(Byte)

    struct name    | size
    ---------------|-------
    MetaFlowPerf   |  328
    TcpSessionPeer |  48
    TcpPerfStats   |  96
    TaggedFlow     |  488
    FlowExtra      |  48

2. 理论内存占用

    理论上flowgen+flowperf内存占用应满足如下关系：

        最小：flow-count-limit * 1KB  (1056 = 48+488+328+96+48*1*2)

        最大：flow-count-limit * 2.5KB(2496 = 48+488+328+96+48*16*2)

    默认配置下，当流数量达到上限时，

        最小内存占用1G = 1M * 1KB

        最大内存占用2.5G = 1M * 2.5KB

3. 说明

    因每次申请内存时，一次申请1024个结构体；故实际内存占用会比理论值多
