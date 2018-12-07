Droplet工程开发指南
===================

背景
----

为了达到易于部署、统一后端技术栈、减少模块间信息传递开销等目的，我们希望整合
目前几乎所有后端的工程，来实现一个重量级、单进程的应用程序。

当然，这也是一个具有挑战的项目，目前能够遇见到的困难包括如下几点：

* 曾经的C、Java和Python的技术栈将会被抛弃，需要尽快熟悉Golang的使用
* 如何划分组件以实现组件隔离，以及设计调用接口来尽可能减少模块间耦合
* 单个组件的缺陷可能会导致整个Droplet崩溃

目录结构组织
------------

* cmd: main函数入口，比如droplet应当是cmd/droplet/main.go
* bin: 二进制文件输出到bin目录下，并添加到.gitignore
* vendor: dep ensure输出目录，建议添加到.gitignore

二进制一致性
------------

相同的git revision在不同时间不同分支编译得到的二进制文件应当保持一致性，
因此生成的二进制文件不允许带有可变内容，比如编译时间或者编译分支。

代码规范
--------

* 包导入规范

  标准库导入、外部库导入和工程内导入通过空行区分开，并按上述顺序导入

* 命名规范

  相比Golang的命名规范，我们有一些额外的命名要求：

  1. 常量使用全大写加下划线的形式以便明显区分
  2. 类型定义首字母大写，避免类型名和变量名混杂在一起
  3. 结构体定义通常不会产生行宽问题，因此应当尽可能使用全称，除非是约定俗成的缩写
  4. 变量和参数的简写应当是完整的单词，比如packetHeader简写为header，而不是pktHdr
  5. 函数也应当尽可能使用全称，但是由于也是结构体成员，因此可能会导致行宽过宽时，可以适当缩写
  6. 定义类成员函数时，对象名称应当是类名称最后一个单词的首字母，比如应当是`(t *ServiceTable)`
     而不是`(s *ServiceTable)`，因为Service是对Table的修辞词，类的本体是Table。
     但是例外的情形是，应当避免使用i作为对象名，比如结构体名是形如`PlatformInfo`的名称，
     此时可以考虑使用`p`或者`info`来命名对象。

* 对象构造

  当如下情形都满足时才应当使用new关键字：

  1. 明确表明对象未初始化(new虽然会写0初始化，但是和对象初始化并不能等同)
  2. 明确表明对象从堆申请()

* 单元测试

  1. 单元测试不允许有fmt输出
  2. 单元测试不应当通过将结构体格式化打印为字符串的方式验证内容是否
     与预期一致，否则一旦修改结构体内容，不能在编译期就检查出问题所在，
     需要等到发现单元测试失败后，再修改格式化后的预期结果。

* 变量声明

  通过var声明变量仅适用于无法立即为变量赋值或初始化的场合，除此之外均不应当通过var声明变量。

* 结构体定义

  继承的结构应当与结构体成员变量通过空行区分开

Droplet依赖管理
--------

Golang自身具备基于git repo的组件依赖描述，因此我们应当遵循这种方式。


示例如下：

```
package droplet

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/linkedlist"
)
```

Golang的依赖并没有包含版本的描述，是隐式地通过GOPATH下所依赖工程当前签出的代码版本来决定的，
这想必不是我们所希望的结果，因此引入额外的版本管理组件很有必要

虽然目前droplet使用的Godep来完成版本管理，但是如今Golang官方提供了dep以供版本管理，因此
droplet应当使用dep

当需要下载droplet所需的依赖时，通过`make vendor`命令完成

当需要更新某个依赖时，通过`dep ensure -update gitlab.x.lan/yunshan/droplet-libs`

编译打包步骤
------------

1. 安装golang

    `yum -y install golang`

2. 修改PATH环境变量

    `export PATH=$GOPATH/bin:$PATH`

3. 下载droplet依赖并编译

    `make`

4. 打包

    `rpmbuild -bb droplet.spec`

调试定位
----------------

* 单元测试通过DLV调试的方法
  1. 首先`go get -u github.com/derekparker/delve/cmd/dlv`下载dlv工具
  2. 以dedup为例，执行`dlv test gitlab.x.lan/yunshan/droplet/handler/`
  3. 列举测试用例，`funcs test.Test*`
  4. 设置断点，`break TestPacketExtract`
  5. 启动调试，`continue`
  6. dlv退出可能挂死，挂死时直接kill
* 当droplet因panic异常退出时，日志文件将无法捕获到异常栈，此时只能通过运行`journalctl -xel -u droplet`来查看异常栈
* 本地运行环境通过DLV调试的方法
  1. make debug生成未编译优化的droplet，使用此droplet运行
  2. dlv exec或dlv attach进入调试环境后，运行`config substitute-path /from /to`来更改源码查找路径
* 远程运行环境通过DLV调试的方法
  1. make debug生成未编译优化的droplet，使用此droplet运行
  2. 远程运行dlv -l 0.0.0.0:2345 --headless exec ./droplet
  3. 本地运行dlv connect 10.30.49.16:2345

Benchmark
---------

一部分用例提供了Benchmark，执行 `make bench` 来运行这些测试

如果想通过Benchmark生成profiler来分析各模块的调用开销，可以执行
`go test -bench=. ./handler -benchmem -cpuprofile profile; go tool pprof --pdf profile > profile.pdf`
来生成profile

profiler
---------------

运行droplet前，编辑droplet.yaml，修改profiler为true

开发/测试环境获取方式:

* 观察堆内存：本地或远端执行`go tool pprof -inuse_space http://HOSTNAME:8000/debug/pprof/heap`
* 观察CPU：本地或远端执行`go tool pprof http://HOSTNAME:8000/debug/pprof/profile`
  - 执行top 30，可查看最热的30个函数
  - 执行list funcName，可查看某个函数的热点
  - 执行pdf可以输出pdf格式的热点图
  - 如果本地不方便运行go，可以使用socat代理socket，命令为`socat TCP4-LISTEN:8000 TCP4:analyzer2:8000`
* 更多内容可以参考[pprof](https://golang.org/pkg/net/http/pprof/)

生产环境获取方式:

* 获取CPU profiler:
  1. 运行环境执行`wget http://localhost:8000/debug/pprof/profile?seconds=30 -o droplet.pprof`
  2. 将droplet.pprof拷贝到本地，然后执行`go tool pprof droplet.pprof`

性能量化字段说明
----------------

原则：宁愿少算漏算，也不错算误算

* 性能字段
  - RTT（建立连接RTT延迟）
      - 对应rtt_syn（两侧加和计算，不区分哪一侧）
      - rtt_syn计算区分所属阶段（建立连接）只需要看请求包是否含有SYN就行
          - SYN + 紧邻的反方向SYN/ACK（seq+1和ack一致）
          - SYN/ACK + 紧邻的正方向的ACK（seq+1和ack一致）
  - SRT（系统响应时间）
      - 对应rtt（只算服务端一侧）
      - 分别计算客户端到引流点、引流点到服务端的rtt（rtt_0和rtt_1），最终输出只输出其中一侧（根据最终的方向判断）
      - rtt计算区分所属阶段（数据传输）只需要看请求包是否含有PSH就行
          - PSH/ACK且有payload（payloadlen>1）+ 紧邻的反方向的无payload（payload_len=0）的ACK（seq和ack一致）
              - 说明：为了避免丢包、乱序情况下TCP Keep-Alive包的影响，限制每对请求、回复包的rtt计算的最大值为10s
  - ART（应用响应时间）
      - 对应art（只算服务端一侧）
      - 分别计算客户端到引流点、引流点到服务端的art（art_0和art_1），最终输出只输出其中一侧（根据最终的方向判断）
      - art计算区分所属阶段（数据传输）,回复包payloadlen需大于1
          - PSH/ACK且有payload（payloadlen>1）+ 反方向有payload（payloadlen>1）的ACK或PSH/ACK（seq和ack一致）
  - 重传
      - 重传计算区分所属阶段（建立连接还是数据传输）只需要看包的seq是属于临界点seq之前还是之后
      - 建立连接阶段重传,需确定临界点seq
          - 请求方向的seq确定：SYN和ACK，根据SYN来计算ACK
          - 回复方向的seq确定：SYN/ACK
      - 数据传输阶段重传，需判断包的seq和length是否与已收到的包重复
          - 说明：数据传输阶段重传retrans统计包含建立连接阶段重传retransSyn
      - 需要注意TCP Keep-Alive包的影响
          - 排除payloadlen=0,或payloadlen=1的包
  - 零窗
      - 统计tcp头传输窗口size为0的包
  - 紧急
      - 统计tcp头URG置1的包
  - 熵字段
      - 包方差PacketSizeDeviation
      - 包间隔均值PacketIntervalAvg
      - 包间隔方差PacketIntervalDeviation

* 性能字段字段对应关系表

     flow性能量化字段                           | 统计粒度      | 所属阶段 | 是否区分方向 | 其他        | 对应report字段                                | 对应kibana字段
     -------------------------------------------|---------------|----------|--------------|-------------|-----------------------------------------------|---------------
     flow.rttSyn0, flow.rttSyn1                 | 每流          | 连接建立 | 是           | N/A         | RTTSyn=rttSyn0+rttSyn1                        | rtt_syn
     period.retransSyn0, period.retransSyn1     | 每上报周期    | 连接建立 | 是           | N/A         | Src.SynRetransCount, Dst.SynRetransCount      | syn_retrans_cnt_0, syn_retrans_cnt_1
     period.art0Sum, period.art1Sum             | 每上报周期    | 数据传输 | 是           | N/A         | ART=art1Sum/art1Count                         | art_avg
     period.art0Count, period.art1Count         | 每上报周期    | 数据传输 | 是           | N/A         | ART=art1Sum/art1Count                         | art_avg
     period.rtt0Sum, period.rtt1Sum             | 每上报周期    | 数据传输 | 是           | N/A         | RTT=rtt1Sum/rtt1Count                         | rtt
     period.rtt0Count, period.rtt1Count         | 每上报周期    | 数据传输 | 是           | N/A         | RTT=rtt1Sum/rtt1Count                         | rtt
     period.retrans0, period.retrans1           | 每上报周期    | 数据传输 | 是           | 包括syn重传 | Src.RetransCount, Dst.RetransCount            | retrans_cnt_0, retrans_cnt_1
     flow.retrans0, flow.retrans1               | 每流          | 数据传输 | 是           | 包括syn重传 | TotalRetransCount=retrans0+retrans1           | total_retrans_cnt
     period.zeroWinCount0, period.zeroWinCount1 | 每上报周期    | 数据传输 | 是           | N/A         | Src.ZeroWinCount, Dst.ZeroWinCount            | zero_wnd_cnt_0, zero_wnd_cnt_1
     flow.zeroWinCount0, flow.zeroWinCount1     | 每流          | 数据传输 | 是           | N/A         | TotalZeroWinCount=zeroWinCount0+zeroWinCount1 | total_zero_wnd_cnt
     period.pshUrgCount0, period.pshUrgCount1   | 每上报周期    | 数据传输 | 是           | N/A         | Src.PshUrgCount, Dst.PshUrgCount              | psh_urg_cnt_0, psh_urg_cnt_1
     flow.pshUrgCount0, flow.pshUrgCount1       | 每流          | 数据传输 | 是           | N/A         | TotalPshUrgCount=pshUrgCount0+pshUrgCount1    | total_psh_urg_cnt
     packetIntervalAvg                          | 每上报周期    | N/A      | 否           | N/A         | PacketIntervalAvg                             | avg_pkt_interval
     packetIntervalVariance                     | 每上报周期    | N/A      | 否           | N/A         | PacketIntervalVariance                        | pkt_interval_deviation
     packetSizeVariance                         | 每上报周期    | N/A      | 否           | N/A         | PacketSizeVariance                            | pkt_size_deviation

网流聚合原则
------------

* 网流聚合
  - 南北和东西本身区分
  - 南北和东西区分引流位置：南北为qinq（0x10000+qinq外层vlan偏移），东西为trident宿主机及引流接口（tridentIp+ifMacSuffix）
  - 南北和东西不区分vlan
  - 南北不区分mac、东西区分mac
  - 南北和东西区分tunnelType、tunnelId、tunnelIpSrc、tunnelIpDst
  - 南北和东西区分ipSrc、ipDst、proto、portSrc、portDst
      - 对于非TCP/UDP的IPv4或者IPv4分片，portSrc和portDst为0
  - 聚合后的特殊字段表示
      - VLAN
        - 网流双方向仅其中一个有VLAN的情况，将此VLAN记录为网流的VLAN
        - 网流双方向VLAN不一致的情况下，选择任何一方VLAN作为网流VLAN
      - TTL
        - 网流双方向的TTL用双方向首包的TTL表示
* 网流方向
  1. 网流的某个端口落在用户输入的服务列表中（比如8080），以该端口为网流的目标端口（服务端）；如果两个端口都满足，以更小值的端口为网流的目标端口（服务端）
  2. 网流中出现的第一个SYN/ACK包的源端口为网流的目标端口（服务端）
  3. 网流的某个端口落在[IANA官方定义的服务列表](https://zh.wikipedia.org/wiki/TCP/UDP%E7%AB%AF%E5%8F%A3%E5%88%97%E8%A1%A8)前1024号中，以该端口为网流的目标端口（服务端）；如果两个端口都满足，以更小值的端口为网流的目标端口（服务端）
  4. 其他情况下，以网流的第一个包的目标端口为网流的目标端口（服务端）
* 网流状态转换
  - TCP流量状态转换
      - 定义的正常状态
          - RAW, OPENING_1, OPENING_2, ESTABLISHED, CLOSING_1, CLOSING_2, CLOSED
      - 定义的异常状态
          - RESET, EXCEPTION
  - 其他流量无状态机，仅简单使用ESTABLISHED, EXCEPTION等状态用于输出
  - 网流超时时间
      - RAW, OPENING_1, OPENING_2, RESET, EXCEPTION状态网流超时时间为5秒
      - TCP流量ESTABLISHED状态超时时间为300秒
      - CLOSING_1, CLOSING_2状态超时时间为35秒
      - 其他协议流量仅单方向有报文时超时时间为5秒，双方向有报文时超时时间为35秒
      - 每自然分钟第0秒上报所有flow
      - 每条网流第5秒进行一次上报
      - 以上超时时间均可通过droplet.yaml文件进行配置

![image](http://gitlab.x.lan/hpn/tasks-hpn/uploads/de65de6b51659d4368fd334b6845e40c/image.png)

* 网流结束类型
  - IPv4-TCP
      - CLOSE_TYPE_FIN: CLOSED、CLOSING_2
      - CLOSE_TYPE_RST: RESET（根据第一个RST所在的方向判断：如果是CLIENT到SERVER，那么就是CLIENT_RST，反之就是SERVER_RST）
      - CLOSE_TYPE_HALF_OPEN: OPENING_1（SERVER_HALF_OPEN）、OPENING_2（CLIENT_HALF_OPEN）
      - CLOSE_TYPE_HALF_CLOSE: CLOSING_TX1（SERVER_HALF_CLOSE）、CLOSING_RX1（CLIENT_HALF_CLOSE）
      - CLOSE_TYPE_TIMEOUT: ESTABLISHED
      - CLOSE_TYPE_UNKNOWN: EXCEPTION
      - CLOSE_TYPE_FORCE_REPORT: 第5秒或每自然分钟分钟第0秒强制上报的情况
  - 其他IPv4
      - CLOSE_TYPE_TIMEOUT: 默认情况
      - CLOSE_TYPE_FORCE_REPORT: 第5秒或每自然分钟分钟第0秒强制上报的情况

* 网流时间序列字段
  - arrTime00: 整条流的请求方向的第一个包的时间戳（内部使用）
  - arrTime10: 整条流的应答方向的第一个包的时间戳（内部使用）
  - arrTime0Last: 此次上报时整条流的请求方向的最后一个包的时间戳（内部使用）
  - arrTime1Last: 此次上报时整条流的应答方向的最后一个包的时间戳（内部使用）
  - startTime: 本次上报的统计起始时间
  - endTime: 本次上报的统计结束时间（与startTime的时间差应该在60秒以内，允许4秒的误差）
      - endTime与`startTime+duration`并不一定相等，主要体现在突发短流和长流包数少的情况下
      - 4秒容差为默认值，可通过droplet.yaml进行配置
  - timeBitmap: 网流每自然分钟内每一秒中是否有包，有的话对应bit为1（共64bit）
  - duration: 本次上报时max(arrTime0Last,arrTime1Last)与min(arrTime00,arrTime10)的时间差
      - （``乱序处理``：如果正在处理的包的timestamp小于max(arrTime0Last,arrTime1Last)，则将其timestamp调整为max(arrTime0Last,arrTime1Last)）
