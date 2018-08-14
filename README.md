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

* 命名规范

  相比Golang的命名规范，我们有一些额外的命名要求：

  1. 常量使用全大写加下划线的形式以便明显区分
  2. 类型定义首字母大写，避免类型名和变量名混杂在一起
  3. 结构体定义通常不会产生行宽问题，因此应当尽可能使用全称，除非是约定俗成的缩写
  4. 变量和参数的简写应当是完整的单词，比如packetHeader简写为header，而不是pktHdr
  5. 函数也应当尽可能使用全称，但是由于也是结构体成员，因此可能会导致行宽过宽时，可以适当缩写

* 单元测试

  单元测试不应当通过将结构体格式化打印为字符串的方式验证内容是否
  与预期一致，否则一旦修改结构体内容，不能在编译期就检查出问题所在，
  需要等到发现单元测试失败后，再修改格式化后的预期结果。

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
  4. 设置断点，`break TestPktExtract`
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

* 运行droplet前编辑droplet.yaml，修改profiler为true
* 观察堆内存：本地或远端执行`go tool pprof -inuse_space http://HOSTNAME:8000/debug/pprof/heap`
* 观察CPU：本地或远端执行`go tool pprof http://HOSTNAME:8000/debug/pprof/profile`
  - 执行top 30，可查看最热的30个函数
  - 执行list funcName，可查看某个函数的热点
  - 执行dot，可输出Graphviz源码，粘贴至 http://www.webgraphviz.com/ 可查看热点图
* 更多内容可以参考[pprof](https://golang.org/pkg/net/http/pprof/)
