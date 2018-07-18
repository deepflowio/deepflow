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

组件依赖方式
------------

Golang自身具备基于git repo的组件依赖描述，因此我们应当遵循这种方式。


示例如下：

```
package droplet

import (
	"gitlab.x.lan/trident/dispatcher"
	"gitlab.x.lan/river/dedup"
)
```

版本管理
--------

Golang的依赖并没有包含版本的描述，是隐式地通过GOPATH下所依赖工程当前签出的代码版本来决定的，
这想必不是我们所希望的结果，因此引入额外的版本管理组件很有必要

虽然目前trident使用的Godep来完成版本管理，但是如今Golang官方提供了dep以供版本管理，因此
droplet应当使用dep

导入依赖的Makefile示例：

```
GOPATH = $(shell go env GOPATH)
DROPLET_ROOT = ${GOPATH}/src/gitlab.x.lan/yunshan/droplet/

deps:
    [ -f ${GOPATH}/bin/dep ] || curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
    go get github.com/derekparker/delve/cmd/dlv
    go get github.com/golang/protobuf/protoc-gen-go
    mkdir -p ${GOPATH}/src/gitlab.x.lan/
    [ ! test -h ${DROPLET_ROOT} ] || ln -snf ${CURDIR} ${DROPLET_ROOT}
    (cd ${DROPLET_ROOT}; dep ensure)
```

目录结构组织
------------

* cmd: main函数入口，比如droplet应当是cmd/droplet/main.go
* bin: 二进制文件输出到bin目录下，并添加到.gitignore
* vendor: dep ensure输出目录，建议添加到.gitignore

二进制一致性
------------

相同的git revision在不同时间不同分支编译得到的二进制文件应当保持一致性，
因此生成的二进制文件不允许带有可变内容，比如编译时间或者编译分支。

Makefile
--------

Makefile并非Golang工程的必须组成部分，事实上即使是trident，Makefile也只是起辅助作用以减少手写命令的繁琐。
因此我们不对Makefile有过多的要求。
