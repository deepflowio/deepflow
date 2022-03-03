架构
====

engine/
  - DB目录 定义DBEngine结构，实现sql的translate
  - TODO：client目录 获取连接及执行语句
  - engine.go 定义Engine接口，所有db的Engine结构体需实现该接口

parse/
  - parse.go 定义了Parser结构体，用于sql解析

支持数据库：
-------------------------------------------------
- ClickHouse
  - clickhouse.go
    - 实现clickhouse的Engine
  - clickhouse/view
    - 用于转换sql的view结构体