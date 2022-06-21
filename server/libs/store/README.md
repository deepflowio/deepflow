## influxdb_writer功能实现说明:

1. 写主成功，同步备
2. 写主成功, 同步写入备失败(或备无法连接)，记录confidence
3. 写主失败，不同步备

## confidence写入说明:

- 写入位置： `_tsdb_meta`-> `confidence`
- 写入内容：
  - _id: 写入shard-id
  - db:  db名字
  - table: measurement名字
  - time:  分钟或10分钟级别时间
  - status：取值如下
    - PRIMARY_FAILED  // 主写失败，但一般写confidence也会失败
    - SYNC_SUCCESS    // 同步成功
    - REPLICA_DISCONNECT // 备influxdb无法连接，需尝试同步
    - SYNC_FAILED_1      // 备同步失败1次
    - SYNC_FAILED_2      // 备同步失败2次
    - SYNC_FAILED_3      // 同步3次失败，不同步

## influxdb_repair功能实现说明:

* 定期(默认1分钟)扫描confidence记录，进行主备同步，若备influxdb无法连接，则无须同步。

 1. 读取`_tsdb_meta`-> `confidence` 下最近的200条confidence记录
 2. 读取confidence记录对应的influxdb数据
 3. 将读取的数据，写入备influxdb中。
    - 若写成功，
      - 删除confidence表相应的记录，并记录到 confidence_synced表中，并修改status 为 SYNC_SUCCESS
    - 若写失败
      - 若当前confidence的status 为 REPLICA_DISCONNECT ，修改status为 SYNC_FAILED_1
      - 若当前confidence的status 为 SYNC_FAILED_1 ，修改status为 SYNC_FAILED_2
      - 若当前confidence的status 为 SYNC_FAILED_2 ，则删除confidence表相应的记录，并记录到 confidence_synced表中，并修改status 为 SYNC_FAILED_3 
