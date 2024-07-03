### Table of Contents

**[DeepFlow release v6.6](#66)**<br/>
**[Changelog for v6.5](https://github.com/deepflowio/deepflow/blob/v6.5/docsCHANGELOG-6-5.md)**<br/>

# v6.6 Changelog

### <a id="66"></a>DeepFlow release v6.6

#### Bug Fix
* fix: agent - incorrect grpc log collected by uprobe [#7199](https://github.com/deepflowio/deepflow/pull/7199) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: getting wrong org-id and team-id when the Agent version is less than v6.5.9 [#7188](https://github.com/deepflowio/deepflow/pull/7188) by [lzf575](https://github.com/lzf575)
* fix: when modifying the TTL of the CK table fails, the connection to CK needs to be closed [#7185](https://github.com/deepflowio/deepflow/pull/7185) by [lzf575](https://github.com/lzf575)
* fix: Modify the value of team's short lcuuid corresponding to org_id [#7177](https://github.com/deepflowio/deepflow/pull/7177) by [jin-xiaofeng](https://github.com/jin-xiaofeng)
* Fix prometheus data cannot be labeled with universal tags，if slow-decoder is used. [#7100](https://github.com/deepflowio/deepflow/pull/7100)


#### NEW FEATURE
* feat: add volcengine icon const [#7179](https://github.com/deepflowio/deepflow/pull/7179) by [askyrie](https://github.com/askyrie)
* feat: Alarm_policy queue.metrics.overwritten and ingester.queue.metri… [#7173](https://github.com/deepflowio/deepflow/pull/7173) by [Ericsssss](https://github.com/Ericsssss)
* feat: Modify system alarm policy query_conditions columns [#7171](https://github.com/deepflowio/deepflow/pull/7171) by [Ericsssss](https://github.com/Ericsssss)
* feat: agent - support vhost user [#7164](https://github.com/deepflowio/deepflow/pull/7164) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: server directly reports metrics of load1_by_cpu_num that can be used for alert [#7088](https://github.com/deepflowio/deepflow/pull/7088) by [lzf575](https://github.com/lzf575)


#### Performance
* perf: improve parsing RequestResource from http.url of OTel data [#7172](https://github.com/deepflowio/deepflow/pull/7172) by [lzf575](https://github.com/lzf575)
