### Table of Contents

**[DeepFlow release v6.6](#66)**<br/>
**[Changelog for v6.5](https://github.com/deepflowio/deepflow/blob/v6.5/docs/CHANGELOG-6-5.md)**<br/>

# v6.6 Changelog

### <a id="66"></a>DeepFlow release v6.6

#### Bug Fix
* fix: Only the default organization registers with tsdb [#7166](https://github.com/deepflowio/deepflow/pull/7166) by [jin-xiaofeng](https://github.com/jin-xiaofeng)
* fix: agent - eBPF Adjust syscall sendto() for IPv6 mapping to IPv4 [#7161](https://github.com/deepflowio/deepflow/pull/7161) by [yinjiping](https://github.com/yinjiping)
* fix: genesis reponse nil pointer [#7157](https://github.com/deepflowio/deepflow/pull/7157) by [askyrie](https://github.com/askyrie)
* fix: agent sync ignore loopback ip [#7152](https://github.com/deepflowio/deepflow/pull/7152) by [askyrie](https://github.com/askyrie)
* fix: agent - eBPF Ensure the Sofa protocol can reassemble [#7151](https://github.com/deepflowio/deepflow/pull/7151) by [yinjiping](https://github.com/yinjiping)
* fix: server static config PacketFanoutMode [#7147](https://github.com/deepflowio/deepflow/pull/7147) by [TomatoMr](https://github.com/TomatoMr)
* fix: Repair collector network card list display incomplete [#7146](https://github.com/deepflowio/deepflow/pull/7146) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: server removes redundant function codes to avoid log errors [#7144](https://github.com/deepflowio/deepflow/pull/7144) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: agent - eBPF Resolve missing fork() syscall on arm64 [#7143](https://github.com/deepflowio/deepflow/pull/7143) by [yinjiping](https://github.com/yinjiping)
* Fix prometheus data cannot be labeled with universal tags，if slow-decoder is used. [#7100](https://github.com/deepflowio/deepflow/pull/7100)


#### NEW FEATURE
* feat: Alarm_policy queue.metrics.overwritten and ingester.queue.metri… [#7173](https://github.com/deepflowio/deepflow/pull/7173) by [Ericsssss](https://github.com/Ericsssss)
* feat: Modify system alarm policy query_conditions columns [#7171](https://github.com/deepflowio/deepflow/pull/7171) by [Ericsssss](https://github.com/Ericsssss)
* feat: OTel’s HTTP protocol parsing optimization in l7_flow_log [#7136](https://github.com/deepflowio/deepflow/pull/7136) by [lzf575](https://github.com/lzf575)
* feat: deepflow-ctl ingester support debugging by org id [#7133](https://github.com/deepflowio/deepflow/pull/7133) by [lzf575](https://github.com/lzf575)
* feat: agent support setting PACKET_FANOUT [#7126](https://github.com/deepflowio/deepflow/pull/7126) by [TomatoMr](https://github.com/TomatoMr)
* feat: add volcengine cloud platform for server controller [#7090](https://github.com/deepflowio/deepflow/pull/7090) by [askyrie](https://github.com/askyrie)
* feat: agent directly reports metrics that can be used for alert [#7089](https://github.com/deepflowio/deepflow/pull/7089) by [TomatoMr](https://github.com/TomatoMr)
* feat: server directly reports metrics of load1_by_cpu_num that can be used for alert [#7088](https://github.com/deepflowio/deepflow/pull/7088) by [lzf575](https://github.com/lzf575)


#### Refactoring
* refactor: Change crate name [#7155](https://github.com/deepflowio/deepflow/pull/7155) by [rvql](https://github.com/rvql)


#### Performance
* perf: improve parsing RequestResource from http.url of OTel data [#7172](https://github.com/deepflowio/deepflow/pull/7172) by [lzf575](https://github.com/lzf575)
