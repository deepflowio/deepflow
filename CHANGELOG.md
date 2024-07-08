### Table of Contents

**[DeepFlow release main](#main)**<br/>
**[Changelog for v6.5](https://github.com/deepflowio/deepflow/blob/v6.5/docs/CHANGELOG-6-5.md)**<br/>

# Changelog

### <a id="main"></a>DeepFlow release main

#### Bug Fix
* fix: agent - incorrect http2 log [#7296](https://github.com/deepflowio/deepflow/pull/7296) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: the flow_tag of prometheus may be lost under multiple organizations [#7294](https://github.com/deepflowio/deepflow/pull/7294) by [lzf575](https://github.com/lzf575)
* fix: agent - eBPF Adjust Java syms-cache update logic & error log output [#7291](https://github.com/deepflowio/deepflow/pull/7291) by [yinjiping](https://github.com/yinjiping)
* fix: deepflow stats may write to wrong database [#7284](https://github.com/deepflowio/deepflow/pull/7284) by [lzf575](https://github.com/lzf575)
* fix: agent - eBPF Addressing excessive eBPF maps memory usage [#7281](https://github.com/deepflowio/deepflow/pull/7281) by [yinjiping](https://github.com/yinjiping)
* fix: agent - remove duplicate vhost dispatcher [#7267](https://github.com/deepflowio/deepflow/pull/7267) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: Show metrics use query cache can be configured [#7263](https://github.com/deepflowio/deepflow/pull/7263) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: server recorder prints unnecessary error logs [#7262](https://github.com/deepflowio/deepflow/pull/7262) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* feat: Add fixed id for remote execution commands [#7255](https://github.com/deepflowio/deepflow/pull/7255) by [rvql](https://github.com/rvql)
* fix: Network interface card list supports duplicate mac [#7251](https://github.com/deepflowio/deepflow/pull/7251) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: agent - windows compilation errors [#7243](https://github.com/deepflowio/deepflow/pull/7243) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: uses long connections to connect to CK for datasources manager [#7239](https://github.com/deepflowio/deepflow/pull/7239) by [lzf575](https://github.com/lzf575)
* fix: server recorder prints unnecessary error logs [#7190](https://github.com/deepflowio/deepflow/pull/7190) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: Attribute supports Chinese [#7210](https://github.com/deepflowio/deepflow/pull/7210) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: agent Packet fanout can only be set in TapMode::Local mode [#7205](https://github.com/deepflowio/deepflow/pull/7205) by [TomatoMr](https://github.com/TomatoMr)
* fix: agent - eBPF DNS cannot obtain network tuple data (#7131) [#7132](https://github.com/deepflowio/deepflow/pull/7132) by [yinjiping](https://github.com/yinjiping)
* fix: Ingester always update prometheus labels even if labels version has not changed [#7128](https://github.com/deepflowio/deepflow/pull/7128) by [lzf575](https://github.com/lzf575)
* fix: k8s refresh close keep alive [#7125](https://github.com/deepflowio/deepflow/pull/7125) by [askyrie](https://github.com/askyrie)
* fix: server controller changes prometheus label version when data doe… [#7116](https://github.com/deepflowio/deepflow/pull/7116) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: agent - eBPF Enhance Mongo/SOFARPC/MySQL/HTTP2 proto-infer(#7110) [#7113](https://github.com/deepflowio/deepflow/pull/7113) by [yinjiping](https://github.com/yinjiping)
* fix: agent - add sleep before exiting [#7111](https://github.com/deepflowio/deepflow/pull/7111) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: agent - incorrect grpc log collected by uprobe [#7199](https://github.com/deepflowio/deepflow/pull/7199) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: getting wrong org-id and team-id when the Agent version is less than v6.5.9 [#7188](https://github.com/deepflowio/deepflow/pull/7188) by [lzf575](https://github.com/lzf575)
* fix: when modifying the TTL of the CK table fails, the connection to CK needs to be closed [#7185](https://github.com/deepflowio/deepflow/pull/7185) by [lzf575](https://github.com/lzf575)
* fix: Modify the value of team's short lcuuid corresponding to org_id [#7177](https://github.com/deepflowio/deepflow/pull/7177) by [jin-xiaofeng](https://github.com/jin-xiaofeng)
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
* feat: add trace map router [#7299](https://github.com/deepflowio/deepflow/pull/7299) by [taloric](https://github.com/taloric)
* feat: server uses sub_domain team id first when publishing message to tagrecorder. [#7293](https://github.com/deepflowio/deepflow/pull/7293) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* feat: agent opens the protocol desensitization by default [#7285](https://github.com/deepflowio/deepflow/pull/7285) by [TomatoMr](https://github.com/TomatoMr)
* feat: agent - flow&app log collected by lo nic do not report ctrl_mac [#7272](https://github.com/deepflowio/deepflow/pull/7272) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: querier - Rewriting ParseShowSql with Regular Expressions [#7268](https://github.com/deepflowio/deepflow/pull/7268) by [duandaa](https://github.com/duandaa)
* feat: Support kubernetes api field_selector [#7248](https://github.com/deepflowio/deepflow/pull/7248) by [rvql](https://github.com/rvql)
* feat: add debug ctl to rebalance agent by traffic [#7184](https://github.com/deepflowio/deepflow/pull/7184) by [roryye](https://github.com/roryye)
* feat: agent - eBPF Add JAVA symbol file generation log [#7258](https://github.com/deepflowio/deepflow/pull/7258) by [yinjiping](https://github.com/yinjiping)
* feat: revert - Rewriting ParseShowSql with Regular Expressions [#7252](https://github.com/deepflowio/deepflow/pull/7252) by [duandaa](https://github.com/duandaa)
* feat: querier - Rewriting ParseShowSql with Regular Expressions [#7181](https://github.com/deepflowio/deepflow/pull/7181) by [duandaa](https://github.com/duandaa)
* feat: server adds mysql conns configs [#7139](https://github.com/deepflowio/deepflow/pull/7139) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* feat: Add command for java stack dump [#7226](https://github.com/deepflowio/deepflow/pull/7226) by [rvql](https://github.com/rvql)
* feat: Add volcengine icon const [#7204](https://github.com/deepflowio/deepflow/pull/7204) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat: Added automatic update changlog action [#7135](https://github.com/deepflowio/deepflow/pull/7135) by [Nick-0314](https://github.com/Nick-0314)
* feat: Profile adjust decompression order [#7122](https://github.com/deepflowio/deepflow/pull/7122) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat: CK’s username and password support the use of special characters [#7119](https://github.com/deepflowio/deepflow/pull/7119) by [lzf575](https://github.com/lzf575)
* feat: add volcengine icon const [#7179](https://github.com/deepflowio/deepflow/pull/7179) by [askyrie](https://github.com/askyrie)
* feat: agent - support vhost user [#7164](https://github.com/deepflowio/deepflow/pull/7164) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: Alarm_policy queue.metrics.overwritten and ingester.queue.metri… [#7173](https://github.com/deepflowio/deepflow/pull/7173) by [Ericsssss](https://github.com/Ericsssss)
* feat: Modify system alarm policy query_conditions columns [#7171](https://github.com/deepflowio/deepflow/pull/7171) by [Ericsssss](https://github.com/Ericsssss)
* feat: OTel’s HTTP protocol parsing optimization in l7_flow_log [#7136](https://github.com/deepflowio/deepflow/pull/7136) by [lzf575](https://github.com/lzf575)
* feat: deepflow-ctl ingester support debugging by org id [#7133](https://github.com/deepflowio/deepflow/pull/7133) by [lzf575](https://github.com/lzf575)
* feat: agent support setting PACKET_FANOUT [#7126](https://github.com/deepflowio/deepflow/pull/7126) by [TomatoMr](https://github.com/TomatoMr)
* feat: add volcengine cloud platform for server controller [#7090](https://github.com/deepflowio/deepflow/pull/7090) by [askyrie](https://github.com/askyrie)
* feat: agent directly reports metrics that can be used for alert [#7089](https://github.com/deepflowio/deepflow/pull/7089) by [TomatoMr](https://github.com/TomatoMr)
* feat: server directly reports metrics of load1_by_cpu_num that can be used for alert [#7088](https://github.com/deepflowio/deepflow/pull/7088) by [lzf575](https://github.com/lzf575)

#### Refactoring
* refactor: OTel HTTP l7_protocol_str change from http to HTTP [#7292](https://github.com/deepflowio/deepflow/pull/7292) by [lzf575](https://github.com/lzf575)
* refactor: server recorder polishes id allocator [#7168](https://github.com/deepflowio/deepflow/pull/7168) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* refactor: Change crate name [#7155](https://github.com/deepflowio/deepflow/pull/7155) by [rvql](https://github.com/rvql)

#### Performance
* perf: add setting ttl_only_drop_parts to the CK table to make TTL more efficient [#7265](https://github.com/deepflowio/deepflow/pull/7265) by [lzf575](https://github.com/lzf575)
* perf: improve parsing RequestResource from http.url of OTel data [#7172](https://github.com/deepflowio/deepflow/pull/7172) by [lzf575](https://github.com/lzf575)

#### Documentation
* docs: rename opentemetry to opentelemetry [#7245](https://github.com/deepflowio/deepflow/pull/7245) by [lzf575](https://github.com/lzf575)


#### Chore
* chore: update cli dependencies [#7249](https://github.com/deepflowio/deepflow/pull/7249) by [lzf575](https://github.com/lzf575)
