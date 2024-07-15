### Table of Contents

**[DeepFlow release v6.5](#v65)**<br/>

# Changelog

### <a id="v65"></a>DeepFlow release v6.5

#### New Feature
* feat: Add Changelog [#7095](https://github.com/deepflowio/deepflow/pull/7095)
* feat: CK’s username and password support the use of special characters [#7229](https://github.com/deepflowio/deepflow/pull/7119)

#### Bug Fix
* fix: deepflow-server may panic when updating platform information [#7399](https://github.com/deepflowio/deepflow/pull/7399) by [lzf575](https://github.com/lzf575)
* fix: Add return processing to agent command [#7397](https://github.com/deepflowio/deepflow/pull/7397) by [roryye](https://github.com/roryye)
* fix: Fix windows compilation [#7390](https://github.com/deepflowio/deepflow/pull/7390) by [rvql](https://github.com/rvql)
* fix: Add filter to agent remote command and handle content when error… [#7382](https://github.com/deepflowio/deepflow/pull/7382) by [roryye](https://github.com/roryye)
* fix: Community Edition does not support multi-organization and multi-team features [#7375](https://github.com/deepflowio/deepflow/pull/7375) by [jin-xiaofeng](https://github.com/jin-xiaofeng)
* fix: agent wrong desensitized mysql trace_id [#7371](https://github.com/deepflowio/deepflow/pull/7371) by [TomatoMr](https://github.com/TomatoMr)
* fix: Add mysql error log to monitor module [#7364](https://github.com/deepflowio/deepflow/pull/7364) by [roryye](https://github.com/roryye)
* fix: agent - windows compile error [#7359](https://github.com/deepflowio/deepflow/pull/7359) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: agent - vm mac address not updated [#7356](https://github.com/deepflowio/deepflow/pull/7356) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: Fix missing pod interface in macvlan mode [#7336](https://github.com/deepflowio/deepflow/pull/7336) by [rvql](https://github.com/rvql)
* fix: agent - incorrect grpc ebpf tcp seq (#7333) [#7335](https://github.com/deepflowio/deepflow/pull/7335) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: Remove useless output from CLI [#7332](https://github.com/deepflowio/deepflow/pull/7332) by [roryye](https://github.com/roryye)
* fix: agent - missing mysql log [#7324](https://github.com/deepflowio/deepflow/pull/7324) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: if OrgID is set, deepflow-server stats should be stored in deepflow_tenant [#7322](https://github.com/deepflowio/deepflow/pull/7322) by [lzf575](https://github.com/lzf575)
* fix: server recorder fixes db query condition error [#7282](https://github.com/deepflowio/deepflow/pull/7282) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: manually created ips are deleted unexpectedly [#7310](https://github.com/deepflowio/deepflow/pull/7310) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: agent - incorrect http2 log [#7297](https://github.com/deepflowio/deepflow/pull/7297) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: the flow_tag of prometheus may be lost under multiple organizations [#7295](https://github.com/deepflowio/deepflow/pull/7295) by [lzf575](https://github.com/lzf575)
* fix: agent - eBPF Adjust Java syms-cache update logic & error log output [#7290](https://github.com/deepflowio/deepflow/pull/7290) by [yinjiping](https://github.com/yinjiping)
* fix: deepflow stats may write to wrong database [#7286](https://github.com/deepflowio/deepflow/pull/7286) by [lzf575](https://github.com/lzf575)
* fix: agent - eBPF Addressing excessive eBPF maps memory usage [#7276](https://github.com/deepflowio/deepflow/pull/7276) by [yinjiping](https://github.com/yinjiping)
* fix: Show metrics use query cache can be configured [#7271](https://github.com/deepflowio/deepflow/pull/7271) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: server recorder prints unnecessary error logs [#7264](https://github.com/deepflowio/deepflow/pull/7264) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: Network interface card list supports duplicate mac [#7253](https://github.com/deepflowio/deepflow/pull/7253) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: uses long connection to connect to CK for datasources manager [#7242](https://github.com/deepflowio/deepflow/pull/7242) by [lzf575](https://github.com/lzf575)
* fix: server recorder prints unnecessary error logs [#7192](https://github.com/deepflowio/deepflow/pull/7192) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: when modifying the TTL of the CK table fails, the connection to CK needs to be closed [#7202](https://github.com/deepflowio/deepflow/pull/7202) by [lzf575](https://github.com/lzf575)
* fix: getting wrong org-id and team-id when the Agent version is less than v6.5.9 [#7202](https://github.com/deepflowio/deepflow/pull/7202) by [lzf575](https://github.com/lzf575)
* fix: agent Packet fanout can only be set in TapMode::Local mode [#7229](https://github.com/deepflowio/deepflow/pull/7229) by [TomatoMr](https://github.com/TomatoMr)
* fix: Attribute supports Chinese [#7228](https://github.com/deepflowio/deepflow/pull/7228) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: agent - incorrect grpc log collected by uprobe [#7201](https://github.com/deepflowio/deepflow/pull/7201) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: Modify the value of team's short lcuuid corresponding to org_id [#7176](https://github.com/deepflowio/deepflow/pull/7176) by [jin-xiaofeng](https://github.com/jin-xiaofeng)
* fix: Only the default organization registers with tsdb [#7169](https://github.com/deepflowio/deepflow/pull/7169) by [jin-xiaofeng](https://github.com/jin-xiaofeng)
* fix: agent - eBPF Adjust syscall sendto() for IPv6 mapping to IPv4 [#7159](https://github.com/deepflowio/deepflow/pull/7159) by [yinjiping](https://github.com/yinjiping)
* fix: agent sync ignore loopback ip [#7153](https://github.com/deepflowio/deepflow/pull/7153) by [askyrie](https://github.com/askyrie)
* fix: agent - eBPF Ensure the Sofa protocol can reassemble [#7150](https://github.com/deepflowio/deepflow/pull/7150) by [yinjiping](https://github.com/yinjiping)
* fix: Repair collector network card list display incomplete [#7148](https://github.com/deepflowio/deepflow/pull/7148) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: server removes redundant function codes to avoid log errors [#7142](https://github.com/deepflowio/deepflow/pull/7142) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: agent - eBPF Resolve missing fork() syscall on arm64 [#7140](https://github.com/deepflowio/deepflow/pull/7140) by [yinjiping](https://github.com/yinjiping)
* fix: agent - eBPF DNS cannot obtain network tuple data [#7131](https://github.com/deepflowio/deepflow/pull/7131) by [yinjiping](https://github.com/yinjiping)
* fix: Ingester always update prometheus labels even if labels version has not change [#7129](https://github.com/deepflowio/deepflow/pull/7129) by [lzf575](https://github.com/lzf575)
* fix: k8s refresh close keep alive [#7117](https://github.com/deepflowio/deepflow/pull/7117) by [askyrie](https://github.com/askyrie)
* fix: server controller changes prometheus label version when data doe… [#7115](https://github.com/deepflowio/deepflow/pull/7115) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: agent - add sleep before exiting [#7112](https://github.com/deepflowio/deepflow/pull/7112) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: agent - eBPF Enhance Mongo/SOFA/MySQL/HTTP2 protocol inference [#7110](https://github.com/deepflowio/deepflow/pull/7110) by [yinjiping](https://github.com/yinjiping)
* fix: prometheus data cannot be labeled with universal tags，if slow-de… [#7101](https://github.com/deepflowio/deepflow/pull/7101) by [lzf575](https://github.com/lzf575)
* fix: agent - eBPF uprobe HTTP2 is missing setting for l7_proto [#7093](https://github.com/deepflowio/deepflow/pull/7093) by [yinjiping](https://github.com/yinjiping)
* fix: prometheus data cannot be labeled with universal tags, if slow-decoder is used. [#7100](https://github.com/deepflowio/deepflow/pull/7100)
* fix: agent - eBPF strengthening protocol inference for SOFARPC and MySQL [#7110](https://github.com/deepflowio/deepflow/pull/7110)
* fix: server controller changes prometheus label version when data does not change actually. [#7115](https://github.com/deepflowio/deepflow/pull/7115)
* fix: Ingester always update prometheus labels even if labels version has not changed.  [#7128](https://github.com/deepflowio/deepflow/pull/7128)

**[Changelog for v6.5](https://www.deepflow.io/docs/release-notes/release-6.5-ce)**<br/>

#### NEW FEATURE
* feat: sub domain support filter user id [#7408](https://github.com/deepflowio/deepflow/pull/7408) by [askyrie](https://github.com/askyrie)
* feat: sub domain support team [#7394](https://github.com/deepflowio/deepflow/pull/7394) by [askyrie](https://github.com/askyrie)
* feat: server uses sub_domain team id first when publishing message to tagrecorder [#7384](https://github.com/deepflowio/deepflow/pull/7384) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* feat: Allow overriding remote exec cmdline with async function [#7385](https://github.com/deepflowio/deepflow/pull/7385) by [rvql](https://github.com/rvql)
* feat: agent - add inner queue to mirror dispatcher [#7345](https://github.com/deepflowio/deepflow/pull/7345) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: Agent remote exec returns specific errors [#7334](https://github.com/deepflowio/deepflow/pull/7334) by [roryye](https://github.com/roryye)
* feat: Add command for java stack/heap dump [#7319](https://github.com/deepflowio/deepflow/pull/7319) by [rvql](https://github.com/rvql)
* feat: agent - eBPF Whitelist implementation reassembly [#7309](https://github.com/deepflowio/deepflow/pull/7309) by [yinjiping](https://github.com/yinjiping)
* feat: agent - support vhost user [#7269](https://github.com/deepflowio/deepflow/pull/7269) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: add debug ctl to rebalance agent by traffic [#7261](https://github.com/deepflowio/deepflow/pull/7261) by [roryye](https://github.com/roryye)
* feat: agent - eBPF Add JAVA symbol file generation log [#7257](https://github.com/deepflowio/deepflow/pull/7257) by [yinjiping](https://github.com/yinjiping)
* feat: Add volcengine icon const [#7232](https://github.com/deepflowio/deepflow/pull/7232) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat: add volcengine icon const [#7180](https://github.com/deepflowio/deepflow/pull/7180) by [askyrie](https://github.com/askyrie)
* feat: Dictionary adds auto-close connection [#7165](https://github.com/deepflowio/deepflow/pull/7165) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat: deepflow-ctl ingester support debugging by org id [#7163](https://github.com/deepflowio/deepflow/pull/7163) by [lzf575](https://github.com/lzf575)
* feat: add volcengine cloud platform for server controller [#7149](https://github.com/deepflowio/deepflow/pull/7149) by [askyrie](https://github.com/askyrie)
* feat: agent support setting PACKET_FANOUT [#7138](https://github.com/deepflowio/deepflow/pull/7138) by [TomatoMr](https://github.com/TomatoMr)
* feat: CK’s username and password support the use of special characters [#7120](https://github.com/deepflowio/deepflow/pull/7120) by [lzf575](https://github.com/lzf575)
* feat: server - add ebpf event type mem alloc/inuse [#7106](https://github.com/deepflowio/deepflow/pull/7106) by [rvql](https://github.com/rvql)
* feat: add change log [#7095](https://github.com/deepflowio/deepflow/pull/7095) by [Nick-0314](https://github.com/Nick-0314)

#### Refactoring
* refactor: Change crate name [#7158](https://github.com/deepflowio/deepflow/pull/7158) by [rvql](https://github.com/rvql)


#### Documentation
* docs: rename opentemetry to opentelemetry [#7246](https://github.com/deepflowio/deepflow/pull/7246) by [lzf575](https://github.com/lzf575)


#### Chore
* chore: bump golang.org/x/net to v0.27.0 [#7306](https://github.com/deepflowio/deepflow/pull/7306) by [zhangzujian](https://github.com/zhangzujian)
* chore: update cli dependencies [#7250](https://github.com/deepflowio/deepflow/pull/7250) by [lzf575](https://github.com/lzf575)

#### OTHER
* bump golang.org/x/net to v0.26.0 [#7234](https://github.com/deepflowio/deepflow/pull/7234) by [zhangzujian](https://github.com/zhangzujian)


#### Performance
* perf: add setting ttl_only_drop_parts to the CK table to make TTL more efficient [#7266](https://github.com/deepflowio/deepflow/pull/7266) by [lzf575](https://github.com/lzf575)


#### Testing
* chore: use the latest go version to build server/cli [#7235](https://github.com/deepflowio/deepflow/pull/7235) by [zhangzujian](https://github.com/zhangzujian)
