# v6.5 Changelog

### DeepFlow release v6.5

#### New Feature
* feat: Add Changelog [#7095](https://github.com/deepflowio/deepflow/pull/7095)
* feat: CK’s username and password support the use of special characters [#7229](https://github.com/deepflowio/deepflow/pull/7119)

#### Bug Fix
* fix: node vm lcuuid duplicate [#9463](https://github.com/deepflowio/deepflow/pull/9463) by [askyrie](https://github.com/askyrie)
* fix: add log to agent remote command [#7521](https://github.com/deepflowio/deepflow/pull/7521) by [roryye](https://github.com/roryye)
* fix: Do not verify dynamic tags [#7505](https://github.com/deepflowio/deepflow/pull/7505) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: agent - eBPF Continuous Java profiling support for linux 3.10 [#7485](https://github.com/deepflowio/deepflow/pull/7485) by [yinjiping](https://github.com/yinjiping)
* fix: update agent commands permission [#7481](https://github.com/deepflowio/deepflow/pull/7481) by [roryye](https://github.com/roryye)
* fix: process resource api does not response sub_domain field [#7448](https://github.com/deepflowio/deepflow/pull/7448) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: Fix the problem of duplicate fields in select [#7436](https://github.com/deepflowio/deepflow/pull/7436) by [xiaochaoren1](https://github.com/xiaochaoren1)
* fix: recorder reports wrong sub_domain infomation in domain logs [#7435](https://github.com/deepflowio/deepflow/pull/7435) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: Fix concurrent request command for the same agent [#7431](https://github.com/deepflowio/deepflow/pull/7431) by [roryye](https://github.com/roryye)
* fix: Uniq operator error [#7402](https://github.com/deepflowio/deepflow/pull/7402) by [xiaochaoren1](https://github.com/xiaochaoren1)
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
* fix: prometheus data cannot be labeled with universal tags, if slow-decoder is used. [#7100](https://github.com/deepflowio/deepflow/pull/7100)
* fix: agent - eBPF strengthening protocol inference for SOFARPC and MySQL [#7110](https://github.com/deepflowio/deepflow/pull/7110)
* fix: server controller changes prometheus label version when data does not change actually. [#7115](https://github.com/deepflowio/deepflow/pull/7115)
* fix: k8s refresh api http client close keep alive. [#7117](https://github.com/deepflowio/deepflow/pull/7117)
* fix: Ingester always update prometheus labels even if labels version has not changed.  [#7128](https://github.com/deepflowio/deepflow/pull/7128)

**[Changelog for v6.5](https://www.deepflow.io/docs/release-notes/release-6.5-ce)**<br/>

#### NEW FEATURE
* feat: agent - eBPF Add a Musl flag option [#9022](https://github.com/deepflowio/deepflow/pull/9022) by [yinjiping](https://github.com/yinjiping)
* feat: agent - eBPF Add an extended directory [#9019](https://github.com/deepflowio/deepflow/pull/9019) by [yinjiping](https://github.com/yinjiping)
* feat: agent - eBPF Add compilation for extension files [#9015](https://github.com/deepflowio/deepflow/pull/9015) by [yinjiping](https://github.com/yinjiping)
* feat: agent - eBPF Adaptation for TLinux 4.14.105-19-0019 [#9014](https://github.com/deepflowio/deepflow/pull/9014) by [yinjiping](https://github.com/yinjiping)
* feat: updatae tunnel decap feature [#8591](https://github.com/deepflowio/deepflow/pull/8591) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: agent - support server port [#7518](https://github.com/deepflowio/deepflow/pull/7518) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: agent adds the CommandParam fields, modifies the param validation method [#7516](https://github.com/deepflowio/deepflow/pull/7516) by [TomatoMr](https://github.com/TomatoMr)
* feat: agent - eBPF Persist Java symbol table [#7325](https://github.com/deepflowio/deepflow/pull/7325) by [yinjiping](https://github.com/yinjiping)
* feat: prevents dirty data from increasing MySQL IO [#7499](https://github.com/deepflowio/deepflow/pull/7499) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* feat: Server exporters support tag-filter-condition config (#7492) [#7493](https://github.com/deepflowio/deepflow/pull/7493) by [ZhuoZhuoCrayon](https://github.com/ZhuoZhuoCrayon)
* feat: agent - eBPF Remove tracing for HEAD type requests in NGINX [#7489](https://github.com/deepflowio/deepflow/pull/7489) by [yinjiping](https://github.com/yinjiping)
* feat: Querier support no limit [#7479](https://github.com/deepflowio/deepflow/pull/7479) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat:  Ingester support trace_tree [#7443](https://github.com/deepflowio/deepflow/pull/7443) by [lzf575](https://github.com/lzf575)
* feat: agent - dispatcher support set cpu affinity [#7423](https://github.com/deepflowio/deepflow/pull/7423) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: create sub domian set default team id [#7421](https://github.com/deepflowio/deepflow/pull/7421) by [askyrie](https://github.com/askyrie)
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

#### Documentation
* docs: rename opentemetry to opentelemetry [#7246](https://github.com/deepflowio/deepflow/pull/7246) by [lzf575](https://github.com/lzf575)


#### Chore
* chore: bump golang.org/x/net to v0.27.0 [#7306](https://github.com/deepflowio/deepflow/pull/7306) by [zhangzujian](https://github.com/zhangzujian)
* chore: update cli dependencies [#7250](https://github.com/deepflowio/deepflow/pull/7250) by [lzf575](https://github.com/lzf575)

#### OTHER
* V65 trace map [#7445](https://github.com/deepflowio/deepflow/pull/7445) by [taloric](https://github.com/taloric)
* bump golang.org/x/net to v0.26.0 [#7234](https://github.com/deepflowio/deepflow/pull/7234) by [zhangzujian](https://github.com/zhangzujian)

#### Performance
* perf: add setting ttl_only_drop_parts to the CK table to make TTL more efficient [#7266](https://github.com/deepflowio/deepflow/pull/7266) by [lzf575](https://github.com/lzf575)


#### Testing
* chore: use the latest go version to build server/cli [#7235](https://github.com/deepflowio/deepflow/pull/7235) by [zhangzujian](https://github.com/zhangzujian)
