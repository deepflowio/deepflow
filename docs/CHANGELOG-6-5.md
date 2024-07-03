### Table of Contents

**[DeepFlow release v6.5](#v65)**<br/>

# Changelog

### <a id="v65"></a>DeepFlow release v6.5

#### New Feature
* feat: Add Changelog [#7095](https://github.com/deepflowio/deepflow/pull/7095)
* feat: CK’s username and password support the use of special characters [#7229](https://github.com/deepflowio/deepflow/pull/7119)

#### Bug Fix

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

#### OTHER

* Cp 65 73 [#7202](https://github.com/deepflowio/deepflow/pull/7202) by [lzf575](https://github.com/lzf575)
