# v6.5 Changelog

### DeepFlow release v6.5

#### New Feature
* feat: Add Changelog [#7095](https://github.com/deepflowio/deepflow/pull/7095)
* feat: CK’s username and password support the use of special characters [#7229](https://github.com/deepflowio/deepflow/pull/7119)

#### Bug Fix
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
* feat: Add volcengine icon const [#7232](https://github.com/deepflowio/deepflow/pull/7232) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat: add volcengine icon const [#7180](https://github.com/deepflowio/deepflow/pull/7180) by [askyrie](https://github.com/askyrie)

