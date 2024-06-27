# v6.5 Changelog

### DeepFlow release v6.5

#### New Feature
* feat: Add Changelog [#7095](https://github.com/deepflowio/deepflow/pull/7095)
* feat: CK’s username and password support the use of special characters [#7229](https://github.com/deepflowio/deepflow/pull/7119)

#### Bug Fix
* fix: prometheus data cannot be labeled with universal tags, if slow-decoder is used. [#7100](https://github.com/deepflowio/deepflow/pull/7100)
* fix: agent - eBPF strengthening protocol inference for SOFARPC and MySQL [#7110](https://github.com/deepflowio/deepflow/pull/7110)
* fix: server controller changes prometheus label version when data does not change actually. [#7115](https://github.com/deepflowio/deepflow/pull/7115)
* fix: k8s refresh api http client close keep alive. [#7117](https://github.com/deepflowio/deepflow/pull/7117)
* fix: Ingester always update prometheus labels even if labels version has not changed.  [#7128](https://github.com/deepflowio/deepflow/pull/7128)

**[Changelog for v6.5](https://www.deepflow.io/docs/release-notes/release-6.5-ce)**<br/>
