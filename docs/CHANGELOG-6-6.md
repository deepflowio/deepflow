### Table of Contents

**[DeepFlow release v6.6](#v6.6)**<br/>

# Changelog

### <a id="v6.6"></a>DeepFlow release v6.6

#### New Feature

#### Bug Fix
* fix: nil pointer may cause panic [#8671](https://github.com/deepflowio/deepflow/pull/8671) by [lzf575](https://github.com/lzf575)
* fix: agent config file.io_event.collect_mode [#8669](https://github.com/deepflowio/deepflow/pull/8669) by [askyrie](https://github.com/askyrie)
* fix: adapt pprof u64 params [#8667](https://github.com/deepflowio/deepflow/pull/8667) by [taloric](https://github.com/taloric)
* fix: agent group configuration api response unexcepted value [#8655](https://github.com/deepflowio/deepflow/pull/8655) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: add alarm_label table [#8644](https://github.com/deepflowio/deepflow/pull/8644) by [SongZhen0704](https://github.com/SongZhen0704)
* fix: modify agent config example [#8649](https://github.com/deepflowio/deepflow/pull/8649) by [yuanchaoa](https://github.com/yuanchaoa)
* fix: parse 1d aggr table failed [#8646](https://github.com/deepflowio/deepflow/pull/8646) by [lzf575](https://github.com/lzf575)
* fix: errors occurred when modifying some agent group configuration [#8605](https://github.com/deepflowio/deepflow/pull/8605) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* fix: TODOs in agent config [#8597](https://github.com/deepflowio/deepflow/pull/8597) by [rvql](https://github.com/rvql)
* fix: pcap,l4_packet,spantrace data exception [#8595](https://github.com/deepflowio/deepflow/pull/8595) by [lzf575](https://github.com/lzf575)
* fix: trim-tunnel-type has not taken effect [#8578](https://github.com/deepflowio/deepflow/pull/8578) by [yuanchaoa](https://github.com/yuanchaoa)

#### Performance
* perf: add primary key for in_process table [#8624](https://github.com/deepflowio/deepflow/pull/8624) by [lzf575](https://github.com/lzf575)
* perf: modify materialized view local table without group by [#8576](https://github.com/deepflowio/deepflow/pull/8576) by [lzf575](https://github.com/lzf575)

#### NEW FEATURE
* feat: querier supports show enum tags by language [#8673](https://github.com/deepflowio/deepflow/pull/8673) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat: add resource association abnormal alarm [#8659](https://github.com/deepflowio/deepflow/pull/8659) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat: adds resource synchronization delay alarms [#8657](https://github.com/deepflowio/deepflow/pull/8657) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* feat: sender add compress flag [#8654](https://github.com/deepflowio/deepflow/pull/8654) by [taloric](https://github.com/taloric)
* feat: support fanout in mirror mode and analyzer mode [#8643](https://github.com/deepflowio/deepflow/pull/8643) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: optimize memory [#8572](https://github.com/deepflowio/deepflow/pull/8572) by [yuanchaoa](https://github.com/yuanchaoa)
* feat: querier add version check [#8622](https://github.com/deepflowio/deepflow/pull/8622) by [xiaochaoren1](https://github.com/xiaochaoren1)
* feat: register esxi vtap support cloudtower [#8613](https://github.com/deepflowio/deepflow/pull/8613) by [askyrie](https://github.com/askyrie)
* feature: adds index to some tables [#8598](https://github.com/deepflowio/deepflow/pull/8598) by [ZhengYa-0110](https://github.com/ZhengYa-0110)
* feature: adds system alarm of recorder cleaner [#8588](https://github.com/deepflowio/deepflow/pull/8588) by [ZhengYa-0110](https://github.com/ZhengYa-0110)

#### Documentation
* docs: update agent config doc [#8661](https://github.com/deepflowio/deepflow/pull/8661) by [sharang](https://github.com/sharang)


#### Refactoring
* refactor: Remove legacy agent config [#8656](https://github.com/deepflowio/deepflow/pull/8656) by [rvql](https://github.com/rvql)
