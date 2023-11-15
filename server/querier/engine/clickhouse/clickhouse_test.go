/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package clickhouse

import (
	"context"
	"strconv"

	//"github.com/k0kubun/pp"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/parse"

	//"github.com/deepflowio/deepflow/server/querier/querier"
	"testing"

	"github.com/deepflowio/deepflow/server/querier/config"
)

/* var (
	parsetest = []struct {
		input string
	}{{
		input: "select Rspread(byte) as rspread_byte from l4_flow_log",
	}}
) */

var (
	parseSQL = []struct {
		index  string
		input  string
		output string
		db     string
	}{{
		input:  "select byte from l4_flow_log limit 1",
		output: "SELECT byte_tx+byte_rx AS `byte` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Sum(byte)/Time_interval as sum_byte, time(time, 120) as time_120 from l4_flow_log group by time_120 having Sum(byte)>=0 limit 10 offset 20",
		output: "WITH toStartOfInterval(time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS `_time_120` SELECT toUnixTimestamp(`_time_120`) AS `time_120`, divide(SUM(byte_tx+byte_rx), 120) AS `sum_byte` FROM flow_log.`l4_flow_log` GROUP BY `time_120` HAVING SUM(byte_tx+byte_rx) >= 0 LIMIT 20, 10",
	}, {
		input:  "select Sum(log_count) as sum_log_count from l4_flow_log order by sum_log_count desc limit 1",
		output: "SELECT SUM(1) AS `sum_log_count` FROM flow_log.`l4_flow_log` ORDER BY `sum_log_count` desc LIMIT 1",
	}, {
		input:  "select Uniq(ip_0) as uniq_ip_0 from l4_flow_log limit 1",
		output: "SELECT uniqIf([toString(ip4_0), toString(is_ipv4), toString(ip6_0)], NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))) AS `uniq_ip_0` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Max(byte) as max_byte, Sum(log_count) as sum_log_count from l4_flow_log having Sum(byte)>=0 limit 1",
		output: "SELECT MAX(byte_tx+byte_rx) AS `max_byte`, SUM(1) AS `sum_log_count` FROM flow_log.`l4_flow_log` HAVING SUM(byte_tx+byte_rx) >= 0 LIMIT 1",
	}, {
		input:  "select (Max(byte_tx) + Sum(byte_tx))/1 as max_byte_tx from l4_flow_log limit 1",
		output: "SELECT divide(plus(MAX(byte_tx), SUM(byte_tx)), 1) AS `max_byte_tx` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Avg(byte_tx) as avg_byte_tx from l4_flow_log where `time`>=60 and `time`<=180 having Spread(byte_tx)>=0 limit 1",
		output: "SELECT AVG(byte_tx) AS `avg_byte_tx` FROM flow_log.`l4_flow_log` PREWHERE `time` >= 60 AND `time` <= 180 HAVING minus(MAX(byte_tx), MIN(byte_tx)) >= 0 LIMIT 1",
	}, {
		input:  "select Stddev(byte_tx) as stddev_byte_tx from l4_flow_log limit 1",
		output: "SELECT stddevPopStable(byte_tx) AS `stddev_byte_tx` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx from l4_flow_log order by max_byte_tx limit 1",
		output: "SELECT MAX(byte_tx) AS `max_byte_tx` FROM flow_log.`l4_flow_log` ORDER BY `max_byte_tx` asc LIMIT 1",
	}, {
		input:  "select Spread(byte_tx) as spread_byte_tx from l4_flow_log where `time`>=60 and `time`<=180 limit 1",
		output: "SELECT minus(MAX(byte_tx), MIN(byte_tx)) AS `spread_byte_tx` FROM flow_log.`l4_flow_log` PREWHERE `time` >= 60 AND `time` <= 180 LIMIT 1",
	}, {
		input:  "select Rspread(byte_tx) as rspread_byte_tx from l4_flow_log where `time`>=60 and `time`<=180 limit 1",
		output: "SELECT divide(MAX(byte_tx)+1e-15, MIN(byte_tx)+1e-15) AS `rspread_byte_tx` FROM flow_log.`l4_flow_log` PREWHERE `time` >= 60 AND `time` <= 180 LIMIT 1",
	}, {
		input:  "select Rspread(rtt) as rspread_rtt from l4_flow_log limit 1",
		output: "SELECT divide(MAXIf(rtt, rtt >= 0)+1e-15, MINIf(rtt, rtt >= 0)+1e-15) AS `rspread_rtt` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Percentile(byte_tx, 50) as percentile_byte_tx from l4_flow_log limit 1",
		output: "SELECT quantile(50)(byte_tx) AS `percentile_byte_tx` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Avg(rtt) as avg_rtt from l4_flow_log where time >= 100+1 and time <= 102 limit 1",
		output: "SELECT AVGIf(rtt, rtt >= 0) AS `avg_rtt` FROM flow_log.`l4_flow_log` PREWHERE `time` >= 100 + 1 AND `time` <= 102 LIMIT 1",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx, Avg(rtt) as avg_rtt from l4_flow_log limit 1",
		output: "SELECT MAX(byte_tx) AS `max_byte_tx`, AVGIf(rtt, rtt >= 0) AS `avg_rtt` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select ((Max(byte_tx))+Avg(rtt ))/(1-Avg(rtt )) as avg_rtt from l4_flow_log limit 1",
		output: "SELECT divide(plus(MAX(byte_tx), AVGIf(rtt, rtt >= 0)), minus(1, AVGIf(rtt, rtt >= 0))) AS `avg_rtt` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Apdex(rtt, 100) as apdex_rtt_100 from l4_flow_log limit 1",
		output: "WITH if(COUNT()>0, divide(plus(SUM(if(rtt<=100,1,0)), SUM(if(100<rtt AND rtt<=100*4,0.5,0))), COUNT()), null) AS `divide_0diveider_as_null_plus_apdex_satisfy_rtt_100_apdex_toler_rtt_100_count_` SELECT `divide_0diveider_as_null_plus_apdex_satisfy_rtt_100_apdex_toler_rtt_100_count_`*100 AS `apdex_rtt_100` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Max(byte) as max_byte, time(time,120) as time_120 from l4_flow_log group by time_120 having Min(byte)>=0 limit 1",
		output: "WITH toStartOfInterval(time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS `_time_120` SELECT toUnixTimestamp(`_time_120`) AS `time_120`, MAX(byte_tx+byte_rx) AS `max_byte` FROM flow_log.`l4_flow_log` GROUP BY `time_120` HAVING MIN(byte_tx+byte_rx) >= 0 LIMIT 1",
	}, {
		input:  "select Max(byte) as max_byte, time(time,86400) as time_120 from l4_flow_log group by time_120 having Min(byte)>=0 limit 1",
		output: "WITH toStartOfInterval(time, toIntervalDay(1)) + toIntervalDay(arrayJoin([0]) * 1) AS `_time_120` SELECT toUnixTimestamp(`_time_120`) AS `time_120`, MAX(byte_tx+byte_rx) AS `max_byte` FROM flow_log.`l4_flow_log` GROUP BY `time_120` HAVING MIN(byte_tx+byte_rx) >= 0 LIMIT 1",
	}, {
		input:  "select Max(byte) as 'max_byte',region_0,chost_id_1 from l4_flow_log group by region_0,chost_id_1 limit 1",
		output: "SELECT dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`, if(l3_device_type_1=1,l3_device_id_1, 0) AS `chost_id_1`, MAX(byte_tx+byte_rx) AS `max_byte` FROM flow_log.`l4_flow_log` PREWHERE (l3_device_id_1!=0 AND l3_device_type_1=1) GROUP BY dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`, if(l3_device_type_1=1,l3_device_id_1, 0) AS `chost_id_1` LIMIT 1",
	}, {
		input:  "select Percentage(Max(byte)+100,100) as percentage_max_byte_100 from l4_flow_log limit 1",
		output: "SELECT divide(plus(MAX(byte_tx+byte_rx), 100), 100)*100 AS `percentage_max_byte_100` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		input:  "select Sum(rtt) as sum_rtt from l4_flow_log having Percentage(Max(byte), 100) >= 1 limit 1",
		output: "SELECT SUMIf(rtt, rtt >= 0) AS `sum_rtt` FROM flow_log.`l4_flow_log` HAVING divide(MAX(byte_tx+byte_rx), 100)*100 >= 1 LIMIT 1",
	}, {
		input:  "select time(time, 60) as toi, PerSecond(Sum(byte)+100) as persecond_max_byte_100 from l4_flow_log group by toi limit 1",
		output: "WITH toStartOfInterval(time, toIntervalSecond(60)) + toIntervalSecond(arrayJoin([0]) * 60) AS `_toi` SELECT toUnixTimestamp(`_toi`) AS `toi`, divide(plus(SUM(byte_tx+byte_rx), 100), 60) AS `persecond_max_byte_100` FROM flow_log.`l4_flow_log` GROUP BY `toi` LIMIT 1",
	}, {
		input:  "select resource_gl0_0,ip_0 from l7_flow_log where ip_0='1.1.1.1' group by resource_gl0_0,ip_0",
		output: "SELECT if(auto_instance_type_0 in (0,255),if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)),dictGet(flow_tag.device_map, 'name', (toUInt64(auto_instance_type_0),toUInt64(auto_instance_id_0)))) AS `resource_gl0_0`, if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS `ip_0`, auto_instance_type_0 AS `resource_gl0_type_0` FROM flow_log.`l7_flow_log` PREWHERE (((if(is_ipv4=1, hex(ip4_0), hex(ip6_0)) = hex(toIPv4('1.1.1.1'))))) GROUP BY if(auto_instance_type_0 in (0,255),if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)),dictGet(flow_tag.device_map, 'name', (toUInt64(auto_instance_type_0),toUInt64(auto_instance_id_0)))) AS `resource_gl0_0`, `resource_gl0_type_0`, if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS `ip_0` LIMIT 10000",
	}, {
		input:  "select pod_service_0 from l7_flow_log where pod_service_0 !='xx' group by pod_service_0",
		output: "SELECT dictGet(flow_tag.device_map, 'name', (toUInt64(11),toUInt64(service_id_0))) AS `pod_service_0` FROM flow_log.`l7_flow_log` PREWHERE (not(((if(is_ipv4=1,IPv4NumToString(ip4_0),IPv6NumToString(ip6_0)),toUInt64(l3_epc_id_0)) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE pod_service_name = 'xx')) OR (toUInt64(service_id_0) IN (SELECT pod_service_id FROM flow_tag.ip_relation_map WHERE pod_service_name = 'xx')))) AND (service_id_0!=0) GROUP BY dictGet(flow_tag.device_map, 'name', (toUInt64(11),toUInt64(service_id_0))) AS `pod_service_0` LIMIT 10000",
	}, {
		input:  "select region_id_0 from l7_flow_log where pod_ingress_0 !='xx' group by region_id_0",
		output: "SELECT region_id_0 FROM flow_log.`l7_flow_log` PREWHERE (not(((if(is_ipv4=1,IPv4NumToString(ip4_0),IPv6NumToString(ip6_0)),toUInt64(l3_epc_id_0)) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE pod_ingress_name = 'xx')) OR (toUInt64(service_id_0) IN (SELECT pod_service_id FROM flow_tag.ip_relation_map WHERE pod_ingress_name = 'xx')))) GROUP BY `region_id_0` LIMIT 10000",
	}, {
		input:  "select node_type(region_0) as `node_type_0`,mask(ip_0,33) as `mask_ip_0` from l7_flow_log group by `mask_ip_0`,`node_type_0`",
		output: "WITH if(is_ipv4, IPv4NumToString(bitAnd(ip4_0, 4294967295)), IPv6NumToString(bitAnd(ip6_0, toFixedString(unhex('ffffffff800000000000000000000000'), 16)))) AS `mask_ip_0` SELECT 'region' AS `node_type_0`, `mask_ip_0` FROM flow_log.`l7_flow_log` GROUP BY `mask_ip_0`, `node_type_0` LIMIT 10000",
	}, {
		input:  "select region_id_0 from l7_flow_log group by region_id_0,chost_id_1",
		output: "SELECT region_id_0, if(l3_device_type_1=1,l3_device_id_1, 0) AS `chost_id_1` FROM flow_log.`l7_flow_log` PREWHERE (l3_device_id_1!=0 AND l3_device_type_1=1) GROUP BY `region_id_0`, if(l3_device_type_1=1,l3_device_id_1, 0) AS `chost_id_1` LIMIT 10000",
	}, {
		input:  "SELECT ip_0 FROM l4_flow_log WHERE  ((is_internet_1=1) OR (is_internet_0=1)) GROUP BY ip_0 limit 1",
		output: "SELECT if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS `ip_0` FROM flow_log.`l4_flow_log` PREWHERE (((l3_epc_id_1 = -2)) OR ((l3_epc_id_0 = -2))) GROUP BY if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS `ip_0` LIMIT 1",
	}, {
		input:  "select Sum(byte) as `流量总量`, region_0 as `区域` from l4_flow_log where 1=1 group by `区域` order by `流量总量` desc",
		output: "SELECT dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `区域`, SUM(byte_tx+byte_rx) AS `流量总量` FROM flow_log.`l4_flow_log` PREWHERE 1 = 1 GROUP BY `区域` ORDER BY `流量总量` desc LIMIT 10000",
	}, {
		input:  "select byte as `123` from l4_flow_log where 1=1 group by `123` order by `123` limit 1 ",
		output: "SELECT byte_tx+byte_rx AS `123` FROM flow_log.`l4_flow_log` PREWHERE 1 = 1 GROUP BY `123` ORDER BY `123` asc LIMIT 1",
	}, {
		input:  "select byte from l4_flow_log where ip>=('1.1.1.1/24','2.2.2.2') and ip<='::/24'",
		output: "SELECT byte_tx+byte_rx AS `byte` FROM flow_log.`l4_flow_log` PREWHERE (((if(is_ipv4=1, hex(ip4), hex(ip6)) >= hex(toIPv4('1.1.1.255'))) OR (if(is_ipv4=1, hex(ip4), hex(ip6)) >= hex(toIPv4('2.2.2.2'))))) AND (((if(is_ipv4=1, hex(ip4), hex(ip6)) <= hex(toIPv6('::'))))) LIMIT 10000",
	}, {
		input:  "select `k8s.label.statefulset.kubernetes.io/pod-name_0` from l4_flow_log where `k8s.label.statefulset.kubernetes.io/pod-name_0`='opensource-loki-0' group by `k8s.label.statefulset.kubernetes.io/pod-name_0`",
		output: "SELECT if(dictGet(flow_tag.pod_service_k8s_label_map, 'value', (toUInt64(service_id_0),'statefulset.kubernetes.io/pod-name'))!='', dictGet(flow_tag.pod_service_k8s_label_map, 'value', (toUInt64(service_id_0),'statefulset.kubernetes.io/pod-name')), dictGet(flow_tag.pod_k8s_label_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) ) AS `k8s.label.statefulset.kubernetes.io/pod-name_0` FROM flow_log.`l4_flow_log` PREWHERE ((toUInt64(service_id_0) IN (SELECT id FROM flow_tag.pod_service_k8s_label_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name')) OR (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_label_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name'))) AND (((toUInt64(service_id_0) IN (SELECT id FROM flow_tag.pod_service_k8s_label_map WHERE key='statefulset.kubernetes.io/pod-name')) OR (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_label_map WHERE key='statefulset.kubernetes.io/pod-name')))) GROUP BY `k8s.label.statefulset.kubernetes.io/pod-name_0` LIMIT 10000",
	}, {
		input:  "select `k8s.label.statefulset.kubernetes.io/pod-name_0` as `k8s.label.abc` from l4_flow_log where `k8s.label.abc`='opensource-loki-0' group by `k8s.label.abc`",
		output: "SELECT if(dictGet(flow_tag.pod_service_k8s_label_map, 'value', (toUInt64(service_id_0),'statefulset.kubernetes.io/pod-name'))!='', dictGet(flow_tag.pod_service_k8s_label_map, 'value', (toUInt64(service_id_0),'statefulset.kubernetes.io/pod-name')), dictGet(flow_tag.pod_k8s_label_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) ) AS `k8s.label.abc` FROM flow_log.`l4_flow_log` PREWHERE ((toUInt64(service_id_0) IN (SELECT id FROM flow_tag.pod_service_k8s_label_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name')) OR (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_label_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name'))) AND (((toUInt64(service_id_0) IN (SELECT id FROM flow_tag.pod_service_k8s_label_map WHERE key='statefulset.kubernetes.io/pod-name')) OR (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_label_map WHERE key='statefulset.kubernetes.io/pod-name')))) GROUP BY `k8s.label.abc` LIMIT 10000",
	}, {
		input:  "select `attribute.cc` as `attribute.abc` from l7_flow_log where `attribute.abc`='opensource-loki-0' group by `attribute.abc`",
		output: "SELECT attribute_values[indexOf(attribute_names,'cc')] AS `attribute.abc` FROM flow_log.`l7_flow_log` PREWHERE attribute_values[indexOf(attribute_names,'cc')] = 'opensource-loki-0' AND (`attribute.abc` != '') GROUP BY `attribute.abc` LIMIT 10000",
	}, {
		input:  "select `tag.cc` as `tag.abc` from cpu where `tag.abc`='opensource-loki-0' group by `tag.abc`",
		output: "SELECT tag_values[indexOf(tag_names,'cc')] AS `tag.abc` FROM ext_metrics.`metrics` PREWHERE (virtual_table_name='cpu') AND tag_values[indexOf(tag_names,'cc')] = 'opensource-loki-0' AND (`tag.abc` != '') GROUP BY `tag.abc` LIMIT 10000",
		db:     "ext_metrics",
	}, {
		input:  "select `metrics.storageclass_annotations` AS `job_info` from prometheus_kube",
		output: "SELECT if(indexOf(metrics_float_names, 'storageclass_annotations')=0,null,metrics_float_values[indexOf(metrics_float_names, 'storageclass_annotations')]) AS `job_info` FROM ext_metrics.`metrics` PREWHERE (virtual_table_name='prometheus_kube') LIMIT 10000",
		db:     "ext_metrics",
	}, {
		input:  "select Sum(`metrics.pending`) from `deepflow_server.queue`",
		output: "SELECT SUM(if(indexOf(metrics_float_names, 'pending')=0,null,metrics_float_values[indexOf(metrics_float_names, 'pending')])) AS `Sum(metrics.pending)` FROM deepflow_system.`deepflow_system` PREWHERE (virtual_table_name='deepflow_server.queue') LIMIT 10000",
		db:     "deepflow_system",
	}, {
		input:  "select `k8s.label_0` from l7_flow_log",
		output: "SELECT if(dictGetOrDefault(flow_tag.pod_service_k8s_labels_map, 'labels', toUInt64(service_id_0),'{}')!='{}', dictGetOrDefault(flow_tag.pod_service_k8s_labels_map, 'labels', toUInt64(service_id_0),'{}'), dictGetOrDefault(flow_tag.pod_k8s_labels_map, 'labels', toUInt64(pod_id_0),'{}'))  AS `k8s.label_0` FROM flow_log.`l7_flow_log` LIMIT 10000",
	}, {
		input:  "select `metrics.xxx.yyy` as xxx from l7_flow_log",
		output: "SELECT if(indexOf(metrics_names, 'xxx.yyy')=0,null,metrics_values[indexOf(metrics_names, 'xxx.yyy')]) AS `xxx` FROM flow_log.`l7_flow_log` LIMIT 10000",
	}, {
		input:  "select `metrics.xxx` as xxx from cpu",
		output: "SELECT if(indexOf(metrics_float_names, 'xxx')=0,null,metrics_float_values[indexOf(metrics_float_names, 'xxx')]) AS `xxx` FROM ext_metrics.`metrics` PREWHERE (virtual_table_name='cpu') LIMIT 10000",
		db:     "ext_metrics",
	}, {
		input:  "select Percentile(`metrics.xxx`, 0.9) as xxx from cpu",
		output: "SELECT quantile(0.9)(if(indexOf(metrics_float_names, 'xxx')=0,null,metrics_float_values[indexOf(metrics_float_names, 'xxx')])) AS `xxx` FROM ext_metrics.`metrics` PREWHERE (virtual_table_name='cpu') LIMIT 10000",
		db:     "ext_metrics",
	}, {
		input:  "select Sum(packet_count) as count from l4_packet",
		output: "SELECT SUM(packet_count) AS `count` FROM flow_log.`l4_packet` LIMIT 10000",
	}, {
		input:  "select Sum(packet_count) as count from l7_packet",
		output: "SELECT SUM(packet_count) AS `count` FROM flow_log.`l7_packet` LIMIT 10000",
	}, {
		input:  "select Sum(byte_tx) as max_byte from l4_flow_log order by length(tap_side) desc, `length(tap_side)`",
		output: "SELECT SUM(byte_tx) AS `max_byte` FROM flow_log.`l4_flow_log` ORDER BY length(tap_side) desc,`length(tap_side)` asc LIMIT 10000",
	}, {
		input:  "select Enum(tap_side) from l7_flow_log limit 0, 50",
		output: "WITH dictGetOrDefault(flow_tag.string_enum_map, 'name', ('tap_side',tap_side), tap_side) AS `Enum(tap_side)` SELECT `Enum(tap_side)` FROM flow_log.`l7_flow_log` LIMIT 0, 50",
	}, {
		input:  "select Avg(`byte_tx`) AS `Avg(byte_tx)`,icon_id(chost_0) as `xx`,region_0 from vtap_flow_edge_port group by region_0 limit 1",
		output: "SELECT `xx`, region_0, AVG(`_sum_byte_tx`) AS `Avg(byte_tx)` FROM (WITH if(l3_device_type_0=1, dictGet(flow_tag.device_map, 'icon_id', (toUInt64(1),toUInt64(l3_device_id_0))), 0) AS `xx` SELECT `xx`, dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`, SUM(byte_tx) AS `_sum_byte_tx` FROM flow_metrics.`vtap_flow_edge_port` GROUP BY `xx`, dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`) GROUP BY `xx`, `region_0` LIMIT 1",
		db:     "flow_metrics",
	}, {
		input:  "select request from l7_flow_log where Enum(tap_side)='xxx' limit 0, 50",
		output: "SELECT if(type IN [0, 2],1,0) AS `request` FROM flow_log.`l7_flow_log` PREWHERE (tap_side IN (SELECT value FROM flow_tag.string_enum_map WHERE name = 'xxx' and tag_name='tap_side') OR tap_side = 'xxx') LIMIT 0, 50",
	}, {
		input:  "select request from l7_flow_log where Enum(tap_side) like 'xxx' limit 0, 50",
		output: "SELECT if(type IN [0, 2],1,0) AS `request` FROM flow_log.`l7_flow_log` PREWHERE (tap_side IN (SELECT value FROM flow_tag.string_enum_map WHERE name ilike 'xxx' and tag_name='tap_side')) LIMIT 0, 50",
	}, {
		input:  "select Histogram(Sum(byte),10) AS histo from l4_flow_log",
		output: "SELECT histogramIf(10)(`_sum_byte_tx+byte_rx`,`_sum_byte_tx+byte_rx`>0) AS `histo` FROM (SELECT SUM(byte_tx+byte_rx) AS `_sum_byte_tx+byte_rx` FROM flow_log.`l4_flow_log` LIMIT 10000)",
	}, {
		input:  "select Sum(log_count) from event",
		output: "SELECT SUM(1) AS `Sum(log_count)` FROM event.`event` LIMIT 10000",
		db:     "event",
	}, {
		input:  "select Sum(session_length) from l7_flow_log",
		output: "SELECT SUM(if(request_length>0,request_length,0)+if(response_length>0,response_length,0)) AS `Sum(session_length)` FROM flow_log.`l7_flow_log` LIMIT 10000",
	}, {
		input:  "select region_0 from l7_flow_log where region regexp '系统*'",
		output: "SELECT dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0` FROM flow_log.`l7_flow_log` PREWHERE (toUInt64(region_id) IN (SELECT id FROM flow_tag.region_map WHERE match(name,'系统*'))) LIMIT 10000",
	}, {
		input:  "select time(time, 0.2) as toi, PerSecond(Sum(byte)+100) as persecond_max_byte_100 from l4_flow_log group by toi limit 1",
		output: "WITH toStartOfInterval(time, toIntervalSecond(1)) + toIntervalSecond(arrayJoin([0]) * 1) AS `_toi` SELECT toUnixTimestamp(`_toi`) AS `toi`, divide(plus(SUM(byte_tx+byte_rx), 100), 1) AS `persecond_max_byte_100` FROM flow_log.`l4_flow_log` GROUP BY `toi` LIMIT 1",
	}, {
		input:  "select time(time, 1.2) as toi, Avg(`byte_tx`) AS `Avg(byte_tx)` from vtap_flow_edge_port group by toi limit 1",
		output: "WITH toStartOfInterval(_time, toIntervalSecond(2)) + toIntervalSecond(arrayJoin([0]) * 2) AS `_toi` SELECT toUnixTimestamp(`_toi`) AS `toi`, AVG(`_sum_byte_tx`) AS `Avg(byte_tx)` FROM (WITH toStartOfInterval(time, toIntervalSecond(1)) AS `_time` SELECT _time, SUM(byte_tx) AS `_sum_byte_tx` FROM flow_metrics.`vtap_flow_edge_port` GROUP BY `_time`) GROUP BY `toi` LIMIT 1",
		db:     "flow_metrics",
	}, {
		input:  "SELECT time(time,5,1,0) as toi, Avg(`metrics.dropped`) AS `Avg(metrics.dropped)` FROM `deepflow_agent_collect_sender` GROUP BY  toi ORDER BY toi desc",
		output: "WITH toStartOfInterval(time, toIntervalSecond(10)) + toIntervalSecond(arrayJoin([0]) * 10) AS `_toi` SELECT toUnixTimestamp(`_toi`) AS `toi`, AVG(if(indexOf(metrics_float_names, 'dropped')=0,null,metrics_float_values[indexOf(metrics_float_names, 'dropped')])) AS `Avg(metrics.dropped)` FROM deepflow_system.`deepflow_system` PREWHERE (virtual_table_name='deepflow_agent_collect_sender') GROUP BY `toi` ORDER BY `toi` desc LIMIT 10000",
		db:     "deepflow_system",
	}, {
		input:  "SELECT time(time,120,1,0) as toi, Avg(`metrics.dropped`) AS `Avg(metrics.dropped)` FROM `deepflow_agent_collect_sender` GROUP BY  toi ORDER BY toi desc",
		output: "WITH toStartOfInterval(time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS `_toi` SELECT toUnixTimestamp(`_toi`) AS `toi`, AVG(if(indexOf(metrics_float_names, 'dropped')=0,null,metrics_float_values[indexOf(metrics_float_names, 'dropped')])) AS `Avg(metrics.dropped)` FROM deepflow_system.`deepflow_system` PREWHERE (virtual_table_name='deepflow_agent_collect_sender') GROUP BY `toi` ORDER BY `toi` desc LIMIT 10000",
		db:     "deepflow_system",
	}, {
		input:  "SELECT chost_id_0 from l4_flow_log WHERE NOT exist(chost_0) LIMIT 1",
		output: "SELECT if(l3_device_type_0=1,l3_device_id_0, 0) AS `chost_id_0` FROM flow_log.`l4_flow_log` PREWHERE NOT (l3_device_type_0=1) LIMIT 1",
	}, {
		input:  "SELECT `cloud.tag.xx` from l4_flow_log WHERE NOT exist(`cloud.tag.xx`) LIMIT 1",
		output: "SELECT if(if(l3_device_type=1, dictGet(flow_tag.chost_cloud_tag_map, 'value', (toUInt64(l3_device_id),'xx')), '')!='',if(l3_device_type=1, dictGet(flow_tag.chost_cloud_tag_map, 'value', (toUInt64(l3_device_id),'xx')), ''), dictGet(flow_tag.pod_ns_cloud_tag_map, 'value', (toUInt64(pod_ns_id),'xx')) ) AS `cloud.tag.xx` FROM flow_log.`l4_flow_log` PREWHERE NOT (((toUInt64(l3_device_id) IN (SELECT id FROM flow_tag.chost_cloud_tag_map WHERE key='xx') AND l3_device_type=1) OR (toUInt64(pod_ns_id) IN (SELECT id FROM flow_tag.pod_ns_cloud_tag_map WHERE key='xx')))) LIMIT 1",
	}, {
		input:  "select `k8s.annotation.statefulset.kubernetes.io/pod-name_0` from l4_flow_log where `k8s.annotation.statefulset.kubernetes.io/pod-name_0`='opensource-loki-0' group by `k8s.annotation.statefulset.kubernetes.io/pod-name_0`",
		output: "SELECT if(dictGet(flow_tag.pod_service_k8s_annotation_map, 'value', (toUInt64(service_id_0),'statefulset.kubernetes.io/pod-name'))!='', dictGet(flow_tag.pod_service_k8s_annotation_map, 'value', (toUInt64(service_id_0),'statefulset.kubernetes.io/pod-name')), dictGet(flow_tag.pod_k8s_annotation_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) ) AS `k8s.annotation.statefulset.kubernetes.io/pod-name_0` FROM flow_log.`l4_flow_log` PREWHERE ((toUInt64(service_id_0) IN (SELECT id FROM flow_tag.pod_service_k8s_annotation_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name')) OR (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_annotation_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name'))) AND (((toUInt64(service_id_0) IN (SELECT id FROM flow_tag.pod_service_k8s_annotation_map WHERE key='statefulset.kubernetes.io/pod-name')) OR (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_annotation_map WHERE key='statefulset.kubernetes.io/pod-name')))) GROUP BY `k8s.annotation.statefulset.kubernetes.io/pod-name_0` LIMIT 10000",
	}, {
		input:  "select `k8s.annotation.statefulset.kubernetes.io/pod-name_0` as `k8s.annotation.abc` from l4_flow_log where `k8s.annotation.abc`='opensource-loki-0' group by `k8s.annotation.abc`",
		output: "SELECT if(dictGet(flow_tag.pod_service_k8s_annotation_map, 'value', (toUInt64(service_id_0),'statefulset.kubernetes.io/pod-name'))!='', dictGet(flow_tag.pod_service_k8s_annotation_map, 'value', (toUInt64(service_id_0),'statefulset.kubernetes.io/pod-name')), dictGet(flow_tag.pod_k8s_annotation_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) ) AS `k8s.annotation.abc` FROM flow_log.`l4_flow_log` PREWHERE ((toUInt64(service_id_0) IN (SELECT id FROM flow_tag.pod_service_k8s_annotation_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name')) OR (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_annotation_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name'))) AND (((toUInt64(service_id_0) IN (SELECT id FROM flow_tag.pod_service_k8s_annotation_map WHERE key='statefulset.kubernetes.io/pod-name')) OR (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_annotation_map WHERE key='statefulset.kubernetes.io/pod-name')))) GROUP BY `k8s.annotation.abc` LIMIT 10000",
	}, {
		input:  "select `k8s.annotation_0` from l7_flow_log",
		output: "SELECT if(dictGetOrDefault(flow_tag.pod_service_k8s_annotations_map, 'annotations', toUInt64(service_id_0),'{}')!='{}', dictGetOrDefault(flow_tag.pod_service_k8s_annotations_map, 'annotations', toUInt64(service_id_0),'{}'), dictGetOrDefault(flow_tag.pod_k8s_annotations_map, 'annotations', toUInt64(pod_id_0),'{}'))  AS `k8s.annotation_0` FROM flow_log.`l7_flow_log` LIMIT 10000",
	}, {
		input:  "select `k8s.env.statefulset.kubernetes.io/pod-name_0` from l4_flow_log group by `k8s.env.statefulset.kubernetes.io/pod-name_0`",
		output: "SELECT dictGet(flow_tag.pod_k8s_env_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) AS `k8s.env.statefulset.kubernetes.io/pod-name_0` FROM flow_log.`l4_flow_log` PREWHERE (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_env_map WHERE key='statefulset.kubernetes.io/pod-name')) GROUP BY `k8s.env.statefulset.kubernetes.io/pod-name_0` LIMIT 10000",
	}, {
		input:  "select `k8s.env.statefulset.kubernetes.io/pod-name_0` from l4_flow_log where `k8s.env.statefulset.kubernetes.io/pod-name_0`='opensource-loki-0' group by `k8s.env.statefulset.kubernetes.io/pod-name_0`",
		output: "SELECT dictGet(flow_tag.pod_k8s_env_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) AS `k8s.env.statefulset.kubernetes.io/pod-name_0` FROM flow_log.`l4_flow_log` PREWHERE toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_env_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name') AND (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_env_map WHERE key='statefulset.kubernetes.io/pod-name')) GROUP BY `k8s.env.statefulset.kubernetes.io/pod-name_0` LIMIT 10000",
	}, {
		input:  "select `k8s.env.statefulset.kubernetes.io/pod-name_0` as `k8s.env.abc` from l4_flow_log where `k8s.env.abc`='opensource-loki-0' group by `k8s.env.abc`",
		output: "SELECT dictGet(flow_tag.pod_k8s_env_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) AS `k8s.env.abc` FROM flow_log.`l4_flow_log` PREWHERE toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_env_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name') AND (toUInt64(pod_id_0) IN (SELECT id FROM flow_tag.pod_k8s_env_map WHERE key='statefulset.kubernetes.io/pod-name')) GROUP BY `k8s.env.abc` LIMIT 10000",
	}, {
		input:  "select `k8s.env_0` from l7_flow_log",
		output: "SELECT dictGetOrDefault(flow_tag.pod_k8s_envs_map, 'envs', toUInt64(pod_id_0),'{}')  AS `k8s.env_0` FROM flow_log.`l7_flow_log` LIMIT 10000",
	}, {
		input:  "SELECT Sum(log_count) as sum_log_count FROM l7_flow_log  WHERE `会话长度`>=893689408 ",
		output: "SELECT SUM(1) AS `sum_log_count` FROM flow_log.`l7_flow_log` PREWHERE `会话长度` >= 893689408 LIMIT 10000",
	}, {
		input:  "select session_length AS `会话长度` from l7_flow_log where `session_length`<=392037",
		output: "SELECT if(request_length>0,request_length,0)+if(response_length>0,response_length,0) AS `会话长度` FROM flow_log.`l7_flow_log` PREWHERE if(request_length>0,request_length,0)+if(response_length>0,response_length,0) <= 392037 LIMIT 10000",
	}, {
		input:  "SELECT node_type(is_internet_0) as `client_node_type` , icon_id(is_internet_0) as `client_icon_id`,  node_type(is_internet_1) as `server_node_type`, is_internet_0, is_internet_1 FROM l4_flow_log GROUP BY is_internet_0, is_internet_1 limit 1",
		output: "WITH if(l3_epc_id_0=-2,dictGet(flow_tag.device_map, 'icon_id', (toUInt64(63999),toUInt64(63999))),0) AS `client_icon_id` SELECT if(l3_epc_id_0=-2,'internet','') AS `client_node_type`, `client_icon_id`, if(l3_epc_id_1=-2,'internet','') AS `server_node_type`, if(l3_epc_id_0=-2,1,0) AS `is_internet_0`, if(l3_epc_id_1=-2,1,0) AS `is_internet_1` FROM flow_log.`l4_flow_log` GROUP BY `client_node_type`, `client_icon_id`, `server_node_type`, if(l3_epc_id_0=-2,1,0) AS `is_internet_0`, if(l3_epc_id_1=-2,1,0) AS `is_internet_1` LIMIT 1",
	}, {
		input:  "select Enum(pod_group_type_0) ,pod_group_type_0 from l7_flow_log where Enum(pod_group_type_0)!='Deployment' limit 10",
		output: "WITH dictGetOrDefault(flow_tag.int_enum_map, 'name', ('pod_group_type',toUInt64(dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64(pod_group_id_0))))), dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64(pod_group_id_0)))) AS `Enum(pod_group_type_0)` SELECT `Enum(pod_group_type_0)`, dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64(pod_group_id_0))) AS `pod_group_type_0` FROM flow_log.`l7_flow_log` PREWHERE (not(toUInt64(dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64(pod_group_id_0)))) IN (SELECT value FROM flow_tag.int_enum_map WHERE name = 'Deployment' and tag_name='pod_group_type') AND pod_group_id_0!=0)) LIMIT 10",
	}, {
		index:  "count_1",
		input:  "select Count(row) as a from l7_flow_log having a > 0 ",
		output: "SELECT COUNT(1) AS `a` FROM flow_log.`l7_flow_log` HAVING a > 0 LIMIT 10000",
	}, {
		index:  "count_2",
		input:  "select Count(row) from l7_flow_log having Count(row) > 0 ",
		output: "SELECT COUNT(1) AS `Count(row)` FROM flow_log.`l7_flow_log` HAVING COUNT(1) > 0 LIMIT 10000",
	}, {
		index:  "count_3",
		input:  "select Avg(`byte_tx`) AS `Avg(byte_tx)`,icon_id(chost_0) as `xx`, Count(row) as `c`, region_0 from vtap_flow_edge_port group by region_0 having `c` > 0 limit 1",
		output: "SELECT `xx`, region_0, AVG(`_sum_byte_tx`) AS `Avg(byte_tx)`, SUM(`_count_1`) AS `c` FROM (WITH if(l3_device_type_0=1, dictGet(flow_tag.device_map, 'icon_id', (toUInt64(1),toUInt64(l3_device_id_0))), 0) AS `xx` SELECT `xx`, dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`, SUM(byte_tx) AS `_sum_byte_tx`, COUNT(1) AS `_count_1` FROM flow_metrics.`vtap_flow_edge_port` GROUP BY `xx`, dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`) GROUP BY `xx`, `region_0` HAVING c > 0 LIMIT 1",
		db:     "flow_metrics",
	}, {
		index:  "topk_1",
		db:     "flow_metrics",
		input:  "select pod_ns, topK(pod, 10) from `vtap_app_port.1h` WHERE time>=1687315761 AND time<=1687316661 group by pod_ns limit 10",
		output: "SELECT dictGet(flow_tag.pod_ns_map, 'name', (toUInt64(pod_ns_id))) AS `pod_ns`, topK(10)(dictGet(flow_tag.pod_map, 'name', (toUInt64(pod_id)))) FROM flow_metrics.`vtap_app_port.1h` WHERE `time` >= 1687315761 AND `time` <= 1687316661 AND (pod_ns_id!=0) GROUP BY dictGet(flow_tag.pod_ns_map, 'name', (toUInt64(pod_ns_id))) AS `pod_ns` LIMIT 10",
	}, {
		index:  "topk_2",
		db:     "flow_metrics",
		input:  "select pod_ns, topK(pod, pod_cluster_id, service_id, 10) from `vtap_app_port.1h` WHERE time>=1694069050 AND time<=1694990640 group by pod_ns limit 10",
		output: "SELECT dictGet(flow_tag.pod_ns_map, 'name', (toUInt64(pod_ns_id))) AS `pod_ns`, topK(10)((dictGet(flow_tag.pod_map, 'name', (toUInt64(pod_id))),pod_cluster_id,service_id)) FROM flow_metrics.`vtap_app_port.1h` WHERE `time` >= 1694069050 AND `time` <= 1694990640 AND (pod_ns_id!=0) GROUP BY dictGet(flow_tag.pod_ns_map, 'name', (toUInt64(pod_ns_id))) AS `pod_ns` LIMIT 10",
	}, {
		index:  "any_1",
		db:     "flow_metrics",
		input:  "select pod_ns, any(pod) from `vtap_app_port.1h` WHERE time>=1694069050 AND time<=1694990640 group by pod_ns limit 10",
		output: "SELECT dictGet(flow_tag.pod_ns_map, 'name', (toUInt64(pod_ns_id))) AS `pod_ns`, topK(1)(dictGet(flow_tag.pod_map, 'name', (toUInt64(pod_id)))) FROM flow_metrics.`vtap_app_port.1h` WHERE `time` >= 1694069050 AND `time` <= 1694990640 AND (pod_ns_id!=0) GROUP BY dictGet(flow_tag.pod_ns_map, 'name', (toUInt64(pod_ns_id))) AS `pod_ns` LIMIT 10",
	}, {
		index:  "any_2",
		db:     "flow_metrics",
		input:  "select pod_ns, any(pod, pod_cluster_id, service_id) from `vtap_app_port.1h` WHERE time>=1694069050 AND time<=1694990640 group by pod_ns limit 10",
		output: "SELECT dictGet(flow_tag.pod_ns_map, 'name', (toUInt64(pod_ns_id))) AS `pod_ns`, topK(1)((dictGet(flow_tag.pod_map, 'name', (toUInt64(pod_id))),pod_cluster_id,service_id)) FROM flow_metrics.`vtap_app_port.1h` WHERE `time` >= 1694069050 AND `time` <= 1694990640 AND (pod_ns_id!=0) GROUP BY dictGet(flow_tag.pod_ns_map, 'name', (toUInt64(pod_ns_id))) AS `pod_ns` LIMIT 10",
	}, {
		input:  "SELECT is_internet_0, is_internet_1 FROM l4_flow_log GROUP BY is_internet_0, is_internet_1 limit 1",
		output: "SELECT if(l3_epc_id_0=-2,1,0) AS `is_internet_0`, if(l3_epc_id_1=-2,1,0) AS `is_internet_1` FROM flow_log.`l4_flow_log` GROUP BY if(l3_epc_id_0=-2,1,0) AS `is_internet_0`, if(l3_epc_id_1=-2,1,0) AS `is_internet_1` LIMIT 1",
	}, {
		index:  "TopK_1",
		input:  "select TopK(ip_0, 10) as top_10_ip_0 from l4_flow_log limit 1",
		output: "SELECT topKIf(10)(if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)), NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))) AS `top_10_ip_0` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		index:  "TopK_2",
		input:  "select TopK(ip_0, pod_0, 10) as top_10_ip_pod_0 from l4_flow_log limit 1",
		output: "SELECT topKIf(10)((if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)), dictGet(flow_tag.pod_map, 'name', (toUInt64(pod_id_0)))), (NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0')))) AND NOT (pod_id_0 = 0))) AS `top_10_ip_pod_0` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		index:  "Any_1",
		input:  "select Any(ip_0) as any_ip_0 from l4_flow_log limit 1",
		output: "SELECT topKIf(1)(if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)), NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))) AS `any_ip_0` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		index:  "Any_2",
		input:  "select Any(ip_0, pod_0) as any_ip_pod_0 from l4_flow_log limit 1",
		output: "SELECT topKIf(1)((if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)), dictGet(flow_tag.pod_map, 'name', (toUInt64(pod_id_0)))), (NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0')))) AND NOT (pod_id_0 = 0))) AS `any_ip_pod_0` FROM flow_log.`l4_flow_log` LIMIT 1",
	}, {
		index:  "layered_0",
		input:  "select Avg(`byte_tx`) AS `Avg(byte_tx)`, region_0 from vtap_flow_edge_port group by region_0 limit 1",
		output: "SELECT region_0, AVG(`_sum_byte_tx`) AS `Avg(byte_tx)` FROM (SELECT dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`, SUM(byte_tx) AS `_sum_byte_tx` FROM flow_metrics.`vtap_flow_edge_port` GROUP BY dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`) GROUP BY `region_0` LIMIT 1",
		db:     "flow_metrics",
	}, {
		index:  "division>=0_l4_flow_log",
		input:  "select Avg(`l7_error_ratio`) AS `Avg(l7_error_ratio)`, Avg(`retrans_syn_ratio`) AS `Avg(retrans_syn_ratio)`, Avg(`retrans_synack_ratio`) AS `Avg(retrans_synack_ratio)`, Avg(`l7_client_error_ratio`) AS `Avg(l7_client_error_ratio)`, Avg(`l7_server_error_ratio`) AS `Avg(l7_server_error_ratio)`, auto_service_id from l4_flow_log group by auto_service_id limit 1",
		output: "SELECT if(auto_service_type in (0,255),subnet_id,auto_service_id) AS `auto_service_id`, AVGIf(l7_error/l7_response, l7_error/l7_response>=0)*100 AS `Avg(l7_error_ratio)`, AVGIf(retrans_syn/syn_count, retrans_syn/syn_count>=0)*100 AS `Avg(retrans_syn_ratio)`, AVGIf(retrans_synack/synack_count, retrans_synack/synack_count>=0)*100 AS `Avg(retrans_synack_ratio)`, AVGIf(l7_client_error/l7_response, l7_client_error/l7_response>=0)*100 AS `Avg(l7_client_error_ratio)`, AVGIf(l7_server_error/l7_response, l7_server_error/l7_response>=0)*100 AS `Avg(l7_server_error_ratio)` FROM flow_log.`l4_flow_log` GROUP BY if(auto_service_type in (0,255),subnet_id,auto_service_id) AS `auto_service_id` LIMIT 1",
	}, {
		index:  "division>=0_l7_flow_log",
		input:  "select Avg(`error_ratio`) AS `Avg(error_ratio)`, auto_service_id from l7_flow_log group by auto_service_id limit 1",
		output: "SELECT if(auto_service_type in (0,255),subnet_id,auto_service_id) AS `auto_service_id`, AVGIf(if(response_status IN [4, 3],1,0)/if(type IN [1, 2],1,0), if(response_status IN [4, 3],1,0)/if(type IN [1, 2],1,0)>=0)*100 AS `Avg(error_ratio)` FROM flow_log.`l7_flow_log` GROUP BY if(auto_service_type in (0,255),subnet_id,auto_service_id) AS `auto_service_id` LIMIT 1",
	}, {
		index:  "division>=0_vtap_app_port",
		input:  "select Avg(`rrt`) AS `Avg(rrt)`, Avg(`error_ratio`) AS `Avg(error_ratio)`, auto_service_id from vtap_app_port group by auto_service_id limit 1",
		output: "SELECT auto_service_id, AVGArray(arrayFilter(x -> x>=0, `_grouparray_rrt_sum/rrt_count`)) AS `Avg(rrt)`, AVG(`_div__sum_error__sum_response`)*100 AS `Avg(error_ratio)` FROM (WITH if(SUM(response)>0, divide(SUM(error), SUM(response)), null) AS `divide_0diveider_as_null_sum_error_sum_response` SELECT if(auto_service_type in (0,255),subnet_id,auto_service_id) AS `auto_service_id`, groupArrayIf(rrt_sum/rrt_count, rrt_sum/rrt_count >= 0) AS `_grouparray_rrt_sum/rrt_count`, `divide_0diveider_as_null_sum_error_sum_response` AS `_div__sum_error__sum_response` FROM flow_metrics.`vtap_app_port` GROUP BY if(auto_service_type in (0,255),subnet_id,auto_service_id) AS `auto_service_id`) GROUP BY `auto_service_id` LIMIT 1",
		db:     "flow_metrics",
	}, {
		index:  "division>=0_vtap_flow_edge_port",
		input:  "select Avg(`bpp`) AS `Avg(bpp)`, Avg(`retrans_syn_ratio`) AS `Avg(retrans_syn_ratio)`, auto_service_id from vtap_flow_edge_port group by auto_service_id limit 1",
		output: "SELECT auto_service_id, AVGIf(`_div__sum_byte__sum_packet`, `_div__sum_byte__sum_packet` >= 0) AS `Avg(bpp)`, AVG(`_div__sum_retrans_syn__sum_syn_count`)*100 AS `Avg(retrans_syn_ratio)` FROM (WITH if(SUM(packet)>0, divide(SUM(byte), SUM(packet)), null) AS `divide_0diveider_as_null_sum_byte_sum_packet`, if(SUM(syn_count)>0, divide(SUM(retrans_syn), SUM(syn_count)), null) AS `divide_0diveider_as_null_sum_retrans_syn_sum_syn_count` SELECT if(auto_service_type in (0,255),subnet_id,auto_service_id) AS `auto_service_id`, `divide_0diveider_as_null_sum_byte_sum_packet` AS `_div__sum_byte__sum_packet`, `divide_0diveider_as_null_sum_retrans_syn_sum_syn_count` AS `_div__sum_retrans_syn__sum_syn_count` FROM flow_metrics.`vtap_flow_edge_port` GROUP BY if(auto_service_type in (0,255),subnet_id,auto_service_id) AS `auto_service_id`) GROUP BY `auto_service_id` LIMIT 1",
		db:     "flow_metrics",
	}, {
		index:  "exist_trans_support_tag_0",
		input:  "SELECT pod from l4_flow_log WHERE exist(pod_0) AND exist(host_1) AND exist(vpc_0) AND exist(auto_instance_1) AND exist(auto_service_0) LIMIT 1",
		output: "SELECT dictGet(flow_tag.pod_map, 'name', (toUInt64(pod_id))) AS `pod` FROM flow_log.`l4_flow_log` PREWHERE (pod_id_0!=0) AND (host_id_1!=0) AND (l3_epc_id_0!=-2) AND (auto_instance_type_1 not in (101,102)) AND (auto_service_type_0 not in (10)) LIMIT 1",
	}, {
		index:  "exist_trans_support_tag_1",
		input:  "SELECT pod from vtap_app_port WHERE exist(resource_gl0_0) AND exist(resource_gl1_1) LIMIT 1",
		output: "SELECT dictGet(flow_tag.pod_map, 'name', (toUInt64(pod_id))) AS `pod` FROM flow_metrics.`vtap_app_port` WHERE (auto_instance_type_0 not in (101,102)) AND (auto_service_type_1 not in (10)) LIMIT 1",
		db:     "flow_metrics",
	}}
)

func TestGetSql(t *testing.T) {
	Load()
	for i, pcase := range parseSQL {
		if pcase.output == "" {
			pcase.output = pcase.input
		}
		db := pcase.db
		if db == "" {
			db = "flow_log"
		}
		e := CHEngine{DB: db}
		e.Context = context.Background()
		e.Init()
		parser := parse.Parser{Engine: &e}
		err := parser.ParseSQL(pcase.input)
		out := parser.Engine.ToSQLString()
		if out != pcase.output {
			caseIndex := pcase.index
			if pcase.index == "" {
				caseIndex = strconv.Itoa(i)
			}
			t.Errorf("\nParse [%s]\n\t%q \n get: \n\t%q \n want: \n\t%q", caseIndex, pcase.input, out, pcase.output)
			if err != nil {
				t.Errorf("\nerror %v", err)
			}
		}
	}
}

/* func TestGetSqltest(t *testing.T) {
	for _, pcase := range parsetest {
		e := CHEngine{DB: "flow_log"}
		e.Init()
		parser := parse.Parser{Engine: &e}
		parser.ParseSQL(pcase.input)
		out := parser.Engine.ToSQLString()
		pp.Println(out)
	}
} */

func Load() error {
	ServerCfg := config.DefaultConfig()
	config.Cfg = &ServerCfg.QuerierConfig
	dir := "../../db_descriptions"
	dbDescriptions, err := common.LoadDbDescriptions(dir)
	if err != nil {
		return err
	}
	err = LoadDbDescriptions(dbDescriptions)
	if err != nil {
		return err
	}
	return nil
}
