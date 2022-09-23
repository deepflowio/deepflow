/*
 * Copyright (c) 2022 Yunshan Networks
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
	//"github.com/k0kubun/pp"
	"github.com/deepflowys/deepflow/server/querier/common"
	"github.com/deepflowys/deepflow/server/querier/parse"
	//"github.com/deepflowys/deepflow/server/querier/querier"
	"testing"
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
		input  string
		output string
		db     string
	}{{
		input:  "select byte from l4_flow_log",
		output: "SELECT byte_tx+byte_rx AS `byte` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Sum(byte)/Time_interval as sum_byte, time(time, 120) as time_120 from l4_flow_log group by time_120 having Sum(byte)>=0 limit 10 offset 20",
		output: "WITH toStartOfInterval(time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS `_time_120` SELECT toUnixTimestamp(`_time_120`) AS `time_120`, divide(SUM(byte_tx+byte_rx), 120) AS `sum_byte` FROM flow_log.l4_flow_log GROUP BY `time_120` HAVING SUM(byte_tx+byte_rx) >= 0 LIMIT 20, 10",
	}, {
		input:  "select Sum(log_count) as sum_log_count from l4_flow_log order by sum_log_count desc",
		output: "SELECT SUM(1) AS `sum_log_count` FROM flow_log.l4_flow_log ORDER BY `sum_log_count` desc",
	}, {
		input:  "select Uniq(ip_0) as uniq_ip_0 from l4_flow_log",
		output: "SELECT uniqIf([toString(ip4_0), toString(subnet_id_0), toString(is_ipv4), toString(ip6_0)], NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))) AS `uniq_ip_0` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Max(byte) as max_byte, Sum(log_count) as sum_log_count from l4_flow_log having Sum(byte)>=0",
		output: "SELECT MAX(byte_tx+byte_rx) AS `max_byte`, SUM(1) AS `sum_log_count` FROM flow_log.l4_flow_log HAVING SUM(byte_tx+byte_rx) >= 0",
	}, {
		input:  "select (Max(byte_tx) + Sum(byte_tx))/1 as max_byte_tx from l4_flow_log",
		output: "SELECT divide(plus(MAX(byte_tx), SUM(byte_tx)), 1) AS `max_byte_tx` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Avg(byte_tx) as avg_byte_tx from l4_flow_log where `time`>=60 and `time`<=180 having Spread(byte_tx)>=0",
		output: "SELECT AVG(byte_tx) AS `avg_byte_tx` FROM flow_log.l4_flow_log PREWHERE `time` >= 60 AND `time` <= 180 HAVING minus(MAX(byte_tx), MIN(byte_tx)) >= 0",
	}, {
		input:  "select Stddev(byte_tx) as stddev_byte_tx from l4_flow_log",
		output: "SELECT stddevPopStable(byte_tx) AS `stddev_byte_tx` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx from l4_flow_log order by max_byte_tx",
		output: "SELECT MAX(byte_tx) AS `max_byte_tx` FROM flow_log.l4_flow_log ORDER BY `max_byte_tx` asc",
	}, {
		input:  "select Spread(byte_tx) as spread_byte_tx from l4_flow_log where `time`>=60 and `time`<=180",
		output: "SELECT minus(MAX(byte_tx), MIN(byte_tx)) AS `spread_byte_tx` FROM flow_log.l4_flow_log PREWHERE `time` >= 60 AND `time` <= 180",
	}, {
		input:  "select Rspread(byte_tx) as rspread_byte_tx from l4_flow_log where `time`>=60 and `time`<=180",
		output: "SELECT divide(MAX(byte_tx)+1e-15, MIN(byte_tx)+1e-15) AS `rspread_byte_tx` FROM flow_log.l4_flow_log PREWHERE `time` >= 60 AND `time` <= 180",
	}, {
		input:  "select Rspread(rtt) as rspread_rtt from l4_flow_log",
		output: "SELECT divide(MAXIf(rtt, rtt != 0)+1e-15, MINIf(rtt, rtt != 0)+1e-15) AS `rspread_rtt` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Percentile(byte_tx, 50) as percentile_byte_tx from l4_flow_log",
		output: "SELECT quantile(50)(byte_tx) AS `percentile_byte_tx` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT AVGIf(rtt, rtt != 0) AS `avg_rtt` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx, Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT MAX(byte_tx) AS `max_byte_tx`, AVGIf(rtt, rtt != 0) AS `avg_rtt` FROM flow_log.l4_flow_log",
	}, {
		input:  "select ((Max(byte_tx))+Avg(rtt ))/(1-Avg(rtt )) as avg_rtt from l4_flow_log",
		output: "SELECT divide(plus(MAX(byte_tx), AVGIf(rtt, rtt != 0)), minus(1, AVGIf(rtt, rtt != 0))) AS `avg_rtt` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Apdex(rtt, 100) as apdex_rtt_100 from l4_flow_log",
		output: "WITH if(COUNT()>0, divide(plus(SUM(if(rtt<=100,1,0)), SUM(if(100<rtt AND rtt<=100*4,0.5,0))), COUNT()), null) AS `divide_0diveider_as_null_plus_apdex_satisfy_rtt_100_apdex_toler_rtt_100_count_` SELECT `divide_0diveider_as_null_plus_apdex_satisfy_rtt_100_apdex_toler_rtt_100_count_`*100 AS `apdex_rtt_100` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Max(byte) as max_byte, time(time,120) as time_120 from l4_flow_log group by time_120 having Min(byte)>=0",
		output: "WITH toStartOfInterval(time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS `_time_120` SELECT toUnixTimestamp(`_time_120`) AS `time_120`, MAX(byte_tx+byte_rx) AS `max_byte` FROM flow_log.l4_flow_log GROUP BY `time_120` HAVING MIN(byte_tx+byte_rx) >= 0",
	}, {
		input:  "select Max(byte) as 'max_byte',region_0,chost_id_1 from l4_flow_log group by region_0,chost_id_1",
		output: "SELECT dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`, if(l3_device_type_1=1,l3_device_id_1, 0) AS `chost_id_1`, MAX(byte_tx+byte_rx) AS `max_byte` FROM flow_log.l4_flow_log PREWHERE (region_id_0!=0) AND (l3_device_id_1!=0 AND l3_device_type_1=1) GROUP BY dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `region_0`, if(l3_device_type_1=1,l3_device_id_1, 0) AS `chost_id_1`",
	}, {
		input:  "select Percentage(Max(byte)+100,100) as percentage_max_byte_100 from l4_flow_log",
		output: "SELECT divide(plus(MAX(byte_tx+byte_rx), 100), 100)*100 AS `percentage_max_byte_100` FROM flow_log.l4_flow_log",
	}, {
		input:  "select Sum(rtt) as sum_rtt from l4_flow_log having Percentage(Max(byte), 100) >= 1",
		output: "SELECT SUMIf(rtt, rtt != 0) AS `sum_rtt` FROM flow_log.l4_flow_log HAVING divide(MAX(byte_tx+byte_rx), 100)*100 >= 1",
	}, {
		input:  "select time(time, 60) as toi, PerSecond(Sum(byte)+100) as persecond_max_byte_100 from l4_flow_log group by toi limit 1",
		output: "WITH toStartOfInterval(time, toIntervalSecond(60)) + toIntervalSecond(arrayJoin([0]) * 60) AS `_toi` SELECT toUnixTimestamp(`_toi`) AS `toi`, divide(plus(SUM(byte_tx+byte_rx), 100), 60) AS `persecond_max_byte_100` FROM flow_log.l4_flow_log GROUP BY `toi` LIMIT 1",
	}, {
		input:  "select resource_gl0_0,ip_0 from l7_flow_log group by resource_gl0_0,ip_0",
		output: "SELECT dictGet(flow_tag.device_map, 'name', (toUInt64(resource_gl0_type_0),toUInt64(resource_gl0_id_0))) AS `resource_gl0_0`, if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS `ip_0`, multiIf(resource_gl0_id_0=0 and is_ipv4=1,IPv4NumToString(ip4_0), resource_gl0_id_0=0 and is_ipv4=0,IPv6NumToString(ip6_0),resource_gl0_id_0!=0 and is_ipv4=1,'0.0.0.0','::') AS `ip_0`, if(resource_gl0_id_0=0,subnet_id_0,0) AS `subnet_id_0`, resource_gl0_type_0 FROM flow_log.l7_flow_log GROUP BY dictGet(flow_tag.device_map, 'name', (toUInt64(resource_gl0_type_0),toUInt64(resource_gl0_id_0))) AS `resource_gl0_0`, `ip_0`, `subnet_id_0`, `resource_gl0_type_0`, if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS `ip_0`",
	}, {
		input:  "select pod_service_0 from l7_flow_log where pod_service_0 !='xx' group by pod_service_0",
		output: "SELECT dictGet(flow_tag.device_map, 'name', (toUInt64(11),toUInt64(service_id_0))) AS `pod_service_0` FROM flow_log.l7_flow_log PREWHERE (not(((if(is_ipv4=1,IPv4NumToString(ip4_0),IPv6NumToString(ip6_0)),toUInt64(l3_epc_id_0)) IN (SELECT ip,l3_epc_id from flow_tag.ip_relation_map WHERE pod_service_name = 'xx')) OR (toUInt64(service_id_0) IN (SELECT pod_service_id from flow_tag.ip_relation_map WHERE pod_service_name = 'xx')))) AND (service_id_0!=0) GROUP BY dictGet(flow_tag.device_map, 'name', (toUInt64(11),toUInt64(service_id_0))) AS `pod_service_0`",
	}, {
		input:  "select pod_ingress_0 from l7_flow_log where pod_ingress_0 !='xx' group by pod_ingress_0",
		output: "SELECT pod_ingress_0 FROM flow_log.l7_flow_log PREWHERE (not(((if(is_ipv4=1,IPv4NumToString(ip4_0),IPv6NumToString(ip6_0)),toUInt64(l3_epc_id_0)) IN (SELECT ip,l3_epc_id from flow_tag.ip_relation_map WHERE pod_ingress_name = 'xx')) OR (toUInt64(service_id_0) IN (SELECT pod_service_id from flow_tag.ip_relation_map WHERE pod_ingress_name = 'xx')))) GROUP BY `pod_ingress_0`",
	}, {
		input:  "select node_type(region_0) as 'node_type_0',mask(ip_0,33) as 'mask_ip_0' from l7_flow_log group by 'mask_ip_0','node_type_0'",
		output: "WITH if(is_ipv4, IPv4NumToString(bitAnd(ip4_0, 4294967295)), IPv6NumToString(bitAnd(ip6_0, toFixedString(unhex('ffffffff800000000000000000000000'), 16)))) AS `mask_ip_0` SELECT 'region' AS `node_type_0`, `mask_ip_0` FROM flow_log.l7_flow_log GROUP BY `mask_ip_0`, `node_type_0`",
	}, {
		input:  "select region_id_0 from l7_flow_log group by region_id_0,chost_id_1",
		output: "SELECT region_id_0, if(l3_device_type_1=1,l3_device_id_1, 0) AS `chost_id_1` FROM flow_log.l7_flow_log PREWHERE (region_id_0!=0) AND (l3_device_id_1!=0 AND l3_device_type_1=1) GROUP BY `region_id_0`, if(l3_device_type_1=1,l3_device_id_1, 0) AS `chost_id_1`",
	}, {
		input:  "SELECT ip_0 FROM l4_flow_log WHERE  ((is_internet_1=1) OR (is_internet_0=1)) GROUP BY ip_0 limit 1",
		output: "SELECT if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS `ip_0` FROM flow_log.l4_flow_log PREWHERE (((l3_epc_id_1 = -2)) OR ((l3_epc_id_0 = -2))) GROUP BY if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS `ip_0` LIMIT 1",
	}, {
		input:  "select Sum(byte) as `流量总量`, region_0 as `区域` from l4_flow_log where 1=1 group by `区域` order by `流量总量` desc",
		output: "SELECT dictGet(flow_tag.region_map, 'name', (toUInt64(region_id_0))) AS `区域`, SUM(byte_tx+byte_rx) AS `流量总量` FROM flow_log.l4_flow_log PREWHERE 1 = 1 AND (region_id_0!=0) GROUP BY `区域` ORDER BY `流量总量` desc",
	}, {
		input:  "select byte as `123` from l4_flow_log where 1=1 group by `123` order by `123` limit 1 ",
		output: "SELECT byte_tx+byte_rx AS `123` FROM flow_log.l4_flow_log PREWHERE 1 = 1 GROUP BY `123` ORDER BY `123` asc LIMIT 1",
	}, {
		input:  "select byte from l4_flow_log where ip>=('1.1.1.1/24','2.2.2.2') and ip<='::/24'",
		output: "SELECT byte_tx+byte_rx AS `byte` FROM flow_log.l4_flow_log PREWHERE (((if(is_ipv4=1, hex(ip4), hex(ip6)) >= hex(toIPv4('1.1.1.255'))) OR (if(is_ipv4=1, hex(ip4), hex(ip6)) >= hex(toIPv4('2.2.2.2'))))) AND (((if(is_ipv4=1, hex(ip4), hex(ip6)) <= hex(toIPv6('::')))))",
	}, {
		input:  "select `label.statefulset.kubernetes.io/pod-name_0` from l4_flow_log where `label.statefulset.kubernetes.io/pod-name_0`='opensource-loki-0' group by `label.statefulset.kubernetes.io/pod-name_0`",
		output: "SELECT dictGet(flow_tag.k8s_label_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) AS `label.statefulset.kubernetes.io/pod-name_0` FROM flow_log.l4_flow_log PREWHERE toUInt64(pod_id_0) IN (SELECT pod_id FROM flow_tag.k8s_label_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name') AND (pod_id_0!=0) GROUP BY `label.statefulset.kubernetes.io/pod-name_0`",
	}, {
		input:  "select `label.statefulset.kubernetes.io/pod-name_0` as `label.abc` from l4_flow_log where `label.abc`='opensource-loki-0' group by `label.abc`",
		output: "SELECT dictGet(flow_tag.k8s_label_map, 'value', (toUInt64(pod_id_0),'statefulset.kubernetes.io/pod-name')) AS `label.abc` FROM flow_log.l4_flow_log PREWHERE toUInt64(pod_id_0) IN (SELECT pod_id FROM flow_tag.k8s_label_map WHERE value = 'opensource-loki-0' and key='statefulset.kubernetes.io/pod-name') AND (pod_id_0!=0) GROUP BY `label.abc`",
	}, {
		input:  "select `attribute.cc` as `attribute.abc` from l7_flow_log where `attribute.abc`='opensource-loki-0' group by `attribute.abc`",
		output: "SELECT attribute_values[indexOf(attribute_names,'cc')] AS `attribute.abc` FROM flow_log.l7_flow_log PREWHERE attribute_values[indexOf(attribute_names,'cc')] = 'opensource-loki-0' AND (`attribute.abc` != '') GROUP BY `attribute.abc`",
	}, {
		input:  "select `tag.cc` as `tag.abc` from cpu where `tag.abc`='opensource-loki-0' group by `tag.abc`",
		output: "SELECT tag_values[indexOf(tag_names,'cc')] AS `tag.abc` FROM ext_metrics.cpu PREWHERE tag_values[indexOf(tag_names,'cc')] = 'opensource-loki-0' AND (`tag.abc` != '') GROUP BY `tag.abc`",
		db:     "ext_metrics",
	}, {
		input:  "select `metrics.storageclass_annotations` AS `job_info` from prometheus_kube",
		output: "SELECT if(indexOf(metrics_float_names, 'storageclass_annotations')=0,null,metrics_float_values[indexOf(metrics_float_names, 'storageclass_annotations')]) AS `job_info` FROM ext_metrics.prometheus_kube PREWHERE (job_info is not null)",
		db:     "ext_metrics",
	}, {
		input:  "select Sum(`metrics.pending`) from `deepflow_server.queue`",
		output: "SELECT SUM(if(indexOf(metrics_float_names, 'pending')=0,null,metrics_float_values[indexOf(metrics_float_names, 'pending')])) FROM deepflow_system.`deepflow_server.queue`",
		db:     "deepflow_system",
	}, {
		input:  "select labels_0 from l7_flow_log",
		output: "SELECT dictGetOrDefault(flow_tag.k8s_labels_map, 'labels', toUInt64(pod_id_0),'{}') AS `labels_0` FROM flow_log.l7_flow_log",
	}, {
		input:  "select `metrics.xxx.yyy` as xxx from l7_flow_log",
		output: "SELECT if(indexOf(metrics_names, 'xxx.yyy')=0,null,metrics_values[indexOf(metrics_names, 'xxx.yyy')]) AS `xxx` FROM flow_log.l7_flow_log",
	}, {
		input:  "select Sum(packet_count) as count from l4_packet",
		output: "SELECT SUM(packet_count) AS `count` FROM flow_log.l4_packet",
	}, {
		input:  "select `metrics.xxx` as xxx from cpu",
		output: "SELECT if(indexOf(metrics_float_names, 'xxx')=0,null,metrics_float_values[indexOf(metrics_float_names, 'xxx')]) AS `xxx` FROM ext_metrics.cpu PREWHERE (xxx is not null)",
		db:     "ext_metrics",
	},
	}
)

func TestGetSql(t *testing.T) {
	Load()
	for _, pcase := range parseSQL {
		if pcase.output == "" {
			pcase.output = pcase.input
		}
		db := pcase.db
		if db == "" {
			db = "flow_log"
		}
		e := CHEngine{DB: db}
		e.Init()
		parser := parse.Parser{Engine: &e}
		parser.ParseSQL(pcase.input)
		out := parser.Engine.ToSQLString()
		if out != pcase.output {
			t.Errorf("Parse(%q) = %q, want: %q", pcase.input, out, pcase.output)
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
