package clickhouse

import (
	//"github.com/k0kubun/pp"
	"metaflow/querier/common"
	"metaflow/querier/parse"
	//"metaflow/querier/querier"
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
	}{{
		input:  "select byte from l4_flow_log",
		output: "SELECT byte_tx+byte_rx AS byte FROM flow_log.l4_flow_log",
	}, {
		input:  "select Sum(byte)/Time_interval as sum_byte, time(time, 120) as time_120 from l4_flow_log group by time_120 having Sum(byte)>=0 limit 10 offset 20",
		output: "WITH toStartOfInterval(time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS _time_120 SELECT toUnixTimestamp(_time_120) AS time_120, divide(SUM(byte_tx+byte_rx), 120) AS sum_byte FROM flow_log.l4_flow_log GROUP BY time_120 HAVING SUM(byte_tx+byte_rx) >= 0 LIMIT 20, 10",
	}, {
		input:  "select Sum(log_count) as sum_log_count from l4_flow_log order by sum_log_count desc",
		output: "SELECT SUM(1) AS sum_log_count FROM flow_log.l4_flow_log ORDER BY sum_log_count desc",
	}, {
		input:  "select Uniq(ip_0) as uniq_ip_0 from l4_flow_log",
		output: "SELECT uniqIf([toString(ip4_0), toString(subnet_id_0), toString(is_ipv4), toString(ip6_0)], NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))) AS uniq_ip_0 FROM flow_log.l4_flow_log",
	}, {
		input:  "select Max(byte) as max_byte, Sum(log_count) as sum_log_count from l4_flow_log having Sum(byte)>=0",
		output: "SELECT MAX(_sum_byte_tx_plus_byte_rx) AS max_byte, SUM(_sum_1) AS sum_log_count FROM (SELECT SUM(byte_tx+byte_rx) AS _sum_byte_tx_plus_byte_rx, SUM(1) AS _sum_1 FROM flow_log.l4_flow_log) HAVING SUM(_sum_byte_tx_plus_byte_rx) >= 0",
	}, {
		input:  "select (Max(byte_tx) + Sum(byte_tx))/1 as max_byte_tx from l4_flow_log",
		output: "SELECT divide(plus(MAX(_sum_byte_tx), SUM(_sum_byte_tx)), 1) AS max_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM flow_log.l4_flow_log)",
	}, {
		input:  "select Avg(byte_tx) as avg_byte_tx from l4_flow_log where `time`>=60 and `time`<=180 having Spread(byte_tx)>=0",
		output: "WITH if(count(_sum_byte_tx)=3, min(_sum_byte_tx), 0) AS min_fillnullaszero__sum_byte_tx SELECT AVG(_sum_byte_tx) AS avg_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM flow_log.l4_flow_log PREWHERE `time` >= 60 AND `time` <= 180) HAVING minus(MAX(_sum_byte_tx), min_fillnullaszero__sum_byte_tx) >= 0",
	}, {
		input:  "select Stddev(byte_tx) as stddev_byte_tx from l4_flow_log",
		output: "SELECT stddevPopStable(_sum_byte_tx) AS stddev_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM flow_log.l4_flow_log)",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx from l4_flow_log order by max_byte_tx",
		output: "SELECT MAX(_sum_byte_tx) AS max_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM flow_log.l4_flow_log) ORDER BY max_byte_tx asc",
	}, {
		input:  "select Spread(byte_tx) as spread_byte_tx from l4_flow_log where `time`>=60 and `time`<=180",
		output: "WITH if(count(_sum_byte_tx)=3, min(_sum_byte_tx), 0) AS min_fillnullaszero__sum_byte_tx SELECT minus(MAX(_sum_byte_tx), min_fillnullaszero__sum_byte_tx) AS spread_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM flow_log.l4_flow_log PREWHERE `time` >= 60 AND `time` <= 180)",
	}, {
		input:  "select Rspread(byte_tx) as rspread_byte_tx from l4_flow_log where `time`>=60 and `time`<=180",
		output: "WITH if(count(_sum_byte_tx)=3, min(_sum_byte_tx), 0) AS min_fillnullaszero__sum_byte_tx SELECT divide(MAX(_sum_byte_tx)+1e-15, min_fillnullaszero__sum_byte_tx+1e-15) AS rspread_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM flow_log.l4_flow_log PREWHERE `time` >= 60 AND `time` <= 180)",
	}, {
		input:  "select Rspread(rtt) as rspread_rtt from l4_flow_log ",
		output: "SELECT divide(MAXArray(arrayFilter(x -> x!=0, _grouparray_rtt))+1e-15, MINArray(arrayFilter(x -> x!=0, _grouparray_rtt))+1e-15) AS rspread_rtt FROM (SELECT groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM flow_log.l4_flow_log)",
	}, {
		input:  "select Percentile(byte_tx, 50) as percentile_byte_tx from l4_flow_log",
		output: "SELECT quantile(50)(_sum_byte_tx) AS percentile_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM flow_log.l4_flow_log)",
	}, {
		input:  "select Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT AVGIf(rtt, rtt != 0) AS avg_rtt FROM flow_log.l4_flow_log",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx, Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT MAX(_sum_byte_tx) AS max_byte_tx, AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt)) AS avg_rtt FROM (SELECT SUM(byte_tx) AS _sum_byte_tx, groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM flow_log.l4_flow_log)",
	}, {
		input:  "select ((Max(byte_tx))+Avg(rtt ))/(1-Avg(rtt )) as avg_rtt from l4_flow_log",
		output: "SELECT divide(plus(MAX(_sum_byte_tx), AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt))), minus(1, AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt)))) AS avg_rtt FROM (SELECT SUM(byte_tx) AS _sum_byte_tx, groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM flow_log.l4_flow_log)",
	}, {
		input:  "select Apdex(rtt, 100) as apdex_rtt_100 from l4_flow_log",
		output: "WITH if(COUNTArray(arrayFilter(x -> x!=0, _grouparray_rtt))>0, divide(plus(COUNTArray(arrayFilter(x -> (x <= 100 AND 0 < x), _grouparray_rtt)), divide(COUNTArray(arrayFilter(x -> ((100 < x) AND (x <= (100 * 4))), _grouparray_rtt)), 2)), COUNTArray(arrayFilter(x -> x!=0, _grouparray_rtt))), null) AS divide_0diveider_as_null_plus_apdex_satisfy__grouparray_rtt_100_apdex_toler__grouparray_rtt_100_count__grouparray_rtt SELECT divide_0diveider_as_null_plus_apdex_satisfy__grouparray_rtt_100_apdex_toler__grouparray_rtt_100_count__grouparray_rtt*100 AS apdex_rtt_100 FROM (SELECT groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM flow_log.l4_flow_log)",
	}, {
		input:  "select Max(byte) as max_byte, time(time,120) as time_120 from l4_flow_log group by time_120",
		output: "WITH toStartOfInterval(_time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS _time_120 SELECT toUnixTimestamp(_time_120) AS time_120, MAX(_sum_byte_tx_plus_byte_rx) AS max_byte FROM (WITH toStartOfInterval(time, toIntervalSecond(60)) AS _time SELECT _time, SUM(byte_tx+byte_rx) AS _sum_byte_tx_plus_byte_rx FROM flow_log.l4_flow_log GROUP BY _time) GROUP BY time_120",
	}, {
		input:  "select Max(byte) as 'max_byte',region_0,chost_id_1 from l4_flow_log group by region_0,chost_id_1",
		output: "SELECT region_0, chost_id_1, MAX(_sum_byte_tx_plus_byte_rx) AS max_byte FROM (SELECT dictGet(deepflow.region_map, 'name', (toUInt64(region_id_0))) AS region_0, if(l3_device_type_1=1,l3_device_id_1, 0) AS chost_id_1, SUM(byte_tx+byte_rx) AS _sum_byte_tx_plus_byte_rx FROM flow_log.l4_flow_log PREWHERE (region_id_0!=0) AND (l3_device_id_1!=0 AND l3_device_type_1=1) GROUP BY dictGet(deepflow.region_map, 'name', (toUInt64(region_id_0))) AS region_0, if(l3_device_type_1=1,l3_device_id_1, 0) AS chost_id_1) GROUP BY region_0, chost_id_1",
	}, {
		input:  "select resource_gl0_0,ip_0 from l7_flow_log group by resource_gl0_0,ip_0",
		output: "SELECT dictGet(deepflow.device_map, 'name', (toUInt64(resource_gl0_type_0),toUInt64(resource_gl0_id_0))) AS resource_gl0_0, if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS ip_0, multiIf(resource_gl0_id_0=0 and is_ipv4=1,IPv4NumToString(ip4_0), resource_gl0_id_0=0 and is_ipv4=0,IPv6NumToString(ip6_0),resource_gl0_id_0!=0 and is_ipv4=1,'0.0.0.0','::') AS ip_0, if(resource_gl0_id_0=0,subnet_id_0,0) AS subnet_id_0 FROM flow_log.l7_flow_log GROUP BY ip_0, subnet_id_0, resource_gl0_type_0, dictGet(deepflow.device_map, 'name', (toUInt64(resource_gl0_type_0),toUInt64(resource_gl0_id_0))) AS resource_gl0_0, if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS ip_0",
	}, {
		input:  "select pod_service_0 from l7_flow_log where pod_service_0 !='xx' group by pod_service_0",
		output: "SELECT dictGet(deepflow.device_map, 'name', (toUInt64(11),toUInt64(l3_device_id_0))) AS pod_service_0 FROM flow_log.l7_flow_log PREWHERE (not((if(is_ipv4=1,IPv4NumToString(ip4_0),IPv6NumToString(ip6_0)),toUInt64(l3_epc_id_0)) IN (SELECT ip,l3_epc_id from deepflow.ip_relation_map WHERE pod_service_name = 'xx'))) AND (l3_device_id_0!=0 AND l3_device_type_0=11) GROUP BY dictGet(deepflow.device_map, 'name', (toUInt64(11),toUInt64(l3_device_id_0))) AS pod_service_0",
	}, {
		input:  "select node_type(region_0) as 'node_type_0',mask(ip_0,33) as 'mask_ip_0' from l7_flow_log group by 'mask_ip_0','node_type_0'",
		output: "WITH if(is_ipv4, IPv4NumToString(bitAnd(ip4_0, 4294967295)), IPv6NumToString(bitAnd(ip6_0, toFixedString(unhex('ffffffff800000000000000000000000'), 16)))) AS mask_ip_0 SELECT 'region' AS node_type_0, mask_ip_0 FROM flow_log.l7_flow_log GROUP BY mask_ip_0, node_type_0",
	}, {
		input:  "select region_id_0 from l7_flow_log group by region_id_0,chost_id_1",
		output: "SELECT region_id_0 FROM flow_log.l7_flow_log PREWHERE (region_id_0!=0) AND (l3_device_id_1!=0 AND l3_device_type_1=1) GROUP BY region_id_0, if(l3_device_type_1=1,l3_device_id_1, 0) AS chost_id_1",
	}, {
		input:  "SELECT ip_0 FROM l4_flow_log WHERE  ((is_internet_1=1) OR (is_internet_0=1)) GROUP BY ip_0 limit 1",
		output: "SELECT if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS ip_0 FROM flow_log.l4_flow_log PREWHERE (((l3_epc_id_1 = -2)) OR ((l3_epc_id_0 = -2))) GROUP BY if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS ip_0 LIMIT 1",
	}, {
		input:  "select Sum(byte) as '流量总量', region_0 as '区域' from l4_flow_log where 1=1 group by '区域' order by '流量总量' desc",
		output: "SELECT dictGet(deepflow.region_map, 'name', (toUInt64(region_id_0))) AS `区域`, SUM(byte_tx+byte_rx) AS `流量总量` FROM flow_log.l4_flow_log PREWHERE 1 = 1 AND region_id_0!=0 GROUP BY `区域` ORDER BY `流量总量` desc",
	}, {
		input:  "select byte as '123' from l4_flow_log where 1=1 group by '123' order by '123' limit 1 ",
		output: "SELECT byte_tx+byte_rx AS `123` FROM flow_log.l4_flow_log PREWHERE 1 = 1 GROUP BY `123` ORDER BY `123` asc LIMIT 1",
	},
	}
)

func TestGetSql(t *testing.T) {
	Load()
	for _, pcase := range parseSQL {
		if pcase.output == "" {
			pcase.output = pcase.input
		}
		e := CHEngine{DB: "flow_log"}
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
