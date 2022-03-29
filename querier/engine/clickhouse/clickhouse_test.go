package clickhouse

import (
	//"github.com/k0kubun/pp"
	"metaflow/querier/parse"
	//"metaflow/querier/querier"
	"bufio"
	"io/ioutil"
	"os"
	"strings"
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
		input:  "select Sum(byte) as sum_byte, time(time, 120) as time_120 from l4_flow_log group by time_120 having Sum(byte)>=0 limit 10 offset 20",
		output: "WITH toStartOfInterval(time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS _time_120 SELECT SUM(byte_tx+byte_rx) AS sum_byte, toUnixTimestamp(_time_120) AS time_120 FROM l4_flow_log GROUP BY time_120 HAVING SUM(byte_tx+byte_rx) >= 0 LIMIT 20, 10",
	}, {
		input:  "select Sum(log_count) as sum_log_count from l4_flow_log order by sum_log_count desc",
		output: "SELECT SUM(1) AS sum_log_count FROM l4_flow_log ORDER BY sum_log_count desc",
	}, {
		input:  "select Uniq(ip_0) as uniq_ip_0 from l4_flow_log",
		output: "SELECT uniqIf([toString(ip4_0), toString(subnet_id_0), toString(is_ipv4), toString(ip6_0)], NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))) AS uniq_ip_0 FROM l4_flow_log",
	}, {
		input:  "select Max(byte) as max_byte, Sum(log_count) as sum_log_count from l4_flow_log having Sum(byte)>=0",
		output: "SELECT MAX(_sum_byte_tx_plus_byte_rx) AS max_byte, SUM(_sum_1) AS sum_log_count FROM (SELECT SUM(byte_tx+byte_rx) AS _sum_byte_tx_plus_byte_rx, SUM(1) AS _sum_1 FROM l4_flow_log) HAVING SUM(_sum_byte_tx_plus_byte_rx) >= 0",
	}, {
		input:  "select (Max(byte_tx) + Sum(byte_tx))/1 as max_byte_tx from l4_flow_log",
		output: "SELECT divide(plus(MAX(_sum_byte_tx), SUM(_sum_byte_tx)), 1) AS max_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Avg(byte_tx) as avg_byte_tx from l4_flow_log",
		output: "SELECT AVG(_sum_byte_tx) AS avg_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Stddev(byte_tx) as stddev_byte_tx from l4_flow_log",
		output: "SELECT stddevPopStable(_sum_byte_tx) AS stddev_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx from l4_flow_log order by max_byte_tx",
		output: "SELECT MAX(_sum_byte_tx) AS max_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log) ORDER BY max_byte_tx asc",
	}, {
		input:  "select Spread(byte_tx) as spread_byte_tx from l4_flow_log where time>=60 and time<=180",
		output: "WITH if(count(_sum_byte_tx)=3, min(_sum_byte_tx), 0) AS min_fillnullaszero__sum_byte_tx SELECT minus(MAX(_sum_byte_tx), min_fillnullaszero__sum_byte_tx) AS spread_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log PREWHERE `time` >= 60 AND `time` <= 180)",
	}, {
		input:  "select Rspread(byte_tx) as rspread_byte_tx from l4_flow_log where time>=60 and time<=180",
		output: "WITH if(count(_sum_byte_tx)=3, min(_sum_byte_tx), 0) AS min_fillnullaszero__sum_byte_tx SELECT divide(MAX(_sum_byte_tx)+1e-15, min_fillnullaszero__sum_byte_tx+1e-15) AS rspread_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log PREWHERE `time` >= 60 AND `time` <= 180)",
	}, {
		input:  "select Rspread(rtt) as rspread_rtt from l4_flow_log ",
		output: "SELECT divide(MAXArray(arrayFilter(x -> x!=0, _grouparray_rtt))+1e-15, MINArray(arrayFilter(x -> x!=0, _grouparray_rtt))+1e-15) AS rspread_rtt FROM (SELECT groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM l4_flow_log)",
	}, {
		input:  "select Percentile(byte_tx, 50) as percentile_byte_tx from l4_flow_log",
		output: "SELECT quantile(50)(_sum_byte_tx) AS percentile_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT AVGIf(rtt, rtt != 0) AS avg_rtt FROM l4_flow_log",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx, Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT MAX(_sum_byte_tx) AS max_byte_tx, AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt)) AS avg_rtt FROM (SELECT SUM(byte_tx) AS _sum_byte_tx, groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM l4_flow_log)",
	}, {
		input:  "select ((Max(byte_tx))+Avg(rtt ))/(1-Avg(rtt )) as avg_rtt from l4_flow_log",
		output: "SELECT divide(plus(MAX(_sum_byte_tx), AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt))), minus(1, AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt)))) AS avg_rtt FROM (SELECT SUM(byte_tx) AS _sum_byte_tx, groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM l4_flow_log)",
	}, {
		input:  "select Apdex(rtt, 100) as apdex_rtt_100 from l4_flow_log",
		output: "WITH if(COUNTArray(arrayFilter(x -> x!=0, _grouparray_rtt))>0, divide(plus(COUNTArray(arrayFilter(x -> (x <= 100 AND 0 < x), _grouparray_rtt)), divide(COUNTArray(arrayFilter(x -> ((100 < x) AND (x <= (100 * 4))), _grouparray_rtt)), 2)), COUNTArray(arrayFilter(x -> x!=0, _grouparray_rtt))), null) AS divide_0diveider_as_null_plus_apdex_satisfy__grouparray_rtt_100_apdex_toler__grouparray_rtt_100_count__grouparray_rtt SELECT divide_0diveider_as_null_plus_apdex_satisfy__grouparray_rtt_100_apdex_toler__grouparray_rtt_100_count__grouparray_rtt AS apdex_rtt_100 FROM (SELECT groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM l4_flow_log)",
	}, {
		input:  "select Max(byte) as max_byte, time(time,120) as time_120 from l4_flow_log group by time_120",
		output: "WITH toStartOfInterval(_time, toIntervalSecond(120)) + toIntervalSecond(arrayJoin([0]) * 120) AS _time_120 SELECT MAX(_sum_byte_tx_plus_byte_rx) AS max_byte, toUnixTimestamp(_time_120) AS time_120 FROM (WITH toStartOfInterval(time, toIntervalSecond(60)) AS _time SELECT SUM(byte_tx+byte_rx) AS _sum_byte_tx_plus_byte_rx, _time FROM l4_flow_log GROUP BY _time, time_120) GROUP BY time_120",
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
	dbDescriptions := make(map[string]interface{})
	err := readDir(dir, dbDescriptions)
	if err != nil {
		return err
	}
	LoadDbDescriptions(dbDescriptions)
	return nil
}

func readDir(dir string, desMap map[string]interface{}) error {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		// TODO
		return err
	}
	for _, fi := range files {
		fileName := dir + "/" + fi.Name()
		if fi.IsDir() {
			dirMap := make(map[string]interface{})
			desMap[fi.Name()] = dirMap
			err := readDir(fileName, dirMap)
			if err != nil {
				return err
			}
		} else {
			desMap[fi.Name()], err = readFile(fileName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func readFile(fileName string) ([][]interface{}, error) {
	file, err := os.Open(fileName)
	if err != nil {
		//TODO
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	data := make([][]interface{}, 0)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || line[:1] == "#" {
			continue
		}
		lineSlice := make([]interface{}, 0)
		for _, split := range strings.Split(line, ",") {
			lineSlice = append(lineSlice, strings.TrimSpace(split))
		}
		data = append(data, lineSlice)
	}
	return data, nil
}
