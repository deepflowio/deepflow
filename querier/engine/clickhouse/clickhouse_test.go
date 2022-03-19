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
		input:  "select Sum(byte) as sum_byte from l4_flow_log",
		output: "SELECT SUM(byte_tx+byte_rx) AS sum_byte FROM l4_flow_log",
	}, {
		input:  "select Sum(log_count) as sum_log_count from l4_flow_log",
		output: "SELECT SUM(1) AS sum_log_count FROM l4_flow_log",
	}, {
		input:  "select Uniq(ip_0) as uniq_ip_0 from l4_flow_log",
		output: "SELECT uniqIf([toString(ip4_0), toString(subnet_id_0), toString(is_ipv4), toString(ip6_0)], NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))) AS uniq_ip_0 FROM l4_flow_log",
	}, {
		input:  "select Max(byte) as max_byte, Sum(log_count) as sum_log_count from l4_flow_log",
		output: "SELECT MAX(_sum_byte_tx_plus_byte_rx) AS max_byte, SUM(_sum_1) AS sum_log_count FROM (SELECT SUM(byte_tx+byte_rx) AS _sum_byte_tx_plus_byte_rx, SUM(1) AS _sum_1 FROM l4_flow_log)",
	}, {
		input:  "select (Max(byte_tx) + Min(byte_tx))/1 as max_byte_tx from l4_flow_log",
		output: "SELECT divide(Plus(MAX(_sum_byte_tx), MIN(_sum_byte_tx)), 1) AS max_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Avg(byte_tx) as avg_byte_tx from l4_flow_log",
		output: "SELECT AVG(_sum_byte_tx) AS avg_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Stddev(byte_tx) as stddev_byte_tx from l4_flow_log",
		output: "SELECT stddevPopStable(_sum_byte_tx) AS stddev_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx from l4_flow_log",
		output: "SELECT MAX(_sum_byte_tx) AS max_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Spread(byte_tx) as spread_byte_tx from l4_flow_log",
		output: "SELECT MAX(_sum_byte_tx) - MIN(_sum_byte_tx) AS spread_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Rspread(byte_tx) as rspread_byte_tx from l4_flow_log",
		output: "SELECT divide(MAX(_sum_byte_tx)+1e-15, MIN(_sum_byte_tx)+1e-15) AS rspread_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Percentile(byte_tx, 50) as percentile_byte_tx from l4_flow_log",
		output: "SELECT quantile(50)(_sum_byte_tx) AS percentile_byte_tx FROM (SELECT SUM(byte_tx) AS _sum_byte_tx FROM l4_flow_log)",
	}, {
		input:  "select Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT AVGIf(rtt, rtt != 0) AS avg_rtt FROM l4_flow_log",
	}, {
		input:  "select Max(byte_tx) as max_byte_tx, Avg(rtt ) as avg_rtt from l4_flow_log",
		output: "SELECT MAX(_sum_byte_tx) AS max_byte_tx, AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt)) AS avg_rtt FROM (SELECT SUM(byte_tx) AS _sum_byte_tx, groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM l4_flow_log)",
	}, {
		input:  "select ((Max(byte_tx))+Avg(rtt ))/(1-Avg(rtt )) as avg_rtt from l4_flow_log",
		output: "SELECT divide(Plus(MAX(_sum_byte_tx), AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt))), MINUS(1, AVGArray(arrayFilter(x -> x!=0, _grouparray_rtt)))) AS avg_rtt FROM (SELECT SUM(byte_tx) AS _sum_byte_tx, groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM l4_flow_log)",
	}, {
		input:  "select Apdex(rtt, 100) as apdex_rtt_100 from l4_flow_log",
		output: "WITH if(COUNT()>0, divide(Plus(SUM(if(_grouparray_rtt<=100,1,0)), SUM(if(100<_grouparray_rtt AND _grouparray_rtt<=100*4,0.5,0))), COUNT()), null) AS divide_0diveider_as_null_plus_apdex_satisfy__grouparray_rtt_100_apdex_toler__grouparray_rtt_100_count_ SELECT divide_0diveider_as_null_plus_apdex_satisfy__grouparray_rtt_100_apdex_toler__grouparray_rtt_100_count_ AS apdex_rtt_100 FROM (SELECT groupArrayIf(rtt, rtt != 0) AS _grouparray_rtt FROM l4_flow_log)",
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
		line = strings.ReplaceAll(line, " ", "")
		if line == "" || line[:1] == "#" {
			continue
		}
		lineSlice := make([]interface{}, 0)
		for _, split := range strings.Split(line, ",") {
			lineSlice = append(lineSlice, split)
		}
		data = append(data, lineSlice)
	}
	return data, nil
}
