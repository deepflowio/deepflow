package clickhouse

import (
	//"github.com/k0kubun/pp"
	"metaflow/querier/parse"
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
		input:  "select host from l4_flow_log",
		output: "SELECT host_id AS host FROM l4_flow_log",
	}, {
		input:  "select host from l4_flow_log group by host",
		output: "SELECT host_id AS host FROM l4_flow_log GROUP BY host_id",
	}, {
		input:  "select host, test from l4_flow_log group by host, test",
		output: "SELECT host_id AS host, test FROM l4_flow_log GROUP BY host_id, test",
	}, {
		input:  "select host from l4_flow_log where host='aaa' group by host",
		output: "SELECT host_id AS host FROM l4_flow_log WHERE host_id = 1 GROUP BY host_id",
	}, {
		input:  "select host from l4_flow_log where host='aaa' and c=1 group by host",
		output: "SELECT host_id AS host FROM l4_flow_log WHERE host_id = 1 AND c = 1 GROUP BY host_id",
	}, {
		input:  "select host from l4_flow_log where (host='aaa' and c=1) or b=2 group by host",
		output: "SELECT host_id AS host FROM l4_flow_log WHERE (host_id = 1 AND c = 1) OR b = 2 GROUP BY host_id",
	}, {
		input:  "select host from l4_flow_log where not((host='aaa' and c=1) or b=2) group by host",
		output: "SELECT host_id AS host FROM l4_flow_log WHERE NOT ((host_id = 1 AND c = 1) OR b = 2) GROUP BY host_id",
	}, {
		input:  "select Sum(byte) as sum_byte from l4_flow_log",
		output: "SELECT SUM(byte) AS sum_byte FROM l4_flow_log",
	}, {
		input:  "select Max(byte) as max_byte from l4_flow_log",
		output: "SELECT MAX(_Sum_byte) AS max_byte FROM (SELECT SUM(byte) AS _Sum_byte FROM l4_flow_log)",
	}, {
		input:  "select Sum(byte)/60 as sum_byte from l4_flow_log",
		output: "SELECT SUM(byte)/60 AS sum_byte FROM l4_flow_log",
	}, {
		input:  "select Sum(byte)/60 as sum_byte from l4_flow_log Where (time>=1 and time<=1)",
		output: "SELECT SUM(byte)/60 AS sum_byte FROM l4_flow_log WHERE (`time` >= 1 AND `time` <= 1)",
	}, {
		input:  "select Max(byte) as max_byte from l4_flow_log",
		output: "SELECT MAX(_Sum_byte) AS max_byte FROM (SELECT SUM(byte) AS _Sum_byte FROM l4_flow_log)",
	}, {
		input:  "select Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT AVGIf(rtt, rtt != 0) AS avg_rtt FROM l4_flow_log",
	}, {
		input:  "select Max(byte) as max_byte, Avg(rtt) as avg_rtt from l4_flow_log",
		output: "SELECT MAX(_Sum_byte) AS max_byte, AVGArray(arrayFilter(x -> x!=0, _groupArray_rtt)) AS avg_rtt FROM (SELECT SUM(byte) AS _Sum_byte, groupArrayIf(rtt, rtt != 0) AS _groupArray_rtt FROM l4_flow_log)",
	}, {
		input:  "select Spread(byte) as spread_byte from l4_flow_log",
		output: "SELECT MAX(_Sum_byte) - MIN(_Sum_byte) AS spread_byte FROM (SELECT SUM(byte) AS _Sum_byte FROM l4_flow_log)",
	}, {
		input:  "select Rspread(byte) as rspread_byte from l4_flow_log",
		output: "SELECT divide(MAX(_Sum_byte)+1e-15, MIN(_Sum_byte)+1e-15) AS rspread_byte FROM (SELECT SUM(byte) AS _Sum_byte FROM l4_flow_log)",
	},
	}
)

func TestGetSql(t *testing.T) {
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
