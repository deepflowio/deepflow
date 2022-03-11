package clickhouse

import (
	"metaflow/querier/parse"
	"testing"
)

var (
	parseSQL = []struct {
		input  string
		output string
	}{{
		input:  "select host from t",
		output: "SELECT host_id AS host FROM t",
	}, {
		input:  "select host from t group by host",
		output: "SELECT host_id AS host FROM t GROUP BY host_id",
	}, {
		input:  "select host, test from t group by host, test",
		output: "SELECT host_id AS host, test FROM t GROUP BY host_id, test",
	}, {
		input:  "select host from t where host='aaa' group by host",
		output: "SELECT host_id AS host FROM t WHERE host_id = 1 GROUP BY host_id",
	}, {
		input:  "select host from t where host='aaa' and c=1 group by host",
		output: "SELECT host_id AS host FROM t WHERE host_id = 1 AND c = 1 GROUP BY host_id",
	}, {
		input:  "select host from t where (host='aaa' and c=1) or b=2 group by host",
		output: "SELECT host_id AS host FROM t WHERE (host_id = 1 AND c = 1) OR b = 2 GROUP BY host_id",
	}, {
		input:  "select host from t where not((host='aaa' and c=1) or b=2) group by host",
		output: "SELECT host_id AS host FROM t WHERE NOT ((host_id = 1 AND c = 1) OR b = 2) GROUP BY host_id",
	}, {
		input:  "select Sum(byte) as sum_byte from t",
		output: "SELECT SUM(byte) AS sum_byte FROM t",
	}, {
		input:  "select Max(byte) as max_byte from t",
		output: "SELECT MAX(_Sum_byte_) AS max_byte FROM (SELECT SUM(byte) AS _Sum_byte_ FROM t)",
	}, {
		input:  "select Sum(byte)/60 as sum_byte from t",
		output: "SELECT SUM(byte)/60 AS sum_byte FROM t",
	}, {
		input:  "select Sum(byte)/60 as sum_byte from t Where (time>=1 and time<=1)",
		output: "SELECT SUM(byte)/60 AS sum_byte FROM t WHERE (`time` >= 1 AND `time` <= 1)",
	}, {
		input:  "select Max(byte) as max_byte from t",
		output: "SELECT MAX(_Sum_byte_) AS max_byte FROM (SELECT SUM(byte) AS _Sum_byte_ FROM t)",
	},
	}
)

func TestGetSql(t *testing.T) {
	for _, pcase := range parseSQL {
		if pcase.output == "" {
			pcase.output = pcase.input
		}
		e := CHEngine{}
		e.Init()
		parser := parse.Parser{Engine: &e}
		parser.ParseSQL(pcase.input)
		out := parser.Engine.ToSQLString()
		if out != pcase.output {
			t.Errorf("Parse(%q) = %q, want: %q", pcase.input, out, pcase.output)
		}
	}
}
