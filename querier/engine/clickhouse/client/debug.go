package client

import (
	"fmt"
)

type Debug struct {
	IP        string
	Sql       string
	QueryTime int64
	QueryUUID string
}

func (s *Debug) Get() map[string]interface{} {
	return map[string]interface{}{
		"ip":         s.IP,
		"sql":        s.Sql,
		"query_time": fmt.Sprintf("%.9fs", float64(s.QueryTime)/1e9),
		"query_uuid": s.QueryUUID,
	}
}

func (s *Debug) String() string {
	return fmt.Sprintf(
		"| ip: %s | sql: %s | query_time: %.9fs | query_uuid: %s |", s.IP, s.Sql, float64(s.QueryTime)/1e9, s.QueryUUID,
	)
}
