package client

import (
	"math"
	"net"
	"time"
)

func TransType(typeName string, value interface{}) (interface{}, error) {
	switch typeName {
	case "UInt64":
		return int(value.(uint64)), nil
	case "DateTime":
		return value.(time.Time).String(), nil
	case "IPv4", "IPv6":
		return value.(net.IP).String(), nil
	case "Float64":
		// NaN, Inf
		if math.IsNaN(value.(float64)) || value.(float64) == math.Inf(1) || value.(float64) == math.Inf(-1) {
			return nil, nil
		}
		return value.(float64), nil
	default:
		// TODO: 报错
		return value, nil
	}
}
