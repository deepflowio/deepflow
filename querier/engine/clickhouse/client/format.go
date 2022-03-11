package client

import (
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
	default:
		// TODO: 报错
		return value, nil
	}
}
