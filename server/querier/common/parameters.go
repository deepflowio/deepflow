package common

import (
	"context"
)

type QuerierParams struct {
	Debug      string
	QueryUUID  string
	DB         string
	Sql        string
	DataSource string
	Context    context.Context
}
