package common

import (
	"context"
)

type ProfileParams struct {
	Debug      string
	QueryUUID  string
	DB         string
	Sql        string
	DataSource string
	Context    context.Context
}
