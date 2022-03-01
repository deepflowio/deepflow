package service

import (
	"metaflow/querier/datasource"
)

func Execute(args map[string]string) (resp []string, err error) {
	resp, err = datasource.ExecuteQuery(args)
	return resp, err
}
