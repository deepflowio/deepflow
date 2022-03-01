package clickhouse

type CHQuery struct {
	IP string
}

func (chq *CHQuery) Exec(sql string) (resp []string, err error) {
	return nil, nil
}
