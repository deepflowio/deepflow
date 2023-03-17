package statsd

import (
	"sync"

	"github.com/deepflowio/deepflow/server/libs/stats" // FIXME: why not use stats directly
)

func RegisterCountableForIngester(module string, countable stats.Countable, opts ...stats.Option) error {
	return stats.RegisterCountableWithModulePrefix("querier.", module, countable, opts...)
}

type ClickhouseCounter struct {
	QueryCount   uint64 `statsd:"query_count"`
	ResponseSize uint64 `statsd:"response_size"`
	RowCount     uint64 `statsd:"row_count"`
	ColumnCount  uint64 `statsd:"column_count"`
	QueryTime    uint64
	QueryTimeSum uint64
	QueryTimeAvg uint64 `statsd:"query_time_avg"`
	QueryTimeMax uint64 `statsd:"query_time_max"`
	ApiTime      uint64
	ApiTimeSum   uint64
	ApiTimeAvg   uint64 `statsd:"api_time_avg"`
	ApiTimeMax   uint64 `statsd:"api_time_max"`
	ApiCount     uint64 `statsd:"api_count"`
}

type Counter struct {
	ck       *ClickhouseCounter
	writeCkM *sync.Mutex
	exited   bool
}

func (c *Counter) WriteCk(qc *ClickhouseCounter) {
	go func() {
		c.writeCkM.Lock()
		defer c.writeCkM.Unlock()
		c.ck.ResponseSize += qc.ResponseSize
		c.ck.RowCount += qc.RowCount
		c.ck.ColumnCount += qc.ColumnCount
		c.ck.QueryCount++

		c.ck.QueryTimeSum += qc.QueryTime
		c.ck.QueryTimeAvg = c.ck.QueryTimeSum / c.ck.QueryCount
		if qc.QueryTime > c.ck.QueryTimeMax {
			c.ck.QueryTimeMax = qc.QueryTime
		}
	}()
}

func (c *Counter) WriteApi(qc *ClickhouseCounter) {
	go func() {
		c.writeCkM.Lock()
		defer c.writeCkM.Unlock()
		c.ck.ApiCount++

		c.ck.ApiTimeSum += qc.ApiTime
		c.ck.ApiTimeAvg = c.ck.ApiTimeSum / c.ck.ApiCount
		if qc.ApiTime > c.ck.ApiTimeMax {
			c.ck.ApiTimeMax = qc.ApiTime
		}
	}()
}

func (c *Counter) GetCounter() interface{} {
	counter := &ClickhouseCounter{}
	counter, c.ck = c.ck, counter
	return counter
}

func (c *Counter) Close() {
	c.exited = true
}

func (c *Counter) Closed() bool {
	return c.exited
}

func NewCounter() *Counter {
	return &Counter{
		exited:   false,
		ck:       &ClickhouseCounter{},
		writeCkM: &sync.Mutex{},
	}
}

var QuerierCounter *Counter
